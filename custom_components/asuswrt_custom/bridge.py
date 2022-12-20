"""aioasuswrt and pyasuswrt bridge classes."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections import namedtuple
import logging
from typing import Any

from aioasuswrt.asuswrt import AsusWrt as AsusWrtLegacy
from aiohttp import ClientSession
from pyasuswrt import AsusWrtError, AsusWrtHttp

from homeassistant.const import (
    CONF_HOST,
    CONF_MODE,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_PROTOCOL,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import format_mac
from homeassistant.helpers.update_coordinator import UpdateFailed

from .const import (
    CONF_DNSMASQ,
    CONF_INTERFACE,
    CONF_REQUIRE_IP,
    CONF_SSH_KEY,
    DEFAULT_DNSMASQ,
    DEFAULT_INTERFACE,
    KEY_METHOD,
    KEY_SENSORS,
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS,
    PROTOCOL_TELNET,
    SENSORS_BYTES,
    SENSORS_LOAD_AVG,
    SENSORS_RATES,
    SENSORS_TEMPERATURES,
    SENSORS_TEMPERATURES_LEGACY,
)

SENSORS_TYPE_BYTES = "sensors_bytes"
SENSORS_TYPE_COUNT = "sensors_count"
SENSORS_TYPE_LOAD_AVG = "sensors_load_avg"
SENSORS_TYPE_RATES = "sensors_rates"
SENSORS_TYPE_TEMPERATURES = "sensors_temperatures"

WrtDevice = namedtuple("WrtDevice", ["ip", "name", "connected_to"])

_LOGGER = logging.getLogger(__name__)


def _get_dict(keys: list, values: list) -> dict[str, Any]:
    """Create a dict from a list of keys and values."""
    ret_dict: dict[str, Any] = dict.fromkeys(keys)

    for index, key in enumerate(ret_dict):
        ret_dict[key] = values[index]

    return ret_dict


class AsusWrtBridge(ABC):
    """The Base Bridge abstract class."""

    @staticmethod
    def get_bridge(
        hass: HomeAssistant, conf: dict[str, Any], options: dict[str, Any] | None = None
    ) -> AsusWrtBridge:
        """Get Bridge instance."""
        protocol = conf[CONF_PROTOCOL]
        if protocol in [PROTOCOL_HTTP, PROTOCOL_HTTPS]:
            session = async_get_clientsession(hass)
            return AsusWrtHttpBridge(conf, session)
        return AsusWrtLegacyBridge(conf, options)

    def __init__(self) -> None:
        """Initialize Bridge."""
        self._firmware: str | None = None
        self._label_mac: str | None = None
        self._model: str | None = None

    @property
    def firmware(self) -> str | None:
        """Return firmware information."""
        return self._firmware or None

    @property
    def label_mac(self) -> str | None:
        """Return label mac information."""
        return self._label_mac or None

    @property
    def model(self) -> str | None:
        """Return model information."""
        return self._model or None

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """Get connected status."""

    @abstractmethod
    async def async_connect(self) -> None:
        """Connect to the device."""

    @abstractmethod
    async def async_disconnect(self) -> None:
        """Disconnect to the device."""

    @abstractmethod
    async def async_get_connected_devices(self) -> dict[str, WrtDevice]:
        """Get list of connected devices."""

    @abstractmethod
    async def async_get_available_sensors(self) -> dict[str, dict[str, Any]]:
        """Return a dictionary of available sensors for this bridge."""


class AsusWrtLegacyBridge(AsusWrtBridge):
    """The Bridge that use legacy library."""

    def __init__(
        self, conf: dict[str, Any], options: dict[str, Any] | None = None
    ) -> None:
        """Initialize Bridge."""
        super().__init__()
        self._protocol: str = conf[CONF_PROTOCOL]
        self._api: AsusWrtLegacy = self._get_api(conf, options)

    @staticmethod
    def _get_api(
        conf: dict[str, Any], options: dict[str, Any] | None = None
    ) -> AsusWrtLegacy:
        """Get the AsusWrtLegacy API."""
        opt = options or {}

        return AsusWrtLegacy(
            conf[CONF_HOST],
            conf.get(CONF_PORT),
            conf[CONF_PROTOCOL] == PROTOCOL_TELNET,
            conf[CONF_USERNAME],
            conf.get(CONF_PASSWORD, ""),
            conf.get(CONF_SSH_KEY, ""),
            conf[CONF_MODE],
            opt.get(CONF_REQUIRE_IP, True),
            interface=opt.get(CONF_INTERFACE, DEFAULT_INTERFACE),
            dnsmasq=opt.get(CONF_DNSMASQ, DEFAULT_DNSMASQ),
        )

    @property
    def is_connected(self) -> bool:
        """Get connected status."""
        return bool(self._api.is_connected)

    async def async_connect(self) -> None:
        """Connect to the device."""
        try:
            await self._api.connection.async_connect()
        except OSError as exc:
            raise ConfigEntryNotReady from exc

        # get main router properties
        await self._get_label_mac()
        await self._get_firmware()
        await self._get_model()

    async def async_disconnect(self) -> None:
        """Disconnect to the device."""
        if self._api is not None and self._protocol == PROTOCOL_TELNET:
            self._api.connection.disconnect()

    async def async_get_connected_devices(self) -> dict[str, WrtDevice]:
        """Get list of connected devices."""
        try:
            api_devices = await self._api.async_get_connected_devices()
        except OSError as exc:
            raise UpdateFailed(exc) from exc
        return {
            format_mac(mac): WrtDevice(dev.ip, dev.name, None)
            for mac, dev in api_devices.items()
        }

    async def _get_nvram_info(self, info_type: str) -> dict[str, Any]:
        """Get AsusWrt router info from nvram."""
        info = {}
        try:
            info = await self._api.async_get_nvram(info_type)
        except OSError as exc:
            _LOGGER.warning(
                "Error calling method async_get_nvram(%s): %s", info_type, exc
            )

        return info

    async def _get_label_mac(self) -> None:
        """Get label mac information."""
        if self._label_mac is None:
            self._label_mac = ""
            label_mac = await self._get_nvram_info("LABEL_MAC")
            if label_mac and "label_mac" in label_mac:
                self._label_mac = format_mac(label_mac["label_mac"])

    async def _get_firmware(self) -> None:
        """Get firmware information."""
        if self._firmware is None:
            self._firmware = ""
            firmware = await self._get_nvram_info("FIRMWARE")
            if firmware and "firmver" in firmware:
                firmver: str = firmware["firmver"]
                if "buildno" in firmware:
                    firmver += f" (build {firmware['buildno']})"
                self._firmware = firmver

    async def _get_model(self) -> None:
        """Get model information."""
        if self._model is None:
            self._model = ""
            model = await self._get_nvram_info("MODEL")
            if model and "model" in model:
                self._model = model["model"]

    async def async_get_available_sensors(self) -> dict[str, dict[str, Any]]:
        """Return a dictionary of available sensors for this bridge."""
        sensors_temperatures = await self._get_available_temperature_sensors()
        sensors_types = {
            SENSORS_TYPE_BYTES: {
                KEY_SENSORS: SENSORS_BYTES,
                KEY_METHOD: self._get_bytes,
            },
            SENSORS_TYPE_LOAD_AVG: {
                KEY_SENSORS: SENSORS_LOAD_AVG,
                KEY_METHOD: self._get_load_avg,
            },
            SENSORS_TYPE_RATES: {
                KEY_SENSORS: SENSORS_RATES,
                KEY_METHOD: self._get_rates,
            },
            SENSORS_TYPE_TEMPERATURES: {
                KEY_SENSORS: sensors_temperatures,
                KEY_METHOD: self._get_temperatures,
            },
        }
        return sensors_types

    async def _get_available_temperature_sensors(self) -> list[str]:
        """Check which temperature information is available on the router."""
        try:
            availability = await self._api.async_find_temperature_commands()
            available_sensors = [
                SENSORS_TEMPERATURES_LEGACY[i] for i in range(3) if availability[i]
            ]
        except Exception as exc:  # pylint: disable=broad-except
            _LOGGER.debug(
                "Failed checking temperature sensor availability for ASUS router. Exception: %s",
                exc,
            )
            return []
        return available_sensors

    async def _get_bytes(self) -> dict[str, Any]:
        """Fetch byte information from the router."""
        try:
            datas = await self._api.async_get_bytes_total()
        except (OSError, ValueError) as exc:
            raise UpdateFailed(exc) from exc

        return _get_dict(SENSORS_BYTES, datas)

    async def _get_rates(self) -> dict[str, Any]:
        """Fetch rates information from the router."""
        try:
            rates = await self._api.async_get_current_transfer_rates()
        except (OSError, ValueError) as exc:
            raise UpdateFailed(exc) from exc

        return _get_dict(SENSORS_RATES, rates)

    async def _get_load_avg(self) -> dict[str, Any]:
        """Fetch load average information from the router."""
        try:
            avg = await self._api.async_get_loadavg()
        except (OSError, ValueError) as exc:
            raise UpdateFailed(exc) from exc

        return _get_dict(SENSORS_LOAD_AVG, avg)

    async def _get_temperatures(self) -> dict[str, Any]:
        """Fetch temperatures information from the router."""
        try:
            temperatures: dict[str, Any] = await self._api.async_get_temperature()
        except (OSError, ValueError) as exc:
            raise UpdateFailed(exc) from exc

        return temperatures


class AsusWrtHttpBridge(AsusWrtBridge):
    """The Bridge that use HTTP library."""

    def __init__(self, conf: dict[str, Any], session: ClientSession) -> None:
        """Initialize Bridge that use HTTP library."""
        super().__init__()
        self._api: AsusWrtHttp = self._get_api(conf, session)

    @staticmethod
    def _get_api(conf: dict[str, Any], session: ClientSession) -> AsusWrtHttp:
        """Get the AsusWrtHttp API."""
        return AsusWrtHttp(
            conf[CONF_HOST],
            conf[CONF_USERNAME],
            conf.get(CONF_PASSWORD, ""),
            use_https=conf[CONF_PROTOCOL] == PROTOCOL_HTTPS,
            port=conf.get(CONF_PORT),
            session=session,
        )

    @property
    def is_connected(self) -> bool:
        """Get connected status."""
        return bool(self._api.is_connected)

    async def async_connect(self) -> None:
        """Connect to the device."""
        try:
            await self._api.async_connect()
        except AsusWrtError as exc:
            raise ConfigEntryNotReady from exc

        # get main router properties
        if mac := self._api.mac:
            self._label_mac = format_mac(mac)
        await self._get_firmware()
        await self._get_model()

    async def async_disconnect(self) -> None:
        """Disconnect to the device."""
        await self._api.async_disconnect()

    async def async_get_connected_devices(self) -> dict[str, WrtDevice]:
        """Get list of connected devices."""
        try:
            api_devices = await self._api.async_get_connected_devices()
        except AsusWrtError as exc:
            raise UpdateFailed(exc) from exc
        return {
            format_mac(mac): WrtDevice(dev.ip, dev.name, dev.node)
            for mac, dev in api_devices.items()
        }

    async def _async_get_settings(self, info_type: str) -> dict[str, Any]:
        """Get AsusWrt router info from nvram."""
        info = {}
        try:
            info = await self._api.async_get_settings(info_type)
        except AsusWrtError as exc:
            _LOGGER.warning(
                "Error calling method async_get_settings(%s): %s", info_type, exc
            )

        return info

    async def _get_firmware(self) -> None:
        """Get firmware information."""
        if self._firmware is None:
            firmware = ""
            firmver = await self._async_get_settings("firmver")
            if firmver and "firmver" in firmver:
                firmware = firmver["firmver"]
            buildno = await self._async_get_settings("buildno")
            if buildno and "buildno" in buildno:
                if firmware:
                    firmware += "."
                firmware += buildno["buildno"]
                if extendno := await self._async_get_settings("extendno"):
                    if ext := extendno.get("extendno"):
                        firmware += f"_{ext}"
            self._firmware = firmware or "N/A"

    async def _get_model(self) -> None:
        """Get model information."""
        if self._model is None:
            self._model = ""
            model = await self._async_get_settings("productid")
            if model and "productid" in model:
                self._model = model["productid"]

    async def async_get_available_sensors(self) -> dict[str, dict[str, Any]]:
        """Return a dictionary of available sensors for this bridge."""
        sensors_temperatures = await self._get_available_temperature_sensors()
        sensors_types = {
            SENSORS_TYPE_BYTES: {
                KEY_SENSORS: SENSORS_BYTES,
                KEY_METHOD: self._get_bytes,
            },
            SENSORS_TYPE_RATES: {
                KEY_SENSORS: SENSORS_RATES,
                KEY_METHOD: self._get_rates,
            },
            SENSORS_TYPE_TEMPERATURES: {
                KEY_SENSORS: sensors_temperatures,
                KEY_METHOD: self._get_temperatures,
            },
        }
        return sensors_types

    async def _get_available_temperature_sensors(self) -> list[str]:
        """Check which temperature information is available on the router."""
        try:
            available_temps = await self._api.async_get_temperatures()
            available_sensors = [
                t for t in SENSORS_TEMPERATURES if t in available_temps
            ]
        except AsusWrtError as exc:
            _LOGGER.debug(
                "Failed checking temperature sensor availability for ASUS router. Exception: %s",
                exc,
            )
            return []
        return available_sensors

    async def _get_bytes(self) -> dict[str, Any]:
        """Fetch byte information from the router."""
        try:
            datas = await self._api.async_get_traffic_bytes()
        except AsusWrtError as exc:
            raise UpdateFailed(exc) from exc

        return _get_dict(SENSORS_BYTES, list(datas.values()))

    async def _get_rates(self) -> dict[str, Any]:
        """Fetch rates information from the router."""
        try:
            rates = await self._api.async_get_traffic_rates()
        except AsusWrtError as exc:
            raise UpdateFailed(exc) from exc

        return _get_dict(SENSORS_RATES, list(rates.values()))

    async def _get_temperatures(self) -> dict[str, Any]:
        """Fetch temperatures information from the router."""
        try:
            temperatures: dict[str, Any] = await self._api.async_get_temperatures()
        except AsusWrtError as exc:
            raise UpdateFailed(exc) from exc

        return temperatures
