"""aioasuswrt and pyasuswrt bridge classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import namedtuple
from collections.abc import Awaitable, Callable, Coroutine
from datetime import datetime
import functools
import logging
from typing import Any, TypeVar, cast

from aioasuswrt.asuswrt import AsusWrt as AsusWrtLegacy
from aiohttp import ClientSession
from pyasuswrt import AsusWrtError, AsusWrtHttp
from pyasuswrt.exceptions import AsusWrtNotAvailableInfoError

from homeassistant.const import (
    CONF_HOST,
    CONF_MODE,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_PROTOCOL,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import format_mac
from homeassistant.helpers.update_coordinator import UpdateFailed

from .const import (
    COMMAND_LED,
    COMMAND_REBOOT,
    COMMAND_UPDATE,
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
    SENSORS_CPU,
    SENSORS_LOAD_AVG,
    SENSORS_MEMORY,
    SENSORS_RATES,
    SENSORS_TEMPERATURES,
    SENSORS_TEMPERATURES_LEGACY,
    SENSORS_UPTIME,
    SENSORS_WAN,
)

HTTP_WAN_SENSORS = ["status", "ipaddr", "gateway", "dns"]

SENSORS_TYPE_BYTES = "sensors_bytes"
SENSORS_TYPE_COUNT = "sensors_count"
SENSORS_TYPE_CPU = "sensors_cpu"
SENSORS_TYPE_LOAD_AVG = "sensors_load_avg"
SENSORS_TYPE_MEMORY = "sensors_memory"
SENSORS_TYPE_RATES = "sensors_rates"
SENSORS_TYPE_TEMPERATURES = "sensors_temperatures"
SENSORS_TYPE_UPTIME = "sensors_uptime"
SENSORS_TYPE_WAN = "sensors_wan"

WrtDevice = namedtuple("WrtDevice", ["ip", "name", "connected_to"])

_LOGGER = logging.getLogger(__name__)


_AsusWrtBridgeT = TypeVar("_AsusWrtBridgeT", bound="AsusWrtBridge")
_FuncType = Callable[
    [_AsusWrtBridgeT], Awaitable[list[Any] | tuple[Any] | dict[str, Any]]
]
_ReturnFuncType = Callable[[_AsusWrtBridgeT], Coroutine[Any, Any, dict[str, Any]]]


def handle_errors_and_zip(
    exceptions: type[Exception] | tuple[type[Exception], ...], keys: list[str] | None
) -> Callable[[_FuncType], _ReturnFuncType]:
    """Run library methods and zip results or manage exceptions."""

    def _handle_errors_and_zip(func: _FuncType) -> _ReturnFuncType:
        """Run library methods and zip results or manage exceptions."""

        @functools.wraps(func)
        async def _wrapper(self: _AsusWrtBridgeT) -> dict[str, Any]:
            try:
                data = await func(self)
            except exceptions as exc:
                raise UpdateFailed(exc) from exc

            if keys is None:
                if not isinstance(data, dict):
                    raise UpdateFailed("Received invalid data type")
                return data

            if isinstance(data, dict):
                return dict(zip(keys, list(data.values()), strict=False))
            if not isinstance(data, (list, tuple)):
                raise UpdateFailed("Received invalid data type")
            return dict(zip(keys, data, strict=False))

        return _wrapper

    return _handle_errors_and_zip


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

    def __init__(self, host: str) -> None:
        """Initialize Bridge."""
        self._host = host
        self._firmware: str | None = None
        self._label_mac: str | None = None
        self._model: str | None = None

    @property
    def host(self) -> str:
        """Return hostname."""
        return self._host

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
    def supported_commands(self) -> list[str]:
        """Return bridge supported commands."""
        return []

    async def async_set_host(self, hostname: str) -> None:
        """Set a new host name."""
        raise NotImplementedError()

    async def async_get_led_status(self) -> bool:
        """Get leds status."""
        raise NotImplementedError()

    async def async_set_led_status(self, status: bool) -> bool:
        """Set leds status."""
        raise NotImplementedError()

    async def async_reboot(self) -> bool:
        """Reboot the device."""
        raise NotImplementedError()

    async def async_get_fw_update(self) -> str | None:
        """Get available fw update."""
        raise NotImplementedError()

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
    async def async_get_mesh_nodes(self) -> dict[str, str] | None:
        """Get list of mesh nodes."""

    @abstractmethod
    async def async_get_available_sensors(self) -> dict[str, dict[str, Any]]:
        """Return a dictionary of available sensors for this bridge."""


class AsusWrtLegacyBridge(AsusWrtBridge):
    """The Bridge that use legacy library."""

    def __init__(
        self, conf: dict[str, Any], options: dict[str, Any] | None = None
    ) -> None:
        """Initialize Bridge."""
        super().__init__(conf[CONF_HOST])
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
        await self._api.connection.async_connect()

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
        api_devices = await self._api.async_get_connected_devices()
        return {
            format_mac(mac): WrtDevice(dev.ip, dev.name, None)
            for mac, dev in api_devices.items()
        }

    async def async_get_mesh_nodes(self) -> dict[str, str] | None:
        """Get list of mesh nodes."""
        return None

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
        availability = await self._api.async_find_temperature_commands()
        return [SENSORS_TEMPERATURES_LEGACY[i] for i in range(3) if availability[i]]

    @handle_errors_and_zip((IndexError, OSError, ValueError), SENSORS_BYTES)
    async def _get_bytes(self) -> Any:
        """Fetch byte information from the router."""
        return await self._api.async_get_bytes_total()

    @handle_errors_and_zip((IndexError, OSError, ValueError), SENSORS_RATES)
    async def _get_rates(self) -> Any:
        """Fetch rates information from the router."""
        return await self._api.async_get_current_transfer_rates()

    @handle_errors_and_zip((IndexError, OSError, ValueError), SENSORS_LOAD_AVG)
    async def _get_load_avg(self) -> Any:
        """Fetch load average information from the router."""
        return await self._api.async_get_loadavg()

    @handle_errors_and_zip((OSError, ValueError), None)
    async def _get_temperatures(self) -> Any:
        """Fetch temperatures information from the router."""
        return await self._api.async_get_temperature()


class AsusWrtHttpBridge(AsusWrtBridge):
    """The Bridge that use HTTP library."""

    def __init__(self, conf: dict[str, Any], session: ClientSession) -> None:
        """Initialize Bridge that use HTTP library."""
        super().__init__(conf[CONF_HOST])
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
    def firmware(self) -> str | None:
        """Return firmware information."""
        return self._api.firmware

    @property
    def supported_commands(self) -> list[str]:
        """Return bridge supported commands."""
        return [COMMAND_LED, COMMAND_REBOOT, COMMAND_UPDATE]

    async def async_set_host(self, hostname: str) -> None:
        """Set a new host name."""
        await self._api.async_set_host(hostname)

    async def async_get_led_status(self) -> bool:
        """Get leds status."""
        try:
            return await self._api.async_get_led_status()
        except AsusWrtError:
            return None

    async def async_set_led_status(self, status: bool) -> bool:
        """Set leds status."""
        return await self._api.async_set_led_status(status)

    async def async_reboot(self) -> bool:
        """Reboot the device."""
        return await self._api.async_reboot()

    async def async_get_fw_update(self) -> str | None:
        """Get available fw update."""
        return await self._api.async_get_new_fw()

    @property
    def is_connected(self) -> bool:
        """Get connected status."""
        return cast(bool, self._api.is_connected)

    async def async_connect(self) -> None:
        """Connect to the device."""
        await self._api.async_connect()

        # get main router properties
        if mac := self._api.mac:
            self._label_mac = format_mac(mac)
        self._model = self._api.model

    async def async_disconnect(self) -> None:
        """Disconnect to the device."""
        await self._api.async_disconnect()

    async def async_get_connected_devices(self) -> dict[str, WrtDevice]:
        """Get list of connected devices."""
        api_devices = await self._api.async_get_connected_devices()
        return {
            format_mac(mac): WrtDevice(dev.ip, dev.name, dev.node)
            for mac, dev in api_devices.items()
        }

    async def async_get_mesh_nodes(self) -> dict[str, str] | None:
        """Get list of mesh nodes."""
        try:
            nodes = await self._api.async_get_mesh_nodes()
        except AsusWrtError:
            return None
        return {format_mac(mac): ip for mac, ip in nodes.items()}

    async def async_get_available_sensors(self) -> dict[str, dict[str, Any]]:
        """Return a dictionary of available sensors for this bridge."""
        sensors_cpu = await self._get_available_cpu_sensors()
        sensors_loadavg = await self._get_loadavg_sensors_availability()
        sensors_temperatures = await self._get_available_temperature_sensors()

        sensors_types = {
            SENSORS_TYPE_BYTES: {
                KEY_SENSORS: SENSORS_BYTES,
                KEY_METHOD: self._get_bytes,
            },
            SENSORS_TYPE_CPU: {
                KEY_SENSORS: sensors_cpu,
                KEY_METHOD: self._get_cpu_usage,
            },
            SENSORS_TYPE_LOAD_AVG: {
                KEY_SENSORS: sensors_loadavg,
                KEY_METHOD: self._get_load_avg,
            },
            SENSORS_TYPE_MEMORY: {
                KEY_SENSORS: SENSORS_MEMORY,
                KEY_METHOD: self._get_memory_usage,
            },
            SENSORS_TYPE_RATES: {
                KEY_SENSORS: SENSORS_RATES,
                KEY_METHOD: self._get_rates,
            },
            SENSORS_TYPE_TEMPERATURES: {
                KEY_SENSORS: sensors_temperatures,
                KEY_METHOD: self._get_temperatures,
            },
            SENSORS_TYPE_UPTIME: {
                KEY_SENSORS: SENSORS_UPTIME,
                KEY_METHOD: self._get_uptime,
            },
            SENSORS_TYPE_WAN: {
                KEY_SENSORS: SENSORS_WAN,
                KEY_METHOD: self._get_wan_info,
            },
        }
        return sensors_types

    async def _get_available_cpu_sensors(self) -> list[str]:
        """Check which cpu information is available on the router."""
        try:
            available_cpu = await self._api.async_get_cpu_usage()
            available_sensors = [t for t in SENSORS_CPU if t in available_cpu]
        except AsusWrtError as exc:
            _LOGGER.warning(
                (
                    "Failed checking cpu sensor availability for ASUS router"
                    " %s. Exception: %s"
                ),
                self.host,
                exc,
            )
            return []
        return available_sensors

    async def _get_available_temperature_sensors(self) -> list[str]:
        """Check which temperature information is available on the router."""
        try:
            available_temps = await self._api.async_get_temperatures()
            available_sensors = [
                t for t in SENSORS_TEMPERATURES if t in available_temps
            ]
        except AsusWrtError as exc:
            _LOGGER.warning(
                (
                    "Failed checking temperature sensor availability for ASUS router"
                    " %s. Exception: %s"
                ),
                self.host,
                exc,
            )
            return []
        return available_sensors

    async def _get_loadavg_sensors_availability(self) -> list[str]:
        """Check if load avg is available on the router."""
        try:
            await self._api.async_get_loadavg()
        except AsusWrtNotAvailableInfoError:
            return []
        except AsusWrtError:
            pass
        return SENSORS_LOAD_AVG

    @handle_errors_and_zip(AsusWrtError, SENSORS_BYTES)
    async def _get_bytes(self) -> Any:
        """Fetch byte information from the router."""
        return await self._api.async_get_traffic_bytes()

    @handle_errors_and_zip(AsusWrtError, SENSORS_RATES)
    async def _get_rates(self) -> Any:
        """Fetch rates information from the router."""
        return await self._api.async_get_traffic_rates()

    @handle_errors_and_zip(AsusWrtError, SENSORS_LOAD_AVG)
    async def _get_load_avg(self) -> Any:
        """Fetch cpu load avg information from the router."""
        return await self._api.async_get_loadavg()

    @handle_errors_and_zip(AsusWrtError, None)
    async def _get_temperatures(self) -> Any:
        """Fetch temperatures information from the router."""
        return await self._api.async_get_temperatures()

    @handle_errors_and_zip(AsusWrtError, None)
    async def _get_cpu_usage(self) -> dict[str, Any]:
        """Fetch cpu information from the router."""
        return await self._api.async_get_cpu_usage()

    @handle_errors_and_zip(AsusWrtError, SENSORS_MEMORY)
    async def _get_memory_usage(self) -> dict[str, Any]:
        """Fetch memory information from the router."""
        return await self._api.async_get_memory_usage()

    async def _get_uptime(self) -> dict[str, Any]:
        """Fetch uptime from the router."""
        try:
            uptimes = await self._api.async_get_uptime()
        except AsusWrtError as exc:
            raise UpdateFailed(exc) from exc

        last_boot = datetime.fromisoformat(uptimes["last_boot"])
        uptime = uptimes["uptime"]

        return dict(zip(SENSORS_UPTIME, [last_boot, uptime], strict=False))

    async def _get_wan_info(self) -> dict[str, Any]:
        """Fetch wan information from the router."""
        try:
            wan_info = await self._api.async_get_wan_info()
        except AsusWrtError as exc:
            raise UpdateFailed(exc) from exc

        wan_sensors = [wan_info.get(v) for v in HTTP_WAN_SENSORS]
        return dict(zip(SENSORS_WAN, wan_sensors, strict=False))
