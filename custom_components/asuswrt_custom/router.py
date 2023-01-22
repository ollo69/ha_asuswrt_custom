"""Represent the AsusWrt router."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
import logging
from typing import Any

from homeassistant.components.device_tracker.const import (
    CONF_CONSIDER_HOME,
    DEFAULT_CONSIDER_HOME,
    DOMAIN as TRACKER_DOMAIN,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import Throttle, dt as dt_util

from .bridge import AsusWrtBridge, WrtDevice
from .const import (
    CONF_DNSMASQ,
    CONF_INTERFACE,
    CONF_REQUIRE_IP,
    CONF_TRACK_UNKNOWN,
    DEFAULT_DNSMASQ,
    DEFAULT_INTERFACE,
    DEFAULT_TRACK_UNKNOWN,
    DOMAIN,
    KEY_COORDINATOR,
    KEY_METHOD,
    KEY_SENSORS,
    SENSORS_CONNECTED_DEVICE,
)

CONF_REQ_RELOAD = [CONF_DNSMASQ, CONF_INTERFACE, CONF_REQUIRE_IP]
DEFAULT_NAME = "Asuswrt"
ASUS_BRAND = "Asus"

MIN_TIME_BETWEEN_NODE_SCANS = timedelta(seconds=300)
SCAN_INTERVAL = timedelta(seconds=30)

SENSORS_TYPE_COUNT = "sensors_count"

_LOGGER = logging.getLogger(__name__)


class AsusWrtSensorDataHandler:
    """Data handler for AsusWrt sensor."""

    def __init__(self, hass: HomeAssistant, api: AsusWrtBridge) -> None:
        """Initialize a AsusWrt sensor data handler."""
        self._hass = hass
        self._api = api
        self._connected_devices = 0

    async def _get_connected_devices(self) -> dict[str, int]:
        """Return number of connected devices."""
        return {SENSORS_CONNECTED_DEVICE[0]: self._connected_devices}

    def update_device_count(self, conn_devices: int) -> bool:
        """Update connected devices attribute."""
        if self._connected_devices == conn_devices:
            return False
        self._connected_devices = conn_devices
        return True

    async def get_coordinator(
        self,
        sensor_type: str,
        update_method: Callable[[], Any] | None = None,
    ) -> DataUpdateCoordinator:
        """Get the coordinator for a specific sensor type."""
        should_poll = True
        if sensor_type == SENSORS_TYPE_COUNT:
            should_poll = False
            method = self._get_connected_devices
        elif update_method is not None:
            method = update_method
        else:
            raise RuntimeError(f"Invalid sensor type: {sensor_type}")

        coordinator = DataUpdateCoordinator(
            self._hass,
            _LOGGER,
            name=f"{sensor_type}@{self._api.host}",
            update_method=method,
            # Polling interval. Will only be polled if there are subscribers.
            update_interval=SCAN_INTERVAL if should_poll else None,
        )
        await coordinator.async_refresh()

        return coordinator


class AsusWrtDevInfo:
    """Representation of a AsusWrt device info."""

    def __init__(self, mac: str, name: str | None = None) -> None:
        """Initialize a AsusWrt device info."""
        self._mac = mac
        self._name = name
        self._ip_address: str | None = None
        self._last_activity: datetime | None = None
        self._connected = False
        self._connected_to: str | None = None

    def update(self, dev_info: WrtDevice | None = None, consider_home: int = 0) -> None:
        """Update AsusWrt device info."""
        utc_point_in_time = dt_util.utcnow()
        if dev_info:
            if not self._name:
                self._name = dev_info.name or self._mac.replace(":", "_")
            self._ip_address = dev_info.ip
            self._last_activity = utc_point_in_time
            self._connected = True
            self._connected_to = dev_info.connected_to

        elif self._connected:
            self._connected = (
                self._last_activity is not None
                and (utc_point_in_time - self._last_activity).total_seconds()
                < consider_home
            )
            self._ip_address = None
            self._connected_to = None

    @property
    def is_connected(self) -> bool:
        """Return connected status."""
        return self._connected

    @property
    def mac(self) -> str:
        """Return device mac address."""
        return self._mac

    @property
    def name(self) -> str | None:
        """Return device name."""
        return self._name

    @property
    def ip_address(self) -> str | None:
        """Return device ip address."""
        return self._ip_address

    @property
    def last_activity(self) -> datetime | None:
        """Return device last activity."""
        return self._last_activity

    @property
    def connected_to(self) -> str | None:
        """Return node to which device is connected."""
        return self._connected_to


class AsusWrtRouter:
    """Representation of a AsusWrt router."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        *,
        bridge: AsusWrtBridge | None = None,
    ) -> None:
        """Initialize a AsusWrt router."""
        self.hass = hass
        self._entry = entry
        self._unique_id = entry.unique_id

        self._devices: dict[str, AsusWrtDevInfo] = {}
        self._mesh_nodes: dict[str, AsusWrtRouter] = {}
        self._connected_devices: int = 0
        self._connect_error: bool = False
        self._is_mesh_node: bool = False

        self._sensors_data_handler: AsusWrtSensorDataHandler | None = None
        self._sensors_coordinator: dict[str, Any] = {}

        self._on_close: list[Callable] = []

        self._options: dict[str, Any] = {
            CONF_DNSMASQ: DEFAULT_DNSMASQ,
            CONF_INTERFACE: DEFAULT_INTERFACE,
            CONF_REQUIRE_IP: True,
        }
        self._options.update(entry.options)

        if bridge:
            self._unique_id = self.get_node_unique_id(bridge.label_mac)
            self._is_mesh_node = True
            self._api = bridge
        else:
            self._api = AsusWrtBridge.get_bridge(
                self.hass, dict(self._entry.data), self._options
            )

    async def setup(self) -> None:
        """Set up a AsusWrt router."""
        if self._is_mesh_node:
            return

        await self._api.async_connect()
        if not self._api.is_connected:
            raise ConfigEntryNotReady

        # Load tracked entities from registry
        entity_reg = er.async_get(self.hass)
        track_entries = er.async_entries_for_config_entry(
            entity_reg, self._entry.entry_id
        )
        for entry in track_entries:

            if entry.domain != TRACKER_DOMAIN:
                continue
            device_mac = dr.format_mac(entry.unique_id)

            # migrate entity unique ID if wrong formatted
            if device_mac != entry.unique_id:
                existing_entity_id = entity_reg.async_get_entity_id(
                    TRACKER_DOMAIN, DOMAIN, device_mac
                )
                if existing_entity_id:
                    # entity with uniqueid properly formatted already
                    # exists in the registry, we delete this duplicate
                    entity_reg.async_remove(entry.entity_id)
                    continue

                entity_reg.async_update_entity(
                    entry.entity_id, new_unique_id=device_mac
                )

            self._devices[device_mac] = AsusWrtDevInfo(device_mac, entry.original_name)

        # Update devices
        await self.update_devices()

        # Init Sensors
        await self.init_sensors_coordinator()

        # Update mesh nodes
        await self.update_mesh_nodes()

        self.async_on_close(
            async_track_time_interval(self.hass, self.update_all, SCAN_INTERVAL)
        )

    async def update_all(self, now: datetime | None = None) -> None:
        """Update all AsusWrt platforms."""
        await self.update_devices()
        await self.update_mesh_nodes()

    async def update_devices(self) -> None:
        """Update AsusWrt devices tracker."""
        new_device = False
        _LOGGER.debug("Checking devices for ASUS router %s", self.host)
        try:
            wrt_devices = await self._api.async_get_connected_devices()
        except UpdateFailed as exc:
            if not self._connect_error:
                self._connect_error = True
                _LOGGER.error(
                    "Error connecting to ASUS router %s for device update: %s",
                    self.host,
                    exc,
                )
            return

        if self._connect_error:
            self._connect_error = False
            _LOGGER.info("Reconnected to ASUS router %s", self.host)

        self._connected_devices = len(wrt_devices)
        consider_home: int = self._options.get(
            CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME.total_seconds()
        )
        track_unknown: bool = self._options.get(
            CONF_TRACK_UNKNOWN, DEFAULT_TRACK_UNKNOWN
        )

        for device_mac, device in self._devices.items():
            dev_info = wrt_devices.pop(device_mac, None)
            device.update(dev_info, consider_home)

        for device_mac, dev_info in wrt_devices.items():
            if not track_unknown and not dev_info.name:
                continue
            new_device = True
            device = AsusWrtDevInfo(device_mac)
            device.update(dev_info)
            self._devices[device_mac] = device

        async_dispatcher_send(self.hass, self.signal_device_update)
        if new_device:
            async_dispatcher_send(self.hass, self.signal_device_new)
        await self._update_unpolled_sensors()

    async def update_mesh_nodes(self) -> None:
        """Update AsusWrt router mesh nodes."""
        if self._is_mesh_node or not self.unique_id or not self._api.is_connected:
            return

        if (node_list := await self._api.async_get_mesh_nodes()) is None:
            return

        new_nodes = False
        for node_mac, node_ip in node_list.items():
            if node_mac == self.mac or node_ip is None:
                continue
            if node_mac in self._mesh_nodes:
                node = self._mesh_nodes[node_mac]
                # node ip for existing node is changed
                if node.host != node_ip:
                    await node.api.async_set_host(node_ip)
                continue

            entry_data = {**self._entry.data, CONF_HOST: node_ip}
            bridge = AsusWrtBridge.get_bridge(self.hass, entry_data, self._options)
            try:
                await bridge.async_connect()
            except ConfigEntryNotReady:
                continue
            if not bridge.label_mac:
                # we need mac as unique_id
                await bridge.async_disconnect()
                continue

            # Init Router and Sensors
            router = AsusWrtRouter(self.hass, self._entry, bridge=bridge)
            await router.init_sensors_coordinator()
            self._mesh_nodes[node_mac] = router
            new_nodes = True

        await self._async_remove_orphan_nodes(node_list)
        if new_nodes:
            async_dispatcher_send(self.hass, self.signal_node_new)

    @Throttle(MIN_TIME_BETWEEN_NODE_SCANS)
    async def _async_remove_orphan_nodes(
        self, node_list: dict[str, str], **kwargs
    ) -> None:
        """Remove mesh orphan nodes from HA."""
        _LOGGER.debug("Calling _async_remove_orphan_nodes")
        if not self.unique_id or self._is_mesh_node:
            return

        device_registry = dr.async_get(self.hass)
        root_dev = device_registry.async_get_device({(DOMAIN, self.unique_id)})
        if not root_dev:
            # if we are not able to retrieve root device, we abort
            return

        # we only take devs with single config entry, others are related to tracker
        entry_id = {self._entry.entry_id}
        entry_devs = [
            device
            for device in device_registry.devices.values()
            if device.config_entries == entry_id and device.id != root_dev.id
        ]

        valid_devs = []
        for node_mac in node_list:
            if node_mac == self.mac:
                continue
            identifier = self.get_node_unique_id(node_mac)
            if dev := device_registry.async_get_device({(DOMAIN, identifier)}):
                valid_devs.append(dev.id)

        for dev in entry_devs:
            if dev.id in valid_devs:
                continue
            _LOGGER.info("Removed orphan device node %s", dev.name)
            device_registry.async_remove_device(dev.id)

        for node_mac in list(self._mesh_nodes):
            if node_mac in node_list:
                continue
            node = self._mesh_nodes.pop(node_mac)
            await node.close()

    async def init_sensors_coordinator(self) -> None:
        """Init AsusWrt sensors coordinators."""
        if self._sensors_data_handler:
            return

        self._sensors_data_handler = AsusWrtSensorDataHandler(self.hass, self._api)
        self._sensors_data_handler.update_device_count(self._connected_devices)

        sensors_types = await self._api.async_get_available_sensors()
        if not self._is_mesh_node:
            sensors_types[SENSORS_TYPE_COUNT] = {KEY_SENSORS: SENSORS_CONNECTED_DEVICE}

        for sensor_type, sensor_def in sensors_types.items():
            if not (sensor_names := sensor_def.get(KEY_SENSORS)):
                continue
            coordinator = await self._sensors_data_handler.get_coordinator(
                sensor_type, update_method=sensor_def.get(KEY_METHOD)
            )
            self._sensors_coordinator[sensor_type] = {
                KEY_COORDINATOR: coordinator,
                KEY_SENSORS: sensor_names,
            }

    async def _update_unpolled_sensors(self) -> None:
        """Request refresh for AsusWrt unpolled sensors."""
        if not self._sensors_data_handler:
            return

        if SENSORS_TYPE_COUNT in self._sensors_coordinator:
            coordinator = self._sensors_coordinator[SENSORS_TYPE_COUNT][KEY_COORDINATOR]
            if self._sensors_data_handler.update_device_count(self._connected_devices):
                await coordinator.async_refresh()

    async def close(self) -> None:
        """Close the connection."""
        for dev in self._mesh_nodes.values():
            await dev.close()
        if self._api is not None:
            await self._api.async_disconnect()

        for func in self._on_close:
            func()
        self._on_close.clear()

    @callback
    def async_on_close(self, func: CALLBACK_TYPE) -> None:
        """Add a function to call when router is closed."""
        self._on_close.append(func)

    def update_options(self, new_options: dict[str, Any]) -> bool:
        """Update router options."""
        req_reload = False
        for name, new_opt in new_options.items():
            if name in CONF_REQ_RELOAD:
                old_opt = self._options.get(name)
                if old_opt is None or old_opt != new_opt:
                    req_reload = True
                    break

        self._options.update(new_options)
        return req_reload

    def get_node_unique_id(self, node_mac: str) -> str | None:
        """Return unique id for mesh node."""
        if not self.unique_id:
            return None
        if self.unique_id.endswith(node_mac):
            return self.unique_id
        return f"{self.unique_id}-{node_mac}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return the device information."""
        info = DeviceInfo(
            identifiers={(DOMAIN, self.unique_id or "AsusWRT")},
            name=self.host,
            model=self._api.model or "Asus Router",
            manufacturer=ASUS_BRAND,
            configuration_url=f"http://{self.host}",
        )
        if self._api.firmware:
            info["sw_version"] = self._api.firmware
        if self.mac:
            info["connections"] = {(dr.CONNECTION_NETWORK_MAC, self.mac)}

        return info

    @property
    def signal_device_new(self) -> str:
        """Event specific per AsusWrt entry to signal new device."""
        return f"{DOMAIN}-device-new"

    @property
    def signal_device_update(self) -> str:
        """Event specific per AsusWrt entry to signal updates in devices."""
        return f"{DOMAIN}-device-update"

    @property
    def signal_node_new(self) -> str:
        """Event specific per AsusWrt entry to signal new mesh node."""
        return f"{DOMAIN}-node-new"

    @property
    def host(self) -> str:
        """Return router hostname."""
        return self._api.host

    @property
    def mac(self) -> str | None:
        """Return router mac address."""
        return self._api.label_mac

    @property
    def unique_id(self) -> str | None:
        """Return router unique id."""
        return self._unique_id

    @property
    def name(self) -> str:
        """Return router name."""
        return self.host if self.unique_id else DEFAULT_NAME

    @property
    def devices(self) -> dict[str, AsusWrtDevInfo]:
        """Return devices."""
        return self._devices

    @property
    def mesh_nodes(self) -> dict[str, AsusWrtRouter]:
        """Return mesh nodes."""
        return self._mesh_nodes

    @property
    def sensors_coordinator(self) -> dict[str, Any]:
        """Return sensors coordinators."""
        return self._sensors_coordinator

    @property
    def api(self) -> AsusWrtBridge:
        """Return router bridge api."""
        return self._api
