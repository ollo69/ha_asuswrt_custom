"""Support for AsusWrt update platform."""

from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.components.update import UpdateDeviceClass, UpdateEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import slugify

from .const import COMMAND_UPDATE, DATA_ASUSWRT, DOMAIN
from .router import AsusWrtRouter

# we check for update every 15 minutes
SCAN_INTERVAL = timedelta(seconds=900)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set update entity for device."""
    router: AsusWrtRouter = hass.data[DOMAIN][entry.entry_id][DATA_ASUSWRT]
    nodes: set = set()

    router_entities = _get_entities(router)
    async_add_entities(router_entities, True)

    @callback
    def add_nodes() -> None:
        """Add the update entity for mesh nodes."""
        _add_entities(router, async_add_entities, nodes)

    router.async_on_close(
        async_dispatcher_connect(hass, router.signal_node_new, add_nodes)
    )

    add_nodes()


@callback
def _add_entities(
    router: AsusWrtRouter, async_add_entities: AddEntitiesCallback, nodes: set[str]
) -> None:
    """Add new mesh nodes entities for the router."""
    entities = []

    for mac, device in router.mesh_nodes.items():
        if mac in nodes:
            continue

        entities.extend(_get_entities(device))
        nodes.add(mac)

    async_add_entities(entities, True)


@callback
def _get_entities(device: AsusWrtRouter) -> list[AsusWrtUpdate]:
    """Get entities list for device."""
    if COMMAND_UPDATE in device.api.supported_commands:
        return [AsusWrtUpdate(device)]

    return []


class AsusWrtUpdate(UpdateEntity):
    """Defines a AsusWrt update entity."""

    _attr_title = "AsusWRT Firmware"
    _attr_has_entity_name = True
    _attr_name = "Update"

    def __init__(self, router: AsusWrtRouter) -> None:
        """Initialize AsusWrt update entity."""
        self._asuswrt_api = router.api

        self._attr_unique_id = slugify(f"{router.unique_id}_update")
        self._attr_device_info = router.device_info
        self._attr_device_class = UpdateDeviceClass.FIRMWARE

        self._cur_version = router.api.firmware
        self._new_version: str | None = None

    async def async_update(self) -> None:
        """Update status with regular polling."""
        _LOGGER.debug("Checking for new available firmware")
        self._new_version = await self._asuswrt_api.async_get_fw_update()
        self._attr_available = self._asuswrt_api.firmware is not None
        self._update_device_firmware_info()

    def _update_device_firmware_info(self) -> None:
        """Update device registry firmware information."""
        cur_version = self._asuswrt_api.firmware
        if cur_version is None or self._cur_version == cur_version:
            return
        self._cur_version = cur_version
        device_registry = dr.async_get(self.hass)
        if dev := device_registry.async_get_device(self.device_info["identifiers"]):
            device_registry.async_update_device(dev.id, sw_version=cur_version)

    @property
    def installed_version(self) -> str | None:
        """Version currently in use."""
        return self._asuswrt_api.firmware

    @property
    def latest_version(self) -> str | None:
        """Latest version available for install."""
        return self._new_version or self._asuswrt_api.firmware

    @property
    def release_summary(self) -> str | None:
        """Summary of the release notes or changelog."""
        if self._new_version:
            return (
                "New firmware available. Use router administration page to perform the"
                " update."
            )
        return None
