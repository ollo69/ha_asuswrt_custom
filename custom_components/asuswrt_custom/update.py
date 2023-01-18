"""Support for AsusWrt update platform."""
from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.components.update import UpdateDeviceClass, UpdateEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

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
    if (
        COMMAND_UPDATE in device.api.supported_commands
        and device.api.firmware is not None
    ):
        return [AsusWrtUpdate(device)]

    return []


class AsusWrtUpdate(UpdateEntity):
    """Defines a AsusWrt update entity."""

    _attr_title = "AsusWRT Firmware"

    def __init__(self, router: AsusWrtRouter) -> None:
        """Initialize AsusWrt update entity."""
        self._asuswrt_api = router.api

        self._attr_name = f"{router.name} Update"
        if router.unique_id:
            self._attr_unique_id = f"{DOMAIN} {router.unique_id} {COMMAND_UPDATE}"
        else:
            self._attr_unique_id = f"{DOMAIN} {self.name}"
        self._attr_device_info = router.device_info
        self._attr_device_class = UpdateDeviceClass.FIRMWARE

        self._new_version: str | None = None

    async def async_update(self) -> None:
        """Update status with regular polling."""
        _LOGGER.debug("Checking for new available firmware")
        self._new_version = await self._asuswrt_api.async_get_fw_update()

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
