"""Support for AsusWrt update platform."""
from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.components.update import UpdateDeviceClass, UpdateEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import COMMAND_UPDATE, DATA_ASUSWRT, DOMAIN, NODES_ASUSWRT
from .router import AsusWrtRouter

# we check for update every 15 minutes
SCAN_INTERVAL = timedelta(seconds=900)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set switches for device."""
    router: AsusWrtRouter = hass.data[DOMAIN][entry.entry_id][DATA_ASUSWRT]
    nodes: list[AsusWrtRouter] = hass.data[DOMAIN][entry.entry_id][NODES_ASUSWRT]

    entities = [
        AsusWrtUpdate(node)
        for node in [router, *nodes]
        if COMMAND_UPDATE in node.api.supported_commands
        and node.api.firmware is not None
    ]

    async_add_entities(entities, True)


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
                f"New firmware [{self._new_version}] is available."
                " Use router's administration page to perform update"
            )
        return None
