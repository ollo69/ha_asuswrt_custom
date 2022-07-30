"""Support for ASUSWRT devices."""
from __future__ import annotations

from collections.abc import Iterable

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    EVENT_HOMEASSISTANT_STOP,
    MAJOR_VERSION,
    MINOR_VERSION,
    Platform,
)
from homeassistant.core import Event, HomeAssistant

from .const import DATA_ASUSWRT, DOMAIN
from .router import AsusWrtRouter

PLATFORMS = [Platform.DEVICE_TRACKER, Platform.SENSOR]


def is_min_ha_version(min_ha_major_ver: int, min_ha_minor_ver: int) -> bool:
    """Check if HA version at least a specific version."""
    return (
        MAJOR_VERSION > min_ha_major_ver or
        (MAJOR_VERSION == min_ha_major_ver and MINOR_VERSION >= min_ha_minor_ver)
    )


async def async_setup_entity_platforms(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    platforms: Iterable[Platform | str],
) -> None:
    """Set up entity platforms using new method from HA version 2022.8."""
    if is_min_ha_version(2022, 8):
        await hass.config_entries.async_forward_entry_setups(config_entry, platforms)
    else:
        hass.config_entries.async_setup_platforms(config_entry, platforms)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up AsusWrt platform."""

    router = AsusWrtRouter(hass, entry)
    await router.setup()

    router.async_on_close(entry.add_update_listener(update_listener))

    async def async_close_connection(event: Event) -> None:
        """Close AsusWrt connection on HA Stop."""
        await router.close()

    entry.async_on_unload(
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, async_close_connection)
    )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {DATA_ASUSWRT: router}

    await async_setup_entity_platforms(hass, entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        router = hass.data[DOMAIN][entry.entry_id][DATA_ASUSWRT]
        await router.close()
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


async def update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Update when config_entry options update."""
    router = hass.data[DOMAIN][entry.entry_id][DATA_ASUSWRT]

    if router.update_options(entry.options):
        await hass.config_entries.async_reload(entry.entry_id)
