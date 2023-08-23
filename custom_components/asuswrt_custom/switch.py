"""Switches for AsusWrt switches."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.switch import (
    SwitchDeviceClass,
    SwitchEntity,
    SwitchEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import slugify

from .const import COMMAND_LED, DATA_ASUSWRT, DOMAIN
from .router import AsusWrtRouter


@dataclass
class AsusWrtSwitchDescriptionMixin:
    """Mixin to describe a Switch entity."""

    update_method: Callable
    toggle_action: Callable


@dataclass
class AsusWrtSwitchDescription(SwitchEntityDescription, AsusWrtSwitchDescriptionMixin):
    """Class to describe a Switch entity."""


SWITCHES: tuple[AsusWrtSwitchDescription, ...] = (
    AsusWrtSwitchDescription(
        key=COMMAND_LED,
        name="Led",
        device_class=SwitchDeviceClass.SWITCH,
        entity_category=EntityCategory.CONFIG,
        update_method=lambda asuswrt_api: asuswrt_api.async_get_led_status(),
        toggle_action=lambda asuswrt_api, status: asuswrt_api.async_set_led_status(
            status
        ),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set switches for device."""
    router: AsusWrtRouter = hass.data[DOMAIN][entry.entry_id][DATA_ASUSWRT]
    nodes: set = set()

    router_entities = _get_entities(router)
    async_add_entities(router_entities, True)

    @callback
    def add_nodes() -> None:
        """Add the sensors for mesh nodes."""
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
def _get_entities(device: AsusWrtRouter) -> list[AsusWrtSwitch]:
    """Get entities list for device."""
    return [
        AsusWrtSwitch(device, switch_descr)
        for switch_descr in SWITCHES
        if switch_descr.key in device.api.supported_commands
    ]


class AsusWrtSwitch(SwitchEntity):
    """Defines a AsusWrt base switch."""

    entity_description: AsusWrtSwitchDescription

    def __init__(
        self,
        router: AsusWrtRouter,
        description: AsusWrtSwitchDescription,
    ) -> None:
        """Initialize AsusWrt switch."""
        self.entity_description = description
        self._asuswrt_api = router.api

        self._attr_name = f"{router.name} {description.name}"
        self._attr_unique_id = slugify(f"{router.unique_id}_{description.key}")
        self._attr_device_info = router.device_info
        self._attr_extra_state_attributes = {"hostname": router.host}
        if mac := router.mac:
            self._attr_extra_state_attributes["mac"] = mac

        self._attr_is_on: bool | None = None
        self._attr_available = True

    async def async_update(self) -> None:
        """Update switch status with regular polling."""
        is_on = await self.entity_description.update_method(self._asuswrt_api)
        self._attr_available = is_on is not None
        self._attr_is_on = bool(is_on)

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on switch."""
        await self.entity_description.toggle_action(self._asuswrt_api, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off switch."""
        await self.entity_description.toggle_action(self._asuswrt_api, False)
