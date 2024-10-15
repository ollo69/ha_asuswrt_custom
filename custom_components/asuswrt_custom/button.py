"""Switches for AsusWrt buttons."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.button import (
    ButtonDeviceClass,
    ButtonEntity,
    ButtonEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import slugify

from .const import COMMAND_REBOOT, DATA_ASUSWRT, DOMAIN
from .router import AsusWrtRouter


@dataclass
class AsusWrtButtonDescriptionMixin:
    """Mixin to describe a Button entity."""

    press_action: Callable


@dataclass
class AsusWrtButtonDescription(ButtonEntityDescription, AsusWrtButtonDescriptionMixin):
    """Class to describe a Button entity."""


BUTTONS: tuple[AsusWrtButtonDescription, ...] = (
    AsusWrtButtonDescription(
        key=COMMAND_REBOOT,
        name="Reboot",
        device_class=ButtonDeviceClass.RESTART,
        entity_category=EntityCategory.CONFIG,
        press_action=lambda asuswrt_api: asuswrt_api.async_reboot(),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set buttons for device."""
    router: AsusWrtRouter = hass.data[DOMAIN][entry.entry_id][DATA_ASUSWRT]
    nodes: set = set()

    router_entities = _get_entities(router)
    async_add_entities(router_entities)

    @callback
    def add_nodes() -> None:
        """Add the buttons for mesh nodes."""
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

    async_add_entities(entities)


@callback
def _get_entities(device: AsusWrtRouter) -> list[AsusWrtButton]:
    """Get entities list for device."""
    return [
        AsusWrtButton(device, button_descr)
        for button_descr in BUTTONS
        if button_descr.key in device.api.supported_commands
    ]


class AsusWrtButton(ButtonEntity):
    """Defines a AsusWrt base button."""

    entity_description: AsusWrtButtonDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        router: AsusWrtRouter,
        description: AsusWrtButtonDescription,
    ) -> None:
        """Initialize AsusWrt button."""
        self.entity_description = description
        self._asuswrt_api = router.api

        self._attr_unique_id = slugify(f"{router.unique_id}_{description.key}")
        self._attr_device_info = router.device_info
        self._attr_extra_state_attributes = {"hostname": router.host}
        if mac := router.mac:
            self._attr_extra_state_attributes["mac"] = mac

    async def async_press(self) -> None:
        """Triggers AsusWrt service."""
        await self.entity_description.press_action(self._asuswrt_api)
