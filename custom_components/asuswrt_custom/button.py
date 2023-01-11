"""Switches for AsusWrt buttons."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from homeassistant.components.button import (
    ButtonDeviceClass,
    ButtonEntity,
    ButtonEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import COMMAND_REBOOT, DATA_ASUSWRT, DOMAIN, NODES_ASUSWRT
from .router import AsusWrtRouter


@dataclass
class AsusWrtButtonDescriptionMixin:
    """Mixin to describe a Button entity."""

    press_action: Callable


@dataclass
class AsusWrtButtonDescription(ButtonEntityDescription, AsusWrtButtonDescriptionMixin):
    """Class to describe a Button entity."""


BUTTONS: Final = [
    AsusWrtButtonDescription(
        key=COMMAND_REBOOT,
        name="Reboot",
        device_class=ButtonDeviceClass.RESTART,
        entity_category=EntityCategory.CONFIG,
        press_action=lambda asuswrt_api: asuswrt_api.async_reboot(),
    ),
]


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set buttons for device."""
    router: AsusWrtRouter = hass.data[DOMAIN][entry.entry_id][DATA_ASUSWRT]
    nodes: list[AsusWrtRouter] = hass.data[DOMAIN][entry.entry_id][NODES_ASUSWRT]
    entities = []

    for node in [router, *nodes]:
        entities.extend(
            [
                AsusWrtButton(node, button_descr)
                for button_descr in BUTTONS
                if button_descr.key in node.api.supported_commands
            ]
        )

    async_add_entities(entities, True)


class AsusWrtButton(ButtonEntity):
    """Defines a AsusWrt base button."""

    entity_description: AsusWrtButtonDescription

    def __init__(
        self,
        router: AsusWrtRouter,
        description: AsusWrtButtonDescription,
    ) -> None:
        """Initialize AsusWrt button."""
        self.entity_description = description
        self._asuswrt_api = router.api

        self._attr_name = f"{router.name} {description.name}"
        if router.unique_id:
            self._attr_unique_id = f"{DOMAIN} {router.unique_id} {description.name}"
        else:
            self._attr_unique_id = f"{DOMAIN} {self.name}"
        self._attr_device_info = router.device_info
        self._attr_extra_state_attributes = {"hostname": router.host}
        if mac := router.mac:
            self._attr_extra_state_attributes["mac"] = mac

    async def async_press(self) -> None:
        """Triggers AsusWrt service."""
        await self.entity_description.press_action(self._asuswrt_api)
