"""Asuswrt binary sensors."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import (
    DATA_ASUSWRT,
    DOMAIN,
    KEY_COORDINATOR,
    KEY_SENSORS,
    NODES_ASUSWRT,
    SENSORS_WAN,
)
from .router import AsusWrtRouter


@dataclass
class AsusWrtBinarySensorEntityDescription(BinarySensorEntityDescription):
    """A class that describes AsusWrt binary sensor entities."""

    on_value: int | str | None = None


BINARY_SENSORS: tuple[AsusWrtBinarySensorEntityDescription, ...] = (
    AsusWrtBinarySensorEntityDescription(
        key=SENSORS_WAN[0],
        name="Wan Status",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        on_value="1",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up the sensors."""
    router: AsusWrtRouter = hass.data[DOMAIN][entry.entry_id][DATA_ASUSWRT]
    nodes: AsusWrtRouter = hass.data[DOMAIN][entry.entry_id][NODES_ASUSWRT]
    entities = []

    for index, node in enumerate([router, *nodes]):
        excluded_sensors = []
        if index > 0:
            excluded_sensors += SENSORS_WAN
        for sensor_data in node.sensors_coordinator.values():
            coordinator = sensor_data[KEY_COORDINATOR]
            sensors = sensor_data[KEY_SENSORS]
            entities.extend(
                [
                    AsusWrtBinarySensor(coordinator, node, sensor_descr)
                    for sensor_descr in BINARY_SENSORS
                    if sensor_descr.key in sensors
                    and sensor_descr.key not in excluded_sensors
                ]
            )

    async_add_entities(entities, True)


class AsusWrtBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Representation of a AsusWrt binary sensor."""

    entity_description: AsusWrtBinarySensorEntityDescription

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        router: AsusWrtRouter,
        description: AsusWrtBinarySensorEntityDescription,
    ) -> None:
        """Initialize a AsusWrt sensor."""
        super().__init__(coordinator)
        self.entity_description = description

        self._attr_name = f"{router.name} {description.name}"
        if router.unique_id:
            self._attr_unique_id = f"{DOMAIN} {router.unique_id} {description.name}"
        else:
            self._attr_unique_id = f"{DOMAIN} {self.name}"
        self._attr_device_info = router.device_info
        self._attr_extra_state_attributes = {"hostname": router.host}
        if mac := router.mac:
            self._attr_extra_state_attributes["mac"] = mac

    @property
    def is_on(self) -> bool | None:
        """Return current state."""
        descr = self.entity_description
        state = self.coordinator.data.get(descr.key)
        if state is not None:
            if (on_value := descr.on_value) is not None:
                return state == on_value
        return state
