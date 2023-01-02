"""Asuswrt binary sensors."""
from __future__ import annotations

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

from .const import DATA_ASUSWRT, DOMAIN, KEY_COORDINATOR, KEY_SENSORS, SENSORS_WAN
from .router import AsusWrtRouter

BINARY_SENSORS: tuple[BinarySensorEntityDescription, ...] = (
    BinarySensorEntityDescription(
        key=SENSORS_WAN[0],
        name="Wan Status",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up the sensors."""
    router: AsusWrtRouter = hass.data[DOMAIN][entry.entry_id][DATA_ASUSWRT]
    entities = []

    for sensor_data in router.sensors_coordinator.values():
        coordinator = sensor_data[KEY_COORDINATOR]
        sensors = sensor_data[KEY_SENSORS]
        entities.extend(
            [
                AsusWrtSensor(coordinator, router, sensor_descr)
                for sensor_descr in BINARY_SENSORS
                if sensor_descr.key in sensors
            ]
        )

    async_add_entities(entities, True)


class AsusWrtSensor(CoordinatorEntity, BinarySensorEntity):
    """Representation of a AsusWrt binary sensor."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        router: AsusWrtRouter,
        description: BinarySensorEntityDescription,
    ) -> None:
        """Initialize a AsusWrt sensor."""
        super().__init__(coordinator)
        self.entity_description: BinarySensorEntityDescription = description

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
            return bool(state)
        return state
