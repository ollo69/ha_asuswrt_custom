"""Asuswrt status sensors."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    DATA_GIGABYTES,
    DATA_MEGABYTES,
    DATA_RATE_MEGABITS_PER_SECOND,
    PERCENTAGE,
    UnitOfTemperature,
)
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
    SENSORS_BYTES,
    SENSORS_CONNECTED_DEVICE,
    SENSORS_LOAD_AVG,
    SENSORS_MEMORY,
    SENSORS_RATES,
    SENSORS_TEMPERATURES,
    SENSORS_WAN,
)
from .router import AsusWrtRouter


@dataclass
class AsusWrtSensorEntityDescription(SensorEntityDescription):
    """A class that describes AsusWrt sensor entities."""

    factor: int | None = None
    precision: int | None = 2


UNIT_DEVICES = "Devices"

TEMP_SENSORS: tuple[AsusWrtSensorEntityDescription, ...] = tuple(
    AsusWrtSensorEntityDescription(
        key=sens_key,
        name=sens_name,
        state_class=SensorStateClass.MEASUREMENT,
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        factor=1,
        precision=1,
    )
    for sens_key, sens_name in SENSORS_TEMPERATURES.items()
)
CONNECTION_SENSORS: tuple[AsusWrtSensorEntityDescription, ...] = (
    AsusWrtSensorEntityDescription(
        key=SENSORS_CONNECTED_DEVICE[0],
        name="Devices Connected",
        icon="mdi:router-network",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UNIT_DEVICES,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_RATES[0],
        name="Download Speed",
        icon="mdi:download-network",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=DATA_RATE_MEGABITS_PER_SECOND,
        entity_registry_enabled_default=False,
        factor=125000,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_RATES[1],
        name="Upload Speed",
        icon="mdi:upload-network",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=DATA_RATE_MEGABITS_PER_SECOND,
        entity_registry_enabled_default=False,
        factor=125000,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_BYTES[0],
        name="Download",
        icon="mdi:download",
        state_class=SensorStateClass.TOTAL_INCREASING,
        native_unit_of_measurement=DATA_GIGABYTES,
        entity_registry_enabled_default=False,
        factor=1000000000,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_BYTES[1],
        name="Upload",
        icon="mdi:upload",
        state_class=SensorStateClass.TOTAL_INCREASING,
        native_unit_of_measurement=DATA_GIGABYTES,
        entity_registry_enabled_default=False,
        factor=1000000000,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_LOAD_AVG[0],
        name="Load Avg (1m)",
        icon="mdi:cpu-32-bit",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        factor=1,
        precision=1,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_LOAD_AVG[1],
        name="Load Avg (5m)",
        icon="mdi:cpu-32-bit",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        factor=1,
        precision=1,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_LOAD_AVG[2],
        name="Load Avg (15m)",
        icon="mdi:cpu-32-bit",
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        factor=1,
        precision=1,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_MEMORY[0],
        name="Memory Usage",
        icon="mdi:memory",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        factor=1,
        precision=None,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_MEMORY[1],
        name="Memory Total",
        icon="mdi:memory",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=DATA_MEGABYTES,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        factor=1024,
        precision=None,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_MEMORY[2],
        name="Memory Free",
        icon="mdi:memory",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=DATA_MEGABYTES,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        factor=1024,
        precision=None,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_MEMORY[3],
        name="Memory Used",
        icon="mdi:memory",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=DATA_MEGABYTES,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        factor=1024,
        precision=None,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_WAN[1],
        name="Wan Ip Address",
        icon="mdi:web",
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_WAN[2],
        name="Wan Gateway",
        icon="mdi:web",
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_WAN[3],
        name="Wan DNS",
        icon="mdi:web",
        entity_category=EntityCategory.CONFIG,
        entity_registry_enabled_default=False,
    ),
) + TEMP_SENSORS


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
                for sensor_descr in CONNECTION_SENSORS
                if sensor_descr.key in sensors
            ]
        )

    async_add_entities(entities, True)


class AsusWrtSensor(CoordinatorEntity, SensorEntity):
    """Representation of a AsusWrt sensor."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        router: AsusWrtRouter,
        description: AsusWrtSensorEntityDescription,
    ) -> None:
        """Initialize a AsusWrt sensor."""
        super().__init__(coordinator)
        self.entity_description: AsusWrtSensorEntityDescription = description

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
    def native_value(self) -> float | int | str | None:
        """Return current state."""
        descr = self.entity_description
        state: float | int | str | None = self.coordinator.data.get(descr.key)
        if state is not None and descr.factor and isinstance(state, (float, int)):
            return round(state / descr.factor, descr.precision)
        return state
