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
    PERCENTAGE,
    UnitOfDataRate,
    UnitOfInformation,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)
from homeassistant.util import slugify

from .const import (
    DATA_ASUSWRT,
    DOMAIN,
    KEY_COORDINATOR,
    KEY_SENSORS,
    SENSORS_BYTES,
    SENSORS_CONNECTED_DEVICE,
    SENSORS_CPU,
    SENSORS_LOAD_AVG,
    SENSORS_MEMORY,
    SENSORS_RATES,
    SENSORS_TEMPERATURES,
    SENSORS_UPTIME,
    SENSORS_WAN,
)
from .router import AsusWrtRouter

SENSORS_CPU_DEF = {
    SENSORS_CPU[0]: "CPU Usage",
    SENSORS_CPU[1]: "CPU Core1 Usage",
    SENSORS_CPU[2]: "CPU Core2 Usage",
    SENSORS_CPU[3]: "CPU Core3 Usage",
    SENSORS_CPU[4]: "CPU Core4 Usage",
    SENSORS_CPU[5]: "CPU Core5 Usage",
    SENSORS_CPU[6]: "CPU Core6 Usage",
    SENSORS_CPU[7]: "CPU Core7 Usage",
    SENSORS_CPU[8]: "CPU Core8 Usage",
}

SENSORS_TEMPERATURES_DEF = {
    SENSORS_TEMPERATURES[0]: "2.4GHz Temperature",
    SENSORS_TEMPERATURES[1]: "5GHz Temperature",
    SENSORS_TEMPERATURES[2]: "CPU Temperature",
    SENSORS_TEMPERATURES[3]: "5GHz Temperature 2",
    SENSORS_TEMPERATURES[4]: "6GHz Temperature",
}


@dataclass
class AsusWrtSensorEntityDescription(SensorEntityDescription):
    """A class that describes AsusWrt sensor entities."""

    factor: int | None = None
    precision: int | None = 2


UNIT_DEVICES = "Devices"

CPU_SENSORS: tuple[AsusWrtSensorEntityDescription, ...] = tuple(
    AsusWrtSensorEntityDescription(
        key=sens_key,
        name=sens_name,
        icon="mdi:cpu-32-bit",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        factor=1,
        precision=None,
    )
    for sens_key, sens_name in SENSORS_CPU_DEF.items()
)
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
    for sens_key, sens_name in SENSORS_TEMPERATURES_DEF.items()
)
SENSORS: tuple[AsusWrtSensorEntityDescription, ...] = (
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
        device_class=SensorDeviceClass.DATA_RATE,
        native_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        entity_registry_enabled_default=False,
        factor=125000,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_RATES[1],
        name="Upload Speed",
        icon="mdi:upload-network",
        state_class=SensorStateClass.MEASUREMENT,
        device_class=SensorDeviceClass.DATA_RATE,
        native_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        entity_registry_enabled_default=False,
        factor=125000,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_BYTES[0],
        name="Download",
        icon="mdi:download",
        state_class=SensorStateClass.TOTAL_INCREASING,
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.GIGABYTES,
        entity_registry_enabled_default=False,
        factor=1000000000,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_BYTES[1],
        name="Upload",
        icon="mdi:upload",
        state_class=SensorStateClass.TOTAL_INCREASING,
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.GIGABYTES,
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
        precision=1,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_MEMORY[2],
        name="Memory Free",
        icon="mdi:memory",
        state_class=SensorStateClass.MEASUREMENT,
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
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
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        factor=1024,
        precision=None,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_UPTIME[0],
        name="Last Boot",
        device_class=SensorDeviceClass.TIMESTAMP,
    ),
    AsusWrtSensorEntityDescription(
        key=SENSORS_UPTIME[1],
        name="Uptime",
        state_class=SensorStateClass.TOTAL,
        device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
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
) + (CPU_SENSORS + TEMP_SENSORS)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up the sensors."""
    router: AsusWrtRouter = hass.data[DOMAIN][entry.entry_id][DATA_ASUSWRT]
    nodes: set = set()

    router_entities = _get_entities(router)
    async_add_entities(router_entities)

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

        entities.extend(_get_entities(device, SENSORS_WAN))
        nodes.add(mac)

    async_add_entities(entities)


@callback
def _get_entities(
    device: AsusWrtRouter, excluded_sensors: list[str] | None = None
) -> list[AsusWrtSensor]:
    """Get entities list for device."""
    entities = []

    for sensor_data in device.sensors_coordinator.values():
        coordinator = sensor_data[KEY_COORDINATOR]
        sensors = sensor_data[KEY_SENSORS]
        entities.extend(
            [
                AsusWrtSensor(coordinator, device, sensor_descr)
                for sensor_descr in SENSORS
                if sensor_descr.key in sensors
                and sensor_descr.key not in (excluded_sensors or [])
            ]
        )

    return entities


class AsusWrtSensor(CoordinatorEntity, SensorEntity):
    """Representation of a AsusWrt sensor."""

    entity_description: AsusWrtSensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        router: AsusWrtRouter,
        description: AsusWrtSensorEntityDescription,
    ) -> None:
        """Initialize a AsusWrt sensor."""
        super().__init__(coordinator)
        self.entity_description = description

        self._attr_unique_id = slugify(f"{router.unique_id}_{description.key}")
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
