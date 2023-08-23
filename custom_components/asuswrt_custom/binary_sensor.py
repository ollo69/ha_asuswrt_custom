"""Asuswrt binary sensors."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)
from homeassistant.util import slugify

from .const import DATA_ASUSWRT, DOMAIN, KEY_COORDINATOR, KEY_SENSORS, SENSORS_WAN
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
        entity_registry_enabled_default=False,
        on_value="1",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up the binary sensors."""
    router: AsusWrtRouter = hass.data[DOMAIN][entry.entry_id][DATA_ASUSWRT]
    nodes: set = set()

    router_entities = _get_entities(router)
    async_add_entities(router_entities)

    @callback
    def add_nodes() -> None:
        """Add the binary sensors for mesh nodes."""
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
) -> list[AsusWrtBinarySensor]:
    """Get entities list for device."""
    entities = []

    for sensor_data in device.sensors_coordinator.values():
        coordinator = sensor_data[KEY_COORDINATOR]
        sensors = sensor_data[KEY_SENSORS]
        entities.extend(
            [
                AsusWrtBinarySensor(coordinator, device, sensor_descr)
                for sensor_descr in BINARY_SENSORS
                if sensor_descr.key in sensors
                and sensor_descr.key not in (excluded_sensors or [])
            ]
        )

    return entities


class AsusWrtBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Representation of a AsusWrt binary sensor."""

    entity_description: AsusWrtBinarySensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        router: AsusWrtRouter,
        description: AsusWrtBinarySensorEntityDescription,
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
    def is_on(self) -> bool | None:
        """Return current state."""
        descr = self.entity_description
        state = self.coordinator.data.get(descr.key)
        if state is not None:
            if (on_value := descr.on_value) is not None:
                return state == on_value
        return state
