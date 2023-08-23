"""Helper for entity unique id migration."""

from homeassistant.components.device_tracker.const import DOMAIN as TRACKER_DOMAIN
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.util import slugify

from .const import COMMAND_UPDATE, DOMAIN

_ENTITY_MIGRATION_ID = {
    Platform.BINARY_SENSOR: {"sensor_wan_status": "Wan Status"},
    Platform.BUTTON: {"cmd_reboot": "Reboot"},
    Platform.SENSOR: {
        "sensor_connected_device": "Devices Connected",
        "sensor_rx_rates": "Download Speed",
        "sensor_tx_rates": "Upload Speed",
        "sensor_rx_bytes": "Download",
        "sensor_tx_bytes": "Upload",
        "sensor_load_avg1": "Load Avg (1m)",
        "sensor_load_avg5": "Load Avg (5m)",
        "sensor_load_avg15": "Load Avg (15m)",
        "sensor_memory_perc": "Memory Usage",
        "sensor_memory_total": "Memory Total",
        "sensor_memory_free": "Memory Free",
        "sensor_memory_used": "Memory Used",
        "sensor_last_boot": "Last Boot",
        "sensor_uptime": "Uptime",
        "sensor_wan_ipaddr": "Wan Ip Address",
        "sensor_wan_gateway": "Wan Gateway",
        "sensor_wan_dns": "Wan DNS",
        "cpu_total_usage": "CPU Usage",
        "cpu1_usage": "CPU Core1 Usage",
        "cpu2_usage": "CPU Core2 Usage",
        "cpu3_usage": "CPU Core3 Usage",
        "cpu4_usage": "CPU Core4 Usage",
        "cpu5_usage": "CPU Core5 Usage",
        "cpu6_usage": "CPU Core6 Usage",
        "cpu7_usage": "CPU Core7 Usage",
        "cpu8_usage": "CPU Core8 Usage",
        "2.4GHz": "2.4GHz Temperature",
        "5.0GHz": "5GHz Temperature",
        "CPU": "CPU Temperature",
        "5.0GHz_2": "5GHz Temperature 2",
        "6.0GHz": "6GHz Temperature",
    },
    Platform.SWITCH: {"cmd_led": "Led"},
    Platform.UPDATE: {"update": COMMAND_UPDATE, "update1": "Update"},
}

DEFAULT_NAME = "Asuswrt"


def _migrate_entities_unique_id(
    hass: HomeAssistant, entry: ConfigEntry, router_unique_id: str
) -> None:
    """Migrate router entities to new unique id format."""
    entity_reg = er.async_get(hass)
    router_entries = er.async_entries_for_config_entry(entity_reg, entry.entry_id)

    old_prefix = router_unique_id
    # in old unique id format, if entry unique id was not
    # available was used the 'DEFAULT_NAME' instead
    if old_prefix == entry.entry_id:
        old_prefix = DEFAULT_NAME
    migrate_entities: dict[str, str] = {}
    for ent_entry in router_entries:
        if ent_entry.domain == TRACKER_DOMAIN:
            continue
        old_unique_id = ent_entry.unique_id
        if not old_unique_id.startswith(DOMAIN):
            continue
        if ent_entry.domain not in _ENTITY_MIGRATION_ID:
            continue
        for new_id, old_id in _ENTITY_MIGRATION_ID[ent_entry.domain].items():
            if old_unique_id.endswith(f"{old_prefix} {old_id}"):
                if ent_entry.domain == Platform.UPDATE:
                    new_id = "update"
                migrate_entities[ent_entry.entity_id] = slugify(
                    f"{router_unique_id}_{new_id}"
                )
                break

    for entity_id, unique_id in migrate_entities.items():
        entity_reg.async_update_entity(entity_id, new_unique_id=unique_id)
