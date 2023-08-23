"""Helper for entity unique id migration."""

from homeassistant.components.device_tracker.const import DOMAIN as TRACKER_DOMAIN
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.util import slugify

from .binary_sensor import BINARY_SENSORS
from .const import DOMAIN, SENSORS_CPU
from .button import BUTTONS
from .switch import SWITCHES
from .update import COMMAND_UPDATE

_ENTITY_MIGRATION_ID = {
    Platform.BINARY_SENSOR: {s.key: s.name for s in BINARY_SENSORS},
    Platform.BUTTON: {s.key: s.name for s in BUTTONS},
    Platform.SENSOR: {k: s for k, s in SENSORS_CPU.items()},
    Platform.SWITCH: {s.key: s.name for s in SWITCHES},
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
        if ent_entry.platform not in _ENTITY_MIGRATION_ID:
            continue
        for new_id, old_id in _ENTITY_MIGRATION_ID[ent_entry.platform].items():
            if old_unique_id.endswith(f"{old_prefix} {old_id}"):
                if ent_entry.platform == Platform.UPDATE:
                    new_id = "update"
                migrate_entities[ent_entry.entity_id] = slugify(
                    f"{router_unique_id}_{new_id}"
                )
                break

    for entity_id, unique_id in migrate_entities.items():
        entity_reg.async_update_entity(entity_id, new_unique_id=unique_id)
