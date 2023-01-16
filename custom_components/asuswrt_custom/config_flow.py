"""Config flow to configure the AsusWrt integration."""

from __future__ import annotations

import logging
import os
import socket
from typing import Any

import voluptuous as vol

from homeassistant.components.device_tracker.const import (
    CONF_CONSIDER_HOME,
    DEFAULT_CONSIDER_HOME,
)
from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.const import (
    CONF_BASE,
    CONF_HOST,
    CONF_MODE,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_PROTOCOL,
    CONF_USERNAME,
)
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv

from .bridge import AsusWrtBridge
from .const import (
    CONF_DNSMASQ,
    CONF_INTERFACE,
    CONF_REQUIRE_IP,
    CONF_SSH_KEY,
    CONF_TRACK_UNKNOWN,
    DEFAULT_DNSMASQ,
    DEFAULT_INTERFACE,
    DEFAULT_TRACK_UNKNOWN,
    DOMAIN,
    MODE_AP,
    MODE_ROUTER,
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS,
    PROTOCOL_SSH,
    PROTOCOL_TELNET,
)

ALLOWED_PROTOCOL = {
    PROTOCOL_HTTPS: "HTTPS",
    PROTOCOL_HTTP: "HTTP",
    PROTOCOL_SSH: "SSH",
    PROTOCOL_TELNET: "Telnet",
}

RESULT_CONN_ERROR = "cannot_connect"
RESULT_SUCCESS = "success"
RESULT_UNKNOWN = "unknown"

_LOGGER = logging.getLogger(__name__)


def _is_file(value: str) -> bool:
    """Validate that the value is an existing file."""
    file_in = os.path.expanduser(value)
    return os.path.isfile(file_in) and os.access(file_in, os.R_OK)


def _get_ip(host: str) -> str | None:
    """Get the ip address from the host name."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


class AsusWrtFlowHandler(ConfigFlow, domain=DOMAIN):
    """Handle a config flow."""

    VERSION = 1

    def __init__(self):
        """Initialize the AsusWrt config flow."""
        self._config_data: dict[str, Any] = {}
        self._unique_id: str | None = None

    @callback
    def _show_setup_form(self, error: str | None = None) -> FlowResult:
        """Show the setup form to the user."""

        user_input = self._config_data

        if self.show_advanced_options:
            add_schema = {
                vol.Optional(CONF_PASSWORD): str,
                vol.Optional(CONF_SSH_KEY): str,
                vol.Required(
                    CONF_PROTOCOL,
                    default=user_input.get(CONF_PROTOCOL, PROTOCOL_HTTPS),
                ): vol.In(ALLOWED_PROTOCOL),
                vol.Optional(CONF_PORT): cv.port,
            }
        else:
            add_schema = {vol.Required(CONF_PASSWORD): str}

        schema = {
            vol.Required(CONF_HOST, default=user_input.get(CONF_HOST, "")): str,
            vol.Required(CONF_USERNAME, default=user_input.get(CONF_USERNAME, "")): str,
            **add_schema,
        }

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(schema),
            errors={CONF_BASE: error} if error else None,
        )

    @callback
    def _show_legacy_form(self) -> FlowResult:
        """Show the setup form to the user for legacy options."""
        data_schema = vol.Schema(
            {
                vol.Required(CONF_MODE, default=MODE_ROUTER): vol.In(
                    {MODE_ROUTER: "Router", MODE_AP: "Access Point"}
                ),
            }
        )
        return self.async_show_form(step_id="legacy", data_schema=data_schema)

    async def _async_check_connection(
        self, user_input: dict[str, Any]
    ) -> tuple[str, str | None, str | None]:
        """Attempt to connect the AsusWrt router."""

        host: str = user_input[CONF_HOST]
        error: str | None = None
        valid_protocol: str | None = None
        api: AsusWrtBridge | None = None
        if CONF_PROTOCOL in user_input:
            protocols: list[str] = [user_input[CONF_PROTOCOL]]
        else:
            protocols = list(ALLOWED_PROTOCOL)

        for protocol in protocols:
            conf = {**user_input, CONF_PROTOCOL: protocol, CONF_MODE: MODE_ROUTER}
            api = AsusWrtBridge.get_bridge(self.hass, conf)
            try:
                await api.async_connect()

            except ConfigEntryNotReady:
                _LOGGER.error(
                    "Error connecting to the AsusWrt router at %s using protocol %s",
                    host,
                    protocol,
                )
                error = RESULT_CONN_ERROR

            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception(
                    "Unknown error connecting with AsusWrt router at %s using protocol %s",
                    host,
                    protocol,
                )
                if error is None:
                    error = RESULT_UNKNOWN

            else:
                valid_protocol = protocol
                error = None

            if error is None:
                if not api.is_connected:
                    _LOGGER.error(
                        "Error connecting to the AsusWrt router at %s using protocol %s",
                        host,
                        protocol,
                    )
                    error = RESULT_CONN_ERROR
                else:
                    break

        if error is not None:
            return error, None, None

        _LOGGER.info(
            "Succesfully connected to the AsusWrt router at %s using protocol %s",
            host,
            protocol,
        )
        unique_id = api.label_mac
        await api.async_disconnect()

        return RESULT_SUCCESS, unique_id, valid_protocol

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle a flow initiated by the user."""

        # if there's one entry without unique ID, we abort config flow
        for unique_id in self._async_current_ids():
            if unique_id is None:
                return self.async_abort(reason="no_unique_id")

        if user_input is None:
            return self._show_setup_form()

        protocol: str = user_input.get(CONF_PROTOCOL, "")
        if protocol != PROTOCOL_SSH and CONF_SSH_KEY in user_input:
            user_input.pop(CONF_SSH_KEY)

        self._config_data = user_input
        pwd: str | None = user_input.get(CONF_PASSWORD)
        ssh: str | None = user_input.get(CONF_SSH_KEY)

        if not pwd and protocol != PROTOCOL_SSH:
            return self._show_setup_form(error="pwd_required")
        if not (pwd or ssh):
            return self._show_setup_form(error="pwd_or_ssh")
        if pwd and ssh:
            return self._show_setup_form(error="pwd_and_ssh")
        if ssh:
            if not await self.hass.async_add_executor_job(_is_file, ssh):
                return self._show_setup_form(error="ssh_not_file")

        host: str = user_input[CONF_HOST]
        if not await self.hass.async_add_executor_job(_get_ip, host):
            return self._show_setup_form(error="invalid_host")

        result, unique_id, protocol = await self._async_check_connection(user_input)
        if result == RESULT_SUCCESS:
            self._unique_id = unique_id
            self._config_data = {**user_input, CONF_PROTOCOL: protocol}
            if protocol in [PROTOCOL_SSH, PROTOCOL_TELNET]:
                return await self.async_step_legacy()
            return await self._async_save_entry()

        return self._show_setup_form(error=result)

    async def async_step_legacy(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle a flow for legacy settings."""
        if user_input is None:
            return self._show_legacy_form()

        self._config_data.update(user_input)
        return await self._async_save_entry()

    async def _async_save_entry(self) -> FlowResult:
        """Save entry data if unique id is valid."""
        if self._unique_id:
            await self.async_set_unique_id(self._unique_id)
        # we allow to configure a single instance without unique id
        elif self._async_current_entries():
            return self.async_abort(reason="invalid_unique_id")
        else:
            _LOGGER.warning(
                "This device does not provide a valid Unique ID."
                " Configuration of multiple instance will not be possible"
            )

        return self.async_create_entry(
            title=self._config_data[CONF_HOST],
            data=self._config_data,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow for this handler."""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(OptionsFlow):
    """Handle a option flow for AsusWrt."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle options flow."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        used_protocol = self.config_entry.data[CONF_PROTOCOL]

        data_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_CONSIDER_HOME,
                    default=self.config_entry.options.get(
                        CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME.total_seconds()
                    ),
                ): vol.All(vol.Coerce(int), vol.Clamp(min=0, max=900)),
                vol.Optional(
                    CONF_TRACK_UNKNOWN,
                    default=self.config_entry.options.get(
                        CONF_TRACK_UNKNOWN, DEFAULT_TRACK_UNKNOWN
                    ),
                ): bool,
            }
        )

        if used_protocol in [PROTOCOL_SSH, PROTOCOL_TELNET]:
            data_schema = data_schema.extend(
                {
                    vol.Required(
                        CONF_INTERFACE,
                        default=self.config_entry.options.get(
                            CONF_INTERFACE, DEFAULT_INTERFACE
                        ),
                    ): str,
                    vol.Required(
                        CONF_DNSMASQ,
                        default=self.config_entry.options.get(
                            CONF_DNSMASQ, DEFAULT_DNSMASQ
                        ),
                    ): str,
                }
            )
            if self.config_entry.data[CONF_MODE] == MODE_AP:
                data_schema = data_schema.extend(
                    {
                        vol.Optional(
                            CONF_REQUIRE_IP,
                            default=self.config_entry.options.get(
                                CONF_REQUIRE_IP, True
                            ),
                        ): bool,
                    }
                )

        return self.async_show_form(step_id="init", data_schema=data_schema)
