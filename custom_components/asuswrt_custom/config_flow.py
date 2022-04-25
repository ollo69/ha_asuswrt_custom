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
    PROTOCOL_HTTP: "HTTP",
    PROTOCOL_HTTPS: "HTTPS",
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

    @callback
    def _show_setup_form(
        self,
        user_input: dict[str, Any] | None = None,
        errors: dict[str, str] | None = None,
    ) -> FlowResult:
        """Show the setup form to the user."""

        if user_input is None:
            user_input = {}

        adv_schema = {}
        conf_password = vol.Required(CONF_PASSWORD)
        if self.show_advanced_options:
            conf_password = vol.Optional(CONF_PASSWORD)
            adv_schema[vol.Optional(CONF_PORT)] = cv.port
            adv_schema[vol.Optional(CONF_SSH_KEY)] = str

        schema = {
            vol.Required(CONF_HOST, default=user_input.get(CONF_HOST, "")): str,
            vol.Required(CONF_USERNAME, default=user_input.get(CONF_USERNAME, "")): str,
            conf_password: str,
            vol.Required(CONF_PROTOCOL, default=PROTOCOL_HTTP): vol.In(
                ALLOWED_PROTOCOL
            ),
            **adv_schema,
            vol.Required(CONF_MODE, default=MODE_ROUTER): vol.In(
                {MODE_ROUTER: "Router", MODE_AP: "Access Point"}
            ),
        }

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(schema),
            errors=errors or {},
        )

    async def _async_check_connection(
        self, user_input: dict[str, Any]
    ) -> tuple[str, str | None]:
        """Attempt to connect the AsusWrt router."""

        host: str = user_input[CONF_HOST]
        api = AsusWrtBridge.get_bridge(self.hass, user_input)
        try:
            await api.async_connect()

        except ConfigEntryNotReady:
            _LOGGER.error("Error connecting to the AsusWrt router at %s", host)
            return RESULT_CONN_ERROR, None

        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception(
                "Unknown error connecting with AsusWrt router at %s", host
            )
            return RESULT_UNKNOWN, None

        if not api.is_connected:
            _LOGGER.error("Error connecting to the AsusWrt router at %s", host)
            return RESULT_CONN_ERROR, None

        unique_id = api.label_mac
        await api.async_disconnect()

        return RESULT_SUCCESS, unique_id

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle a flow initiated by the user."""

        # if exist one entry without unique ID, we abort config flow
        for unique_id in self._async_current_ids():
            if unique_id is None:
                _LOGGER.warning(
                    "A device without a valid UniqueID is already configured."
                    " Configuration of multiple instance is not possible"
                )
                return self.async_abort(reason="single_instance_allowed")

        if user_input is None:
            return self._show_setup_form(user_input)

        errors: dict[str, str] = {}
        host: str = user_input[CONF_HOST]

        protocol: str = user_input[CONF_PROTOCOL]
        if protocol in [PROTOCOL_HTTP, PROTOCOL_HTTPS]:
            user_input.pop(CONF_MODE, None)

        pwd: str | None = user_input.get(CONF_PASSWORD)
        ssh: str | None = user_input.get(CONF_SSH_KEY)

        if not pwd and protocol in [PROTOCOL_HTTP, PROTOCOL_HTTPS]:
            errors["base"] = "pwd_http_request"
        elif not (pwd or ssh):
            errors["base"] = "pwd_or_ssh"
        elif ssh:
            if pwd:
                errors["base"] = "pwd_and_ssh"
            else:
                isfile = await self.hass.async_add_executor_job(_is_file, ssh)
                if not isfile:
                    errors["base"] = "ssh_not_file"

        if not errors:
            ip_address = await self.hass.async_add_executor_job(_get_ip, host)
            if not ip_address:
                errors["base"] = "invalid_host"

        if not errors:
            result, unique_id = await self._async_check_connection(user_input)
            if result == RESULT_SUCCESS:
                if unique_id:
                    await self.async_set_unique_id(unique_id)
                    self._abort_if_unique_id_configured()
                # we allow to configure a single instance without unique id
                elif self._async_current_entries():
                    return self.async_abort(reason="invalid_unique_id")
                else:
                    _LOGGER.warning(
                        "This device do not provide a valid Unique ID."
                        " Configuration of multiple instance will not be possible"
                    )

                return self.async_create_entry(
                    title=host,
                    data=user_input,
                )

            errors["base"] = result

        return self._show_setup_form(user_input, errors)

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
