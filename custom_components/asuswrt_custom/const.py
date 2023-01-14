"""AsusWrt component constants."""
DOMAIN = "asuswrt_custom"

CONF_DNSMASQ = "dnsmasq"
CONF_INTERFACE = "interface"
CONF_REQUIRE_IP = "require_ip"
CONF_SSH_KEY = "ssh_key"
CONF_TRACK_UNKNOWN = "track_unknown"

DATA_ASUSWRT = DOMAIN
NODES_ASUSWRT = "asuswrt_nodes"

DEFAULT_DNSMASQ = "/var/lib/misc"
DEFAULT_INTERFACE = "eth0"
DEFAULT_TRACK_UNKNOWN = False

KEY_COORDINATOR = "coordinator"
KEY_METHOD = "method"
KEY_SENSORS = "sensors"

MODE_AP = "ap"
MODE_ROUTER = "router"

PROTOCOL_HTTP = "http"
PROTOCOL_HTTPS = "https"
PROTOCOL_SSH = "ssh"
PROTOCOL_TELNET = "telnet"

# Commands
COMMAND_LED = "cmd_led"
COMMAND_REBOOT = "cmd_reboot"
COMMAND_UPDATE = "cmd_update"

# Sensors
SENSORS_BYTES = ["sensor_rx_bytes", "sensor_tx_bytes"]
SENSORS_CONNECTED_DEVICE = ["sensor_connected_device"]
SENSORS_CPU = {
    "cpu_total_usage": "CPU Usage",
    "cpu1_usage": "CPU Core1 Usage",
    "cpu2_usage": "CPU Core2 Usage",
    "cpu3_usage": "CPU Core3 Usage",
    "cpu4_usage": "CPU Core4 Usage",
    "cpu5_usage": "CPU Core5 Usage",
    "cpu6_usage": "CPU Core6 Usage",
    "cpu7_usage": "CPU Core7 Usage",
    "cpu8_usage": "CPU Core8 Usage",
}
SENSORS_LOAD_AVG = ["sensor_load_avg1", "sensor_load_avg5", "sensor_load_avg15"]
SENSORS_MEMORY = [
    "sensor_memory_perc",
    "sensor_memory_total",
    "sensor_memory_free",
    "sensor_memory_used",
]
SENSORS_RATES = ["sensor_rx_rates", "sensor_tx_rates"]
SENSORS_TEMPERATURES = {
    "2.4GHz": "2.4GHz Temperature",
    "5.0GHz": "5GHz Temperature",
    "CPU": "CPU Temperature",
    "5.0GHz_2": "5GHz Temperature 2",
    "6.0GHz": "6GHz Temperature",
}
SENSORS_TEMPERATURES_LEGACY = [[*SENSORS_TEMPERATURES][i] for i in range(3)]
SENSORS_UPTIME = ["sensor_last_boot", "sensor_uptime"]
SENSORS_WAN = [
    "sensor_wan_status",
    "sensor_wan_ipaddr",
    "sensor_wan_gateway",
    "sensor_wan_dns",
]
