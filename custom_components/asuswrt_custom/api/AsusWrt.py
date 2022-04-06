
from __future__ import annotations

import asyncio
from aiohttp import ClientSession
import base64
import json
import logging
import time

ASUSWRT_USR_AGENT = "asusrouter-Android-DUTUtil-1.0.0.245"
ASUSWRT_ERROR_KEY = "error_status"
ASUSWRT_TOKEN_KEY = "asus_token"
ASUSWRT_LOGIN_PATH = "login.cgi"
ASUSWRT_GET_PATH = "appGet.cgi"

DEFAULT_TIMEOUT = 5

NVRAM_INFO = [
    "acs_dfs",
    "model",
    "productid",
    "label_mac",
    "firmver",
    "innerver",
    "buildinfo",
    "buildno",
    "buildno_org",
    "apps_sq",
    "lan_hwaddr",
    "lan_ipaddr",
    "lan_proto",
    "x_Setting",
    "lan_netmask",
    "lan_gateway",
    "http_enable",
    "https_lanport",
    "cfg_device_list",
    "wl0_country_code",
    "wl1_country_code"
    "time_zone",
    "time_zone_dst",
    "time_zone_x",
    "time_zone_dstoff",
    "time_zone",
    "ntp_server0",
]

_LOGGER = logging.getLogger(__name__)


class AsusWrtConnectionError(Exception):
    """Error communicating with the router."""
    pass


class AsusWrtLoginError(Exception):
    """Login error / invalid credential."""
    pass


class AsusWrtNotConnectedError(Exception):
    """Not connected to the router."""
    pass


class AsusWrtInfo:

    def __init__(
            self,
            hostname: str,
            username: str,
            password: str,
            *,
            timeout: int = 0,
            session: ClientSession | None = None
    ):
        """
        Create the object and connect with the router
        Parameters:
            hostname : HostName or IP Address of the router
            username : Root user name
            password : Password required to login
        """
        self._hostname = hostname
        self._username = username
        self._password = password
        self._timeout = timeout if timeout > 0 else DEFAULT_TIMEOUT

        self._auth_headers = None
        if session:
            self._session = session
            self._managed_session = False
        else:
            self._session = ClientSession()
            self._managed_session = True

    def __url(self, path):
        """Return the url to a specific path."""
        return f"http://{self._hostname}/{path}"

    async def async_disconnect(self):
        """Close the managed session on exit."""
        if self._managed_session:
            await self._session.close()

    async def async_connect(self):
        """
        Authenticate the object with the router
        """
        if self._auth_headers is not None:
            return

        auth = f"{self._username}:{self._password}".encode("ascii")
        login_token = base64.b64encode(auth).decode("ascii")
        payload = f"login_authorization={login_token}"
        headers = {"user-agent": ASUSWRT_USR_AGENT}

        try:
            async with self._session.post(
                url=self.__url(ASUSWRT_LOGIN_PATH),
                headers=headers,
                data=payload,
                timeout=self._timeout,
                raise_for_status=True,
            ) as resp:
                result = await resp.json()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            raise AsusWrtConnectionError()

        if ASUSWRT_TOKEN_KEY not in result:
            raise AsusWrtLoginError()

        token = result[ASUSWRT_TOKEN_KEY]
        self._auth_headers = {
            "user-agent": ASUSWRT_USR_AGENT,
            "cookie": f"{ASUSWRT_TOKEN_KEY}={token}",
        }

    async def __get(self, command):
        """
        Private get method to execute a hook on the router and return the result
        Parameters:
            command : Command to send to the return
        :returns: string result from the router
        """
        await self.async_connect()
        payload = f"hook={command}"
        try:
            async with self._session.post(
                url=self.__url(ASUSWRT_GET_PATH),
                headers=self._auth_headers,
                data=payload,
                timeout=self._timeout,
                raise_for_status=True,
            ) as resp:
                result = await resp.text()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            raise AsusWrtConnectionError()

        if result.find(ASUSWRT_ERROR_KEY, 0, len(ASUSWRT_ERROR_KEY)+5) >= 0:
            self._auth_headers = None
            raise AsusWrtNotConnectedError()

        return result

    async def get_uptime(self):
        """
        Return uptime of the router
        Format: {'since': 'Thu, 22 Jul 2021 14:32:38 +0200', 'uptime': '375001'}
        :returns: JSON with last boot time and uptime in seconds
        """
        r = await self.__get('uptime()')
        since = r.partition(':')[2].partition('(')[0]
        up = r.partition('(')[2].partition(' ')[0]
        return json.loads('{' + '"since":"{}", "uptime":"{}"'.format(since, up) + '}')

    async def get_uptime_secs(self):
        """
        Return uptime of the router in seconds
        :returns: integer - uptime in seconds
        """
        r = await self.get_uptime()
        return int(r['uptime'])

    async def get_memory_usage(self):
        """
        Return memory usage of the router
        Format: {'mem_total': '262144', 'mem_free': '107320', 'mem_used': '154824'}
        :returns: JSON with memory variables
        """
        s = await self.__get('memory_usage()')
        return json.loads('{' + s[17:])

    async def get_cpu_usage(self):
        """
        Return CPU usage of the router
        Format: {'cpu1_total': '38106047', 'cpu1_usage': '3395512',
                 'cpu2_total': '38106008', 'cpu2_usage': '2384694'}
        :returns: JSON with CPU load statistics
        """
        s = await self.__get('cpu_usage()')
        return json.loads('{' + s[14:])

    async def get_clients_fullinfo(self):
        """
        Obtain a list of all clients
        Format: {"get_clientlist":{"AC:84:C6:6C:A7:C0":{"type": "2", "defaultType": "0", "name": "Archer_C1200",
                                                        "nickName": "Router Forlindon", "ip": "192.168.2.175",
                                                        "mac": "AC:84:C6:6C:A7:C0", "from": "networkmapd",
                                                        "macRepeat": "1", "isGateway": "0", "isWebServer": "0",
                                                        "isPrinter": "0", "isITunes": "0", "dpiType": "",
                                                        "dpiDevice": "", "vendor": "TP-LINK", "isWL": "0",
                                                        "isOnline": "1", "ssid": "", "isLogin": "0", "opMode": "0",
                                                        "rssi": "0", "curTx": "", "curRx": "", "totalTx": "",
                                                        "totalRx": "", "wlConnectTime": "", "ipMethod": "Manual",
                                                        "ROG": "0", "group": "", "callback": "", "keeparp": "",
                                                        "qosLevel": "", "wtfast": "0", "internetMode": "allow",
                                                        "internetState": "1", "amesh_isReClient": "1",
                                                        "amesh_papMac": "04:D4:C4:C4:AD:D0"
                                  },
                                  "maclist": ["AC:84:C6:6C:A7:C0"],
                                  "ClientAPILevel": "2" }}
        :returns: JSON with list of clents and a list of mac addresses
        """
        return json.loads(await self.__get('get_clientlist()'))

    # Total traffic in Mb/s
    async def get_traffic_total(self):
        """
        Get total amount of traffic since last restart (Megabit format)
        Format: {'sent': '15901.92873764038', 'recv': '10926.945571899414'}
        :returns: JSON with sent and received Megabits since last boot
        """
        meas_2 = json.loads(await self.__get('netdev(appobj)'))
        tx = int(meas_2['netdev']['INTERNET_tx'], base=16) * 8 / 1024 / 1024 / 2
        rx = int(meas_2['netdev']['INTERNET_rx'], base=16) * 8 / 1024 / 1024 / 2
        return json.loads('{' + '"sent":"{}", "recv":"{}"'.format(tx, rx) + '}')

    # Traffic in Mb/s . Megabit per second
    # Note this method has a 2 second delay to calculate current throughput
    async def get_traffic(self):
        """
        Get total and current amount of traffic since last restart (Megabit format)
        Note there is a two second delay to determine current traffic
        Format: {"speed": {"tx": 0.13004302978515625, "rx": 4.189826965332031},
                 "total": {"sent": 15902.060073852539, "recv": 10931.135665893555}}
        :returns: JSON with current up and down stream in Mbit/s and totals since last reboot
        """
        meas_1 = await self.__get('netdev(appobj)')
        time.sleep(2)
        meas_2 = await self.__get('netdev(appobj)')
        meas_1 = json.loads(meas_1)
        meas_2 = json.loads(meas_2)
        persec = {}
        totaldata = {}
        tx = int(meas_2['netdev']['INTERNET_tx'], base=16) * 8 / 1024 / 1024 / 2
        totaldata['sent'] = tx
        tx -= int(meas_1['netdev']['INTERNET_tx'], base=16) * 8 / 1024 / 1024 / 2
        persec['tx'] = tx
        rx = int(meas_2['netdev']['INTERNET_rx'], base=16) * 8 / 1024 / 1024 / 2
        totaldata['recv'] = rx
        rx -= int(meas_1['netdev']['INTERNET_rx'], base=16) * 8 / 1024 / 1024 / 2
        persec['rx'] = rx
        return json.dumps({'speed': persec, 'total': totaldata})

    async def get_status_wan(self):
        """
        Get the status of the WAN connection
        Format: {"status": "1", "statusstr": "'Connected'", "type": "'dhcp'", "ipaddr": "'192.168.1.2'",
                 "netmask": "'255.255.255.0'", "gateway": "'192.168.1.1'", "dns": "1.1.1.1'",
                 "lease": "86400", "expires": "81967", "xtype": "''", "xipaddr": "'0.0.0.0'",
                 "xnetmask": "'0.0.0.0'", "xgateway": "'0.0.0.0'", "xdns": "''", "xlease": "0",
                 "xexpires": "0"}
        :returns: JSON with status information on the WAN connection
        """
        r = await self.__get('wanlink()')
        status = {}
        for f in r.split('\n'):
            if 'return' in f:
                if 'wanlink_' in f:
                    key = f.partition('(')[0].partition('_')[2]
                    value = f.rpartition(' ')[-1][:-2]
                    status[key] = value
        return json.loads(json.dumps(status))

    async def is_wan_online(self):
        """
        Returns if the WAN connection in onlise
        :returns: True if WAN is connected
        """
        r = await self.get_status_wan()
        return r['status'] == '1'

    async def get_settings(self):
        """
        Get settings from the router
        Format:{'time_zone': 'MEZ-1DST', 'time_zone_dst': '1', 'time_zone_x': 'MEZ-1DST,M3.2.0/2,M10.2.0/2',
               'time_zone_dstoff': 'M3.2.0/2,M10.2.0/2', 'ntp_server0': 'pool.ntp.org', 'acs_dfs': '1',
               'productid': 'RT-AC68U', 'apps_sq': '', 'lan_hwaddr': '04:D4:C4:C4:AD:D0',
               'lan_ipaddr': '192.168.2.1', 'lan_proto': 'static', 'x_Setting': '1',
               'label_mac': '04:D4:C4:C4:AD:D0', 'lan_netmask': '255.255.255.0', 'lan_gateway': '0.0.0.0',
               'http_enable': '2', 'https_lanport': '8443', 'wl0_country_code': 'EU', 'wl1_country_code': 'EU'}
        :returns: JSON with Router settings
        """
        settings = {}
        for s in NVRAM_INFO:
            r = await self.__get(f"nvram_get({s})")
            settings[s] = json.loads(r)[s]
        return settings

    async def get_lan_ip_adress(self):
        """
        Obtain the IP address of the router
        :return: IP address
        """
        r = await self.__get("nvram_get(lan_ipaddr)")
        return json.loads(r)['lan_ipaddr']

    async def get_lan_netmask(self):
        """
        Obtain the Netmask for the LAN network
        :return: Netmask
        """
        r = await self.__get("nvram_get(lan_netmask)")
        return json.loads(r)['lan_netmask']

    async def get_lan_gateway(self):
        """
        Obtain the gateway for the LAN network
        :return: IP address of gateay
        """
        r = await self.__get("nvram_get(lan_gateway)")
        return json.loads(r)['lan_gateway']

    async def get_dhcp_list(self):
        """
        Obtain a list of DHCP leases
        Format: { "dhcpLeaseMacList":[["00:00:00:00:00:00", "name"], ...]
        :returns: JSON with a list of DHCP leases
        """
        r = await self.__get("dhcpLeaseMacList()")
        return json.loads(r)

    async def get_online_clients(self):
        """
        Obtain a list of MAC-addresses from online clients
        Format: [{"mac": "00:00:00:00:00:00"}, ...]
        :returns: JSON list with MAC adresses
        """
        clnts = await self.get_clients_fullinfo()
        print(clnts)
        lst = []
        for c in clnts['get_clientlist']:
            if (len(c) == 17) and (clnts['get_clientlist'][c]['isOnline'] == '1'):
                lst.append({"mac": c})
        return json.dumps(lst)

    async def get_clients_info(self):
        """
        Obtain info on all clients (limited list of datafields)
        Format: [{"name": "Archer_C1200", "nickName": "Router Forlindon", "ip": "192.168.2.175",
                  "mac": "AC:84:C6:6C:A7:C0", "isOnline": "1", "curTx": "", "curRx": "", "totalTx": ""}, ...]
        :return: JSON list of clients with main characteristics
        """
        clnts = await self.get_clients_fullinfo()
        lst = []
        for c in clnts['get_clientlist']:
            # Only walk through the mac-adresses, not the additional datafields
            if (len(c) == 17) and (clnts['get_clientlist'][c]['isOnline'] == '1'):
                lst.append(
                    {
                        "name": clnts['get_clientlist'][c]['name'],
                        "nickName": clnts['get_clientlist'][c]['nickName'],
                        "ip": clnts['get_clientlist'][c]['ip'],
                        "mac": clnts['get_clientlist'][c]['mac'],
                        "isOnline": clnts['get_clientlist'][c]['isOnline'],
                        "curTx": clnts['get_clientlist'][c]['curTx'],
                        "curRx": clnts['get_clientlist'][c]['curRx'],
                        "totalTx": clnts['get_clientlist'][c]['totalTx'],
                        "totalRx": clnts['get_clientlist'][c]['totalRx'],
                    }
                )
        return json.loads(json.dumps(lst))

    async def get_client_info(self, clientid):
        """
        Get info on a single client
        :param clientid: MAC address of the client requested
        :return: JSON with clientinfo (see get_clients_info() for description)
        """
        clnts = await self.get_clients_fullinfo()
        if clientid in clnts['get_clientlist']:
            return clnts[clientid]
        else:
            return None
