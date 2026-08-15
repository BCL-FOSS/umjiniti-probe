from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from utils.network_utils.ProbeInfo import ProbeInfo
import logging
import bcrypt
import os
from typing import Callable
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.PacketCapture import PacketCapture
from utils.alerts_utils.SlackAlert import SlackAlert
from utils.alerts_utils.JiraSM import JiraSM
from utils.alerts_utils.EmailSenderHandler import EmailSenderHandler
from utils.alerts_utils.BotConnection import BotConnection
import logging
from crontab import CronTab
from utils.alerts_utils.LogAlert import LogAlert
from utils.Parsers import Parsers
from utils.RedisDB import RedisDB
from utils.network_utils.base.Network import Network
import httpx

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logging.getLogger("fakeredis").setLevel(logging.WARNING)
logging.getLogger("docket.worker").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)
net_discovery = NetworkDiscovery()
net_test = NetworkTest()
net_base = Network()
pcap = PacketCapture()
probe_util = ProbeInfo()
log_alert = LogAlert()
slack_alert = SlackAlert()
jira_alert = JiraSM()
email_alert = EmailSenderHandler()
bot_connection = BotConnection()
parsers = Parsers()
cron=CronTab(user='root')  
action_map: dict[str, Callable[[dict], object]] = {
    "trcrt_dns": net_test.dnstraceroute,
    "trcrt": net_test.traceroute,
    "test_srvr": net_test.iperf_server,
    "test_clnt": net_test.iperf_client,
    "scan_vuln": net_discovery.vulnerabilities,
    "scan_snmp": net_discovery.snmp,
    "scan_os": net_discovery.operating_system,
    "scan_srvc": net_discovery.services,
    "scan_cust": net_discovery.custom,
    "scan_map": net_discovery.mapper,
    "pcap_lcl": pcap.pcap_local,
    "pcap_tux": pcap.pcap_remote_linux,
    "pcap_win": pcap.pcap_remote_windows,
    "slack": slack_alert.send_alert_message,
    "jira": jira_alert.send_alert,
    "bot": bot_connection.mcp_exec,
    "email": email_alert.send_transactional_email,
}
api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)
prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))
error_response = 'missing required data'
cwd = os.getcwd()
utility_scripts_path = os.path.join(cwd, 'utils', 'jini-utils')
nmap_scans_path = os.path.join(cwd, 'nmap_scans')
core_url = f"https://{os.getenv('CORE_URL')}/v1/api/core/probe"

async def get_probe_data():
    await prb_db.connect_db()
    probe_data = await prb_db.get_all_data(match='prb:*')
    probe_data_dict = next(iter(probe_data.values()))
    return probe_data_dict

async def check_for_utils():
    # Check if jini utility scripts have been downloaded. If not, clones from github.
    if os.path.exists(utility_scripts_path) is False:
        code, output, error = await Network.run_shell_cmd(cmd=f'cd {os.path.join(cwd, "utils")} && git clone https://github.com/BCL-FOSS/jini-utils.git')
        logger.info(f'code: {code}\noutput: {output}\nerror: {error}')
    else:
        pass

async def init_probe():
    prb_id, hstnm = probe_util.gen_probe_register_data()
    
    if os.environ.get('DEFAULT_INTERFACE') is None:
        net_discovery.set_interface(probe_util.get_ifaces()[0])
    else:
        net_discovery.set_interface(os.environ.get('DEFAULT_INTERFACE'))

    probe_data_check = await prb_db.get_all_data(match='*prb:*', cnfrm=True)

    if probe_data_check is False:
        probe_data=probe_util.collect_local_stats(id=f"{prb_id}", hostname=hstnm)
        host_interfaces = probe_util.get_ifaces()
        probe_data['iface_list'] = host_interfaces
        logger.info(host_interfaces)

        if await prb_db.upload_db_data(id=f"{prb_id}", data=probe_data) > 0:
            logger.info(f"Successfully uploaded probe data to Redis for probe ID: {prb_id}")
            return prb_id, hstnm, probe_data
        else:
            exit(1)

    elif probe_data_check is True:
        probe_data = await prb_db.get_all_data(match='*prb:*')
        probe_data_dict = next(iter(probe_data.values()))
        prb_id = probe_data_dict.get('prb_id')
        hstnm = probe_data_dict.get('hstnm')
        return prb_id, hstnm, probe_data_dict
    
async def check_api_key(key: str):
    probe_data = await prb_db.get_all_data(match='*prb:*')
    probe_data_dict = next(iter(probe_data.values()))
    stored_api_key = probe_data_dict.get("api_key")
    
    if not stored_api_key or bcrypt.checkpw(key, stored_api_key) is False:
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid"
        )
    else:
        return 200
            
async def validate_api_key(key: str = Depends(api_key_header)):
    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_response
        )
    if await prb_db.get_all_data(match='*prb:*', cnfrm=True) is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_response
        )
    await check_api_key(key)
            
async def validate_mcp_api_key(headers: dict[str, str]) -> None:
    key = headers.get("x-api-key")
    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_response
        )
    if await prb_db.get_all_data(match='*prb:*', cnfrm=True) is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_response
        )
    await check_api_key(key)
    
async def make_http_request(cmd: str, url: str, payload: dict = {}, headers: dict = {}, cookies: str = ''):
    async with httpx.AsyncClient() as client:
        if cmd == 'p':
            client.cookies.set("access_token", value=cookies)
            post_result = await client.post(url, json=payload, headers=headers)
            return post_result
        elif cmd == 'g':
            get_result = await client.get(url, headers=headers)
            return get_result
