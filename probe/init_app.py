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
import logging
from crontab import CronTab
from utils.RedisDB import RedisDB
from utils.network_utils.base.Network import Network
import httpx
import uuid

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
cron=CronTab(user='root')  
web_client = httpx.AsyncClient()
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
    "pcap_win": pcap.pcap_remote_windows
}
api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)
prb_db = RedisDB(hostname=os.environ.get('PROBE_DB'), port=os.environ.get('PROBE_DB_PORT'))
error_response = 'missing required data'
cwd = os.getcwd()
utility_scripts_path = os.path.join(cwd, 'utils', 'jini-utils')
automation_scripts_path = os.path.join(cwd, 'auto_scripts')
nmap_scans_path = os.path.join(cwd, 'nmap_scans')
parser_script_path=os.path.join(utility_scripts_path, f'Parsers.py')
core_url = f"https://{os.getenv('CORE_URL')}/v1/api/core/probes"

def as_bytes(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    return str(value).encode()

async def get_probe_data():
    await prb_db.connect_db()
    probe_data = await prb_db.get_all_data(match='prb:*')
    probe_data_dict = next(iter(probe_data.values()))
    return probe_data_dict

async def check_for_utils():
    if os.path.exists(utility_scripts_path) is False:
        code, output, error = await Network.run_shell_cmd(cmd=f'cd {os.path.join(cwd, "utils")} && git clone https://github.com/BCL-FOSS/jini-utils.git')
        logger.info(f'code: {code}\noutput: {output}\nerror: {error}')
    else:
        pass

async def init_probe():
    if os.environ.get('DEFAULT_INTERFACE') is None:
        net_discovery.set_interface(probe_util.get_ifaces()[0])
    else:
        net_discovery.set_interface(os.environ.get('DEFAULT_INTERFACE'))
    probe_data_check = await prb_db.get_all_data(match='*prb:*', cnfrm=True)
    if probe_data_check is False:
        prb_id, hstnm = probe_util.gen_probe_register_data()
        probe_data=probe_util.collect_local_stats()
        probe_data['prb_id'] = prb_id
        probe_data['site'] = os.getenv('PROBE_SITE')
        probe_data['hstnm'] = hstnm
        probe_data['url'] = os.getenv('PROBE_URL')
        probe_data['umj_url'] = os.getenv('CORE_URL')
        probe_data['name'] = os.getenv('PROBE_NAME')
        probe_data['assigned_user'] = os.getenv('PROBE_USER')
        host_interfaces = probe_util.get_ifaces()
        probe_data['iface_list'] = host_interfaces
        probe_data['enrolled'] = 'n'
        new_api_key = str(uuid.uuid4())
        api_hashed = bcrypt.hashpw(new_api_key.encode(), bcrypt.gensalt())
        probe_data['api_key'] = api_hashed
        logger.info(host_interfaces)
        if await prb_db.upload_db_data(id=f"{prb_id}", data=probe_data) > 0:
            logger.info(f"""ATTENTION: Your API Key for Probe ID: {prb_id} is below. 
            Please copy and store in a password manager of your choice for safe keeping. This willl not be displayed again.\n

            API KEY: {new_api_key}
            
            """)
            return prb_id, hstnm, probe_data
    elif probe_data_check is True:
        probe_data = await prb_db.get_all_data(match='*prb:*')
        probe_data_dict = next(iter(probe_data.values()))
        prb_id = str(probe_data_dict.get('prb_id'))
        hstnm = str(probe_data_dict.get('hstnm'))
        return prb_id, hstnm, probe_data_dict
            
    
async def check_api_key(key: str):
    probe_data = await prb_db.get_all_data(match='*prb:*')
    probe_data_dict = next(iter(probe_data.values()))
    stored_api_key = probe_data_dict.get("api_key")
    
    if not stored_api_key or bcrypt.checkpw(key.encode(), as_bytes(stored_api_key)) is False:
        
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
    
async def make_http_request(cmd: str, url: str, payload: dict = None, api_key: str = None, cookies: str = None, cookie_name: str = None, token: str = None):
    # Deliberately not `async with`: web_client is a module-level AsyncClient
    # and the context manager would close it after the first request.
    client = web_client
    headers={}
    if api_key is not None:
        headers['X-UMJ-WFLW-API-KEY'] = api_key
    if token is not None:
        headers['Authorization'] = f'Bearer {token}'
    if cookies is not None:
        client.cookies.set(cookie_name, value=cookies)
    payload = payload if payload is not None else {}
    match cmd:
        case 'p':
            headers['Content-Type'] = 'application/json'
            post_result = await client.post(url, json=payload, headers=headers)
            return post_result
        case 'g':
            get_result = await client.get(url, headers=headers)
            return get_result