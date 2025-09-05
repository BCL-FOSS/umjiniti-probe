from fastapi import FastAPI
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
import redis
from utils.network_utils.ProbeInfo import ProbeInfo
import logging
import uuid
from passlib.hash import bcrypt
import sys
import asyncio
from utils.RedisDB import RedisDB
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.NetUtil import NetUtil
from utils.network_utils.NetworkSNMP import NetworkSNMP

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Define the API key header scheme (e.g., header name "x-api-key")
api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)
prb_db = RedisDB(hostname='localhost', port='6379')
probe_utils = ProbeInfo()
net_discovery = NetworkDiscovery()
net_test = NetworkTest()
net_utils = NetUtil(interface='')
net_snmp = NetworkSNMP()

async def probe_init():
    await prb_db.connect_db()
    ping = await prb_db.ping_db()
    logger.info(f'redis db ping result: {ping}')
    prb_id, hstnm = probe_utils.gen_probe_register_data()

    if await prb_db.get_all_data(match=f'*{hstnm}*', cnfrm=True) is False:
        probe_data=probe_utils.collect_local_stats(id=f"{prb_id}", hostname=hstnm)
        probe_data['api_key'] = bcrypt.hash(str(uuid.uuid4()))
        logger.info(f"API Key for umjiniti probe {id}: {probe_data['api_key']}. Store this is a secure location as it will not be displayed again.")
        logger.info(probe_data)
    
        if await prb_db.upload_db_data(id=f"{prb_id}", data=probe_data) is not None:
            logger.info(f'probe data for {prb_id} generated successfully')
        else:
            logger.error('Probe data generation failed')
    else:
        pass
        
asyncio.run(probe_init())

# Dependency function to validate the API key
def validate_api_key(key: str = Depends(api_key_header)):
    r = redis.Redis(host='localhost', port=6379)
    pong = r.ping()
    logger.info(pong)
    cursor = b'0'
    id, hostname = probe_utils.gen_probe_register_data()
    cursor, keys = r.scan(cursor=cursor, match=f'*{hostname}*')
    if keys:
        all_data = {}
        for key in keys:
                # Retrieve hash data for each key
            hash_data = r.hgetall(key)
            all_data[key] = {k: v for k, v in hash_data.items()}
            logger.info(all_data.items())

        if bcrypt.verify(key, hash=all_data['api_key']) is False:
            raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or missing API key"
                )
        else:
            return key

api = FastAPI()

