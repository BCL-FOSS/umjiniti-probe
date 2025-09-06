from fastapi import FastAPI
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
import redis
from utils.network_utils.ProbeInfo import ProbeInfo
import logging
from passlib.hash import bcrypt
from utils.RedisDB import RedisDB
from utils.network_utils.ProbeInfo import ProbeInfo
from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkTest import NetworkTest
from utils.NetUtil import NetUtil
from utils.network_utils.NetworkSNMP import NetworkSNMP

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)
prb_db = RedisDB(hostname='localhost', port='6379')
probe_utils = ProbeInfo()
net_discovery = NetworkDiscovery()
net_test = NetworkTest()
net_utils = NetUtil(interface='')
net_snmp = NetworkSNMP()

# Dependency function to validate the API key
def validate_api_key(key: str = Depends(api_key_header)):
    r = redis.Redis(host='localhost', port=6379, decode_responses=True)  # decode for str output
    pong = r.ping()
    logger.info(f"Redis ping: {pong}")

    _, hostname = probe_utils.gen_probe_register_data()
    cursor, keys = r.scan(cursor=0, match=f'*{hostname}*')

    if keys:
        for redis_key in keys:
            hash_data = r.hgetall(redis_key)
            logger.info(hash_data)
            stored_api_key = hash_data.get("api_key")

            if not stored_api_key:
                raise

            if bcrypt.verify(key, stored_api_key):
                return key
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or missing API key"
                )
"""
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

"""


api = FastAPI()