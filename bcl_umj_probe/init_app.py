from fastapi import FastAPI
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
import redis
from utils.network_utils.ProbeInfo import ProbeInfo
import logging
import uuid
from passlib.hash import bcrypt
import sys

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Define the API key header scheme (e.g., header name "x-api-key")
api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)
r = redis.Redis(host='localhost', port=6379)

pong = r.ping()

logger.info(pong)

probe_utils = ProbeInfo()

# Dependency function to validate the API key
def validate_api_key(key: str = Depends(api_key_header)):
    cursor = b'0'
    pong = r.ping() 
    logger.info(pong)
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

