from fastapi import FastAPI
from fastmcp import FastMCP
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from fastmcp import FastMCP
import redis
from utils.Probe import Probe
import logging
from utils.RedisDB import RedisDB
import uuid
from passlib.hash import bcrypt
import sys

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Define the API key header scheme (e.g., header name "x-api-key")
api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)
r = redis.Redis(host='localhost', port=6369)
probe_utils = Probe()

logger.info(r.ping())

id, hostname = probe_utils.gen_probe_register_data()
cursor = b'0'  # Start the SCAN with cursor 0

prb_key=probe_utils.read_txt_file('key.txt')

# Check if probe has been initialized
cursor, keys = r.scan(cursor=cursor, match=f'*{hostname}*')
if keys:
    pass
else:
    probe_data=probe_utils.collect_local_stats(id=f"{id}", hostname=hostname)
    probe_data['api_key'] = bcrypt.hash(str(uuid.uuid4()))
    logger.info(f"API Key for umjiniti probe {id}: {probe_data['api_key']}. Store this is a secure location as it will not be displayed again.")
    str_hashmap = {str(k): str(v) for k, v in probe_data.items()}
    result = r.hset(id, mapping=str_hashmap)
    if result > 0:
        logger.info(result)
    else:
        sys.exit(status=0)

# Dependency function to validate the API key
def validate_api_key(key: str = Depends(api_key_header)):
    pong = r.ping() 
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
    
mcp = FastMCP("API Tools")
api = FastAPI(dependencies=[Depends(validate_api_key)], lifespan=mcp.lifespan)

# Mount MCP at /mcp
api.mount("/mcp/", mcp.http_app())