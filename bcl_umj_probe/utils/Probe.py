import uuid
import socket
from utils.network_utils.NetworkInfo import NetworkInfo
from utils.network_utils.NetworkWiFi import NetworkkWiFi
import subprocess
import platform
import logging
import logging
import platform
import subprocess
import socket
import psutil

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)

class Probe:
    def __init__(self) -> None:
        self.USE_DB=True
        self.logger = logging.getLogger(__name__)
        
    def gen_probe_register_data(self):
        id=self.gen_id()
        hostname=socket.gethostname()
        probe_id=f"prb-{hostname}-{id}"

        if probe_id and hostname:
            return probe_id, hostname
        
    def read_txt_file(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                data = file.read()
            return data
        except FileNotFoundError:
            return f"File not found: {filepath}"
        except Exception as e:
            return f"An error occurred: {str(e)}"

    def gen_id(self):
        id = uuid.uuid4()
        if id:
            return str(id)
        else:
            return self.logger.info("Probe ID Gen Failed")  

    def collect_local_stats(self, id: str, hostname: str):
        stat_data={}

        stat_data["prb_id"] = id
        stat_data["hstnm"] = hostname
        
        self.logger.info("\n📍 Local System Stats")
        stat_data["sys"] = f"{platform.system()} {platform.release()}"
        stat_data["cpu"] = f"{psutil.cpu_percent()}%"
        mem = psutil.virtual_memory()
        stat_data["mem"] = f"{mem.used / 1024**2:.2f} MB / {mem.total / 1024**2:.2f} MB"
        disk = psutil.disk_usage('/')
        stat_data['dsk'] = f"{disk.used / 1024**3:.2f} GB / {disk.total / 1024**3:.2f} GB"
        uptime = subprocess.getoutput("uptime -p")
        stat_data['upt'] = f"{uptime}"
        stat_data['ifcs'] = {}
        
        # Network interfaces
        self.logger.info("\n🔌 Interface Statistics:")
        for iface, addrs in psutil.net_if_addrs().items():

            stats = psutil.net_if_stats()[iface]
            io = psutil.net_io_counters(pernic=True)[iface]
            stat_data['ifcs'][iface]['dta'] = stats
            stat_data['ifcs'][iface]['bndwth_io'] = f"  Sent: {io.bytes_sent / 1024:.2f} KB | Recv: {io.bytes_recv / 1024:.2f} KB"
            stat_data['ifcs'][iface]['pckt_io'] = f"  Sent Packets: {io.packets_sent} | Recv Packets: {io.packets_recv}"

            """
            self.logger.info(f"Interface: {iface}")
            self.logger.info(f"  Speed: {stats.speed} Mbps")
            self.logger.info(f"  Status: {'UP' if stats.isup else 'DOWN'}")
            io = psutil.net_io_counters(pernic=True)[iface]
            self.logger.info(f"  Sent: {io.bytes_sent / 1024:.2f} KB | Recv: {io.bytes_recv / 1024:.2f} KB")
            
            """

        return stat_data if stat_data.items() else None
    
    
            
            

        

        
