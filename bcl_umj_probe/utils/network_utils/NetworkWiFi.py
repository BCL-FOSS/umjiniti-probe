from scapy.all import sniff, Packet
from scapy.all import *
from scapy import *
from scapy.tools import *
from scapy.layers import dot11 
from scapy.layers.dot11 import RadioTap, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq
from scapy.layers.inet import *
from scapy.layers.l2 import *
from manuf import manuf
import subprocess
import threading
import time
import json
import csv
import os
from utils.network_utils.base.Network import Network
from datetime import datetime, timedelta

class NetworkkWiFi(Network):
    def __init__(self, interface: str):
        super().__init__()

        # Global survey point list
        self.survey_points = []
        self.lock = threading.Lock()

        # Manufacturer lookup
        self.parser = manuf.MacParser()

        # Interface settings
        self.MONITOR_INTERFACE = None
        self.BASE_INTERFACE = interface
        self.job_id = str(uuid.uuid4()+"-"+datetime.today().strftime('%Y-%m-%d'))
        self.SURVEY_RESULTS_DIR=os.path.join(os.getcwd(), f"/{self.job_id}_survey_results")

        if os.path.exists(self.SURVEY_RESULTS_DIR) is False:
            os.makedirs(self.SURVEY_RESULTS_DIR)

        self.HISTORY_DIR = self.SURVEY_RESULTS_DIR
        self.HISTORY_JSON = os.path.join(self.HISTORY_DIR, f"{self.job_id}_survey_history.json")
        self.HISTORY_CSV = os.path.join(self.HISTORY_DIR, f"{self.job_id}_survey_history.csv")

    def ensure_history_dir(self):
        if os.path.exists(self.HISTORY_DIR) is False:
            os.makedirs(self.HISTORY_DIR)

    def save_point_to_history(self, point):
        self.ensure_history_dir()

        try:
            if os.path.exists(self.HISTORY_JSON):
                with open(self.HISTORY_JSON, "r") as f:
                    data = json.load(f)
            else:
                data = []

            data.append(point)

            with open(self.HISTORY_JSON, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.info(f"[!] Failed to save JSON history: {e}")
            
        try:
            new_file = not os.path.exists(self.HISTORY_CSV)
            with open(self.HISTORY_CSV, "a", newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "timestamp", "mac", "ssid", "manufacturer", "type", "x", "y", "signal", "noise", "snr", "coverage"
                ])
                if new_file:
                    writer.writeheader()
                writer.writerow(point)
        except Exception as e:
            self.logger.info(f"[!] Failed to save CSV history: {e}")

    def run_command(self, cmd):
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            self.logger.info(f"Command failed: {e}")

    def enable_monitor_mode(self):
        global MONITOR_INTERFACE
        self.run_command("airmon-ng check kill")
        self.run_command(f"airmon-ng start {self.BASE_INTERFACE}")
        MONITOR_INTERFACE = self.BASE_INTERFACE + "mon"
        time.sleep(2)

    def disable_monitor_mode(self):
        global MONITOR_INTERFACE
        if MONITOR_INTERFACE:
            self.run_command(f"airmon-ng stop {MONITOR_INTERFACE}")
            self.run_command("service NetworkManager restart || systemctl restart NetworkManager || true")
            MONITOR_INTERFACE = None
            time.sleep(2)

    def get_gps_coordinates(self):
        try:
            out = subprocess.check_output(["gpspipe", "-w", "-n", "10"], timeout=5).decode()
            for line in out.splitlines():
                if '"lat"' in line and '"lon"' in line:
                    
                    data = json.loads(line)
                    return data.get("lat"), data.get("lon")
        except Exception as e:
            self.logger.info(f"No GPS data: {e}")
        return None, None

    def packet_handler(self, pkt: Packet):
        if not pkt.haslayer(dot11):
            return

        dot11_layer = pkt.getlayer(dot11)
        radiotap_layer = pkt.getlayer(RadioTap)

        mac = dot11_layer.addr2
        if mac is None:
            return

        # Radiotap fields
        signal_strength = None
        noise_level = None
        channel_freq = None

        if radiotap_layer:
            signal_strength = getattr(radiotap_layer, 'dBm_AntSignal', None)
            noise_level = getattr(radiotap_layer, 'dBm_AntNoise', None)
            channel_freq = getattr(radiotap_layer, 'ChannelFrequency', None)

        signal_strength = signal_strength if signal_strength is not None else -100
        noise_level = noise_level if noise_level is not None else -95
        channel_freq = channel_freq if channel_freq is not None else 2412

        # Signal to noise ratio calculation
        snr = signal_strength - noise_level

        # Classify coverage
        if snr >= 30:
            coverage_level = "Good"
        elif 20 <= snr < 30:
            coverage_level = "Fair"
        else:
            coverage_level = "Poor"

        manufacturer = self.parser.get_manuf(mac) or "Unknown"
        lat, lon = self.get_gps_coordinates()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

        point = None

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Beacon].info.decode(errors='ignore')
            else:
                ssid = pkt[Dot11ProbeResp].info.decode(errors='ignore')

            point = {
                "timestamp": timestamp,
                "x": lat if lat else signal_strength,
                "y": lon if lon else channel_freq,
                "signal": signal_strength,
                "noise": noise_level,
                "snr": snr,
                "coverage": coverage_level,
                "ssid": ssid,
                "mac": mac,
                "type": "AP",
                "manufacturer": manufacturer
            }

        elif pkt.haslayer(Dot11ProbeReq):
            point = {
                "timestamp": timestamp,
                "x": lat if lat else signal_strength,
                "y": lon if lon else 0,
                "signal": signal_strength,
                "noise": noise_level,
                "snr": snr,
                "coverage": coverage_level,
                "ssid": None,
                "mac": mac,
                "type": "Client",
                "manufacturer": manufacturer
            }

        if point:
            with self.lock:
                self.survey_points.append(point)
                self.save_point_to_history(point)

    def start_sniffing(self, timeout=10):
        with self.lock:
            self.survey_points.clear()
        if not MONITOR_INTERFACE:
            raise Exception("Monitor interface not enabled!")
        sniff(iface=MONITOR_INTERFACE, prn=self.packet_handler, timeout=timeout, monitor=True)

    def get_survey_json(self):
        if os.path.exists(self.HISTORY_JSON):
            with open(self.HISTORY_JSON, "r") as f:
                data = json.load(f)
            return data if data is not None else None
