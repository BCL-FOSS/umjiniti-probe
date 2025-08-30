import platform
import logging

class Network():
    
    def __init__(self):
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('passlib').setLevel(logging.ERROR)
        self.system = platform.system().lower()
        self.logger = logging.getLogger(__name__)
        