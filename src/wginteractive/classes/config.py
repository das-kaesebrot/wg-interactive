import configparser
import os

class Config:
    
    peers_output_dir = "/var/lib/wginteractive/output"
    wireguard_conf_dir = "/etc/wireguard"
    
    def __init__(self, filename: str = "wg-interactive.ini", config_dir = "/etc/wg-interactive") -> None:
        self._filename = filename
        self._config_dir = config_dir.rstrip("/")        
        self._filepath = os.path.join(self._config_dir, self._filename)
        
        self._read_out_config()
                    
    def _read_out_config(self):
        config = configparser.ConfigParser()
        
        if os.path.isfile(self._filepath):
            config.read(self._filepath)
            
            if 'wgconfpath' in config['main']:
                self.wireguard_conf_dir = config['main'].get('wgconfpath').rstrip("/")
                
                if os.getenv("WGCONFPATH"):
                    self.wireguard_conf_dir = os.getenv("WGCONFPATH").rstrip("/")
                
                if not os.path.isabs(self.wireguard_conf_dir):
                    raise ValueError(f"Value of 'wgconfpath' must be absolute, given value: '{self.wireguard_conf_dir}'")
            
            if 'wgpeersdir' in config['main']:
                self.peers_output_dir = config['main'].get('wgpeersdir').rstrip("/")
                
                if os.getenv("WGPEERSDIR"):
                    self.peers_output_dir = os.getenv("WGPEERSDIR").rstrip("/")
                
                if not os.path.isabs(self.peers_output_dir):
                    raise ValueError(f"Value of 'wgpeersdir' must be absolute, given value: '{self.wireguard_conf_dir}'")
            
        else:
            self._create_config()
    
    
    def _create_config(self):
        os.makedirs(self._config_dir, exist_ok=True)
        with open(self._filepath, 'w') as f:
            f.write(f"""[main]
# wgconfpath = {self.wireguard_conf_dir}
# wgpeersdir = {self.peers_output_dir}
""")