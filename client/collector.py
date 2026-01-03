import os
import json
import socket
import hashlib
import base64
import platform
import psutil
import winreg
import requests
import warnings
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

warnings.filterwarnings('ignore')

from datetime import datetime

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
CASE_ID = f"CASE-{timestamp}"

print("\n" + "="*60)
print("  CHAIN-OF-CUSTODY LEGAL REQUIREMENTS")
print("="*60)
INVESTIGATOR_NAME = input("Investigator Name: ").strip() or "Digital Forensics Investigator"
INVESTIGATOR_ID = input("Investigator ID: ").strip() or "DFI-001"
DEPARTMENT = input("Department: ").strip() or "Cyber Security Incident Response Team"
LOCATION = input("Location: ").strip() or "Corporate Headquarters"
CASE_DESCRIPTION = input("Case Description: ").strip() or f"Volatile data collection - {timestamp}"
COLLECTOR_VERSION = "TAC-v1.0"
print("="*60 + "\n")


SERVER_URL = "https://192.168.56.20:5000/api/upload"

BASE_PATH = r"C:\forensics_project"
KEYS_PATH = os.path.join(BASE_PATH, "keys")
EVIDENCE_PATH = os.path.join(BASE_PATH, "collected_evidence")

def get_system_info():
    """Collect system information"""
    print("[*] Collecting system information...")
    return {
        "computer_name": socket.gethostname(),
        "platform": platform.system(),
        "platform_version": platform.version(),
        "processor": platform.processor(),
        "username": os.getlogin(),
        "collection_time": datetime.now().isoformat()
    }

def get_running_processes():
    """Collect running processes"""
    print("[*] Collecting running processes...")
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return processes

def get_network_connections():
    """Collect active network connections"""
    print("[*] Collecting network connections...")
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            connections.append({
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid
            })
        except:
            pass
    return connections

def get_registry_run_keys():
    """Collect registry Run keys (persistence mechanisms)"""
    print("[*] Collecting registry Run keys...")
    run_keys = []
    
    registry_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
    ]
    
    for hive, path in registry_paths:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, value, type_ = winreg.EnumValue(key, i)
                    run_keys.append({
                        "hive": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                        "path": path,
                        "name": name,
                        "value": value
                    })
                    i += 1
                except WindowsError:
                    break
            winreg.CloseKey(key)
        except WindowsError:
            pass
    
    return run_keys

def get_startup_items():
    """Collect startup folder items"""
    print("[*] Collecting startup items...")
    startup_items = []
    
    startup_paths = [
        os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
        os.path.join(os.environ.get('PROGRAMDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup')
    ]
    
    for path in startup_paths:
        if os.path.exists(path):
            for item in os.listdir(path):
                startup_items.append({
                    "path": path,
                    "item": item
                })
    
    return startup_items

def get_scheduled_tasks():
    """Collect Windows scheduled tasks"""
    print("[*] Collecting scheduled tasks...")
    import subprocess
    try:
        result = subprocess.run(['schtasks', '/query', '/fo', 'CSV', '/nh'], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            tasks = []
            for line in lines[1:]:  # Skip header
                if line.strip():
                    parts = line.split('","')
                    if len(parts) >= 3:
                        tasks.append({
                            "task_name": parts[0].strip('"'),
                            "status": parts[1].strip('"'),
                            "next_run_time": parts[2].strip('"')
                        })
            return tasks[:50]  
    except:
        pass
    return []

def get_browser_history():
    """Collect basic browser history indicators"""
    print("[*] Collecting browser history indicators...")
    history_indicators = []
    
    
    browser_paths = [
        os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data\Default\History"),
        os.path.expanduser(r"~\AppData\Roaming\Mozilla\Firefox\Profiles"),
        os.path.expanduser(r"~\AppData\Local\Microsoft\Edge\User Data\Default\History")
    ]
    
    for path in browser_paths:
        if os.path.exists(path):
            if os.path.isfile(path):
                history_indicators.append({
                    "browser": os.path.basename(os.path.dirname(path)),
                    "history_file": path,
                    "modified": datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                })
            elif os.path.isdir(path):
               
                for root, dirs, files in os.walk(path):
                    if 'places.sqlite' in files:
                        history_file = os.path.join(root, 'places.sqlite')
                        history_indicators.append({
                            "browser": "Firefox",
                            "history_file": history_file,
                            "modified": datetime.fromtimestamp(os.path.getmtime(history_file)).isoformat()
                        })
                        break
    
    return history_indicators

def collect_all_artifacts():
    """Collect all forensic artifacts"""
    print("\n" + "="*50)
    print("  FORENSICS TRIAGE ACQUISITION CLIENT")
    print("="*50 + "\n")
    
    return {
    "system_info": get_system_info(),
    "processes": get_running_processes(),
    "network_connections": get_network_connections(),
    "registry_run_keys": get_registry_run_keys(),
    "startup_items": get_startup_items(),
    "scheduled_tasks": get_scheduled_tasks(),          
    "browser_history_indicators": get_browser_history(),  
   
    "chain_of_custody_legal": {
        "case_id": CASE_ID,
        "investigator_name": INVESTIGATOR_NAME,
        "investigator_id": INVESTIGATOR_ID,
        "department": DEPARTMENT,
        "location": LOCATION,
        "case_description": CASE_DESCRIPTION,
        "collection_time": datetime.now().isoformat(),
        "collector_version": COLLECTOR_VERSION
    }
}


def calculate_hash(data):
    """Calculate SHA-256 hash of data"""
    json_data = json.dumps(data, sort_keys=True)
    return hashlib.sha256(json_data.encode()).hexdigest()

def sign_hash(hash_value):
    """Sign hash using private key"""
    print("[*] Signing evidence with private key...")
    
    private_key_path = os.path.join(KEYS_PATH, "private_key.pem")
    
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    signature = private_key.sign(
        hash_value.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode()

def save_evidence_locally(artifacts, evidence_hash, signature):
    """Save collected evidence locally"""
    print("[*] Saving evidence locally...")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    evidence_folder = os.path.join(EVIDENCE_PATH, f"evidence_{timestamp}")
    os.makedirs(evidence_folder, exist_ok=True)
    
    
    with open(os.path.join(evidence_folder, "artifacts.json"), 'w') as f:
        json.dump(artifacts, f, indent=2)
    
    coc_log = {
        "case_id": CASE_ID,
        "source_computer": socket.gethostname(),
        "collector_agent": COLLECTOR_VERSION,
        "collection_time": datetime.now().isoformat(),
        "evidence_hash": evidence_hash,
        "signature": signature
    }
    
    with open(os.path.join(evidence_folder, "chain_of_custody.json"), 'w') as f:
        json.dump(coc_log, f, indent=2)
    
    print(f"[+] Evidence saved to: {evidence_folder}")


def send_to_server(artifacts, evidence_hash, signature):
    """Send evidence to verification server"""
    print("[*] Sending evidence to server...")
    
    payload = {
        "case_id": CASE_ID,
        "source_computer": socket.gethostname(),
        "collector_agent": COLLECTOR_VERSION,
        "artifacts": artifacts,
        "evidence_hash": evidence_hash,
        "signature": signature
    }
    
    try:
        response = requests.post(
            SERVER_URL,
            json=payload,
            verify=False,
            timeout=30
        )
        
        result = response.json()
        
        print("\n" + "="*50)
        print("  SERVER RESPONSE")
        print("="*50)
        print(f"  Status: {result.get('status')}")
        print(f"  Signature: {result.get('signature_status')}")
        print(f"  Hash: {result.get('hash_status')}")
        print(f"  Message: {result.get('message')}")
        print("="*50 + "\n")
        
        return result
        
    except requests.exceptions.ConnectionError:
        print("[!] Error: Could not connect to server")
        return None
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        return None

def main():
    
    artifacts = collect_all_artifacts()
    
    print("[*] Calculating evidence hash...")
    evidence_hash = calculate_hash(artifacts)
    print(f"[+] Evidence Hash: {evidence_hash}")
    
    signature = sign_hash(evidence_hash)
    print("[+] Evidence signed successfully")
    
    save_evidence_locally(artifacts, evidence_hash, signature)

    
    send_to_server(artifacts, evidence_hash, signature)
    
    print("[+] Collection complete!")

if __name__ == "__main__":
    main()
