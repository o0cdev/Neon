
import json
import time
import threading
import psutil
import socket
import subprocess
import sqlite3
from datetime import datetime
import hashlib
import base64

class TelemetryEngine:
    def __init__(self, db_path="neon_database.db"):
        self.db_path = db_path
        self.collectors = {}
        self.active_monitors = []
        self.telemetry_buffer = []
        self.running = False
        
    def start_collection(self):
        self.running = True
        collectors = [
            threading.Thread(target=self.collect_process_telemetry, daemon=True),
            threading.Thread(target=self.collect_network_telemetry, daemon=True),
            threading.Thread(target=self.collect_file_telemetry, daemon=True),
            threading.Thread(target=self.collect_registry_telemetry, daemon=True),
            threading.Thread(target=self.collect_system_telemetry, daemon=True)
        ]
        
        for collector in collectors:
            collector.start()
            self.active_monitors.append(collector)
    
    def stop_collection(self):
        self.running = False
        
    def collect_process_telemetry(self):
        previous_processes = set()
        
        while self.running:
            try:
                current_processes = set()
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'ppid']):
                    try:
                        proc_info = proc.info
                        proc_key = (proc_info['pid'], proc_info['name'])
                        current_processes.add(proc_key)
                        
                        if proc_key not in previous_processes:
                            telemetry = {
                                "event_type": "process_creation",
                                "timestamp": datetime.now().isoformat(),
                                "pid": proc_info['pid'],
                                "process_name": proc_info['name'],
                                "command_line": ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                                "parent_pid": proc_info['ppid'],
                                "create_time": proc_info['create_time'],
                                "source": "endpoint_agent"
                            }
                            self.store_telemetry(telemetry)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                terminated_processes = previous_processes - current_processes
                for pid, name in terminated_processes:
                    telemetry = {
                        "event_type": "process_termination",
                        "timestamp": datetime.now().isoformat(),
                        "pid": pid,
                        "process_name": name,
                        "source": "endpoint_agent"
                    }
                    self.store_telemetry(telemetry)
                
                previous_processes = current_processes
                time.sleep(2)
                
            except Exception as e:
                print(f"Process telemetry error: {e}")
                time.sleep(5)
    
    def collect_network_telemetry(self):
        previous_connections = set()
        
        while self.running:
            try:
                current_connections = set()
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'ESTABLISHED':
                        conn_key = (conn.laddr, conn.raddr, conn.pid)
                        current_connections.add(conn_key)
                        
                        if conn_key not in previous_connections:
                            try:
                                proc = psutil.Process(conn.pid) if conn.pid else None
                                proc_name = proc.name() if proc else "unknown"
                            except:
                                proc_name = "unknown"
                            
                            telemetry = {
                                "event_type": "network_connection",
                                "timestamp": datetime.now().isoformat(),
                                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "unknown",
                                "protocol": "TCP",
                                "status": conn.status,
                                "pid": conn.pid,
                                "process_name": proc_name,
                                "source": "network_sensor"
                            }
                            self.store_telemetry(telemetry)
                
                previous_connections = current_connections
                time.sleep(3)
                
            except Exception as e:
                print(f"Network telemetry error: {e}")
                time.sleep(5)
    
    def collect_file_telemetry(self):
        monitored_paths = [
            "C:\\Windows\\System32",
            "C:\\Windows\\Temp",
            "C:\\Users",
            "C:\\Program Files"
        ]
        
        file_hashes = {}
        
        while self.running:
            try:
                for path in monitored_paths:
                    if not os.path.exists(path):
                        continue
                        
                    for root, dirs, files in os.walk(path):
                        for file in files[:10]:
                            file_path = os.path.join(root, file)
                            try:
                                stat = os.stat(file_path)
                                current_hash = hashlib.md5(f"{stat.st_mtime}{stat.st_size}".encode()).hexdigest()
                                
                                if file_path not in file_hashes:
                                    telemetry = {
                                        "event_type": "file_creation",
                                        "timestamp": datetime.now().isoformat(),
                                        "file_path": file_path,
                                        "file_size": stat.st_size,
                                        "file_hash": current_hash,
                                        "source": "file_monitor"
                                    }
                                    self.store_telemetry(telemetry)
                                    file_hashes[file_path] = current_hash
                                    
                                elif file_hashes[file_path] != current_hash:
                                    telemetry = {
                                        "event_type": "file_modification",
                                        "timestamp": datetime.now().isoformat(),
                                        "file_path": file_path,
                                        "file_size": stat.st_size,
                                        "old_hash": file_hashes[file_path],
                                        "new_hash": current_hash,
                                        "source": "file_monitor"
                                    }
                                    self.store_telemetry(telemetry)
                                    file_hashes[file_path] = current_hash
                                    
                            except (OSError, PermissionError):
                                continue
                        break
                
                time.sleep(10)
                
            except Exception as e:
                print(f"File telemetry error: {e}")
                time.sleep(10)
    
    def collect_registry_telemetry(self):
        while self.running:
            try:
                registry_keys = [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services"
                ]
                
                for key in registry_keys:
                    try:
                        result = subprocess.run(
                            f'reg query "{key}"',
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        
                        if result.returncode == 0:
                            telemetry = {
                                "event_type": "registry_access",
                                "timestamp": datetime.now().isoformat(),
                                "registry_key": key,
                                "access_type": "query",
                                "result": "success",
                                "source": "registry_monitor"
                            }
                            self.store_telemetry(telemetry)
                            
                    except subprocess.TimeoutExpired:
                        continue
                
                time.sleep(15)
                
            except Exception as e:
                print(f"Registry telemetry error: {e}")
                time.sleep(15)
    
    def collect_system_telemetry(self):
        while self.running:
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                telemetry = {
                    "event_type": "system_metrics",
                    "timestamp": datetime.now().isoformat(),
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "memory_available": memory.available,
                    "disk_percent": disk.percent,
                    "disk_free": disk.free,
                    "source": "system_monitor"
                }
                self.store_telemetry(telemetry)
                
                time.sleep(30)
                
            except Exception as e:
                print(f"System telemetry error: {e}")
                time.sleep(30)
    
    def store_telemetry(self, telemetry_data):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO telemetry (source, event_type, data, timestamp, processed)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                telemetry_data.get("source", "unknown"),
                telemetry_data.get("event_type", "unknown"),
                json.dumps(telemetry_data),
                telemetry_data.get("timestamp", datetime.now().isoformat()),
                False
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Telemetry storage error: {e}")
    
    def get_telemetry_summary(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT event_type, COUNT(*) as count
            FROM telemetry
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY event_type
            ORDER BY count DESC
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        return results
    
    def analyze_anomalies(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        anomalies = []
        
        cursor.execute('''
            SELECT data FROM telemetry
            WHERE event_type = 'process_creation'
            AND timestamp > datetime('now', '-1 hour')
        ''')
        
        process_events = cursor.fetchall()
        
        suspicious_processes = [
            "powershell.exe", "cmd.exe", "wmic.exe", "reg.exe",
            "net.exe", "sc.exe", "tasklist.exe", "whoami.exe"
        ]
        
        for event in process_events:
            data = json.loads(event[0])
            if any(proc in data.get("process_name", "").lower() for proc in suspicious_processes):
                anomalies.append({
                    "type": "suspicious_process",
                    "process": data.get("process_name"),
                    "command_line": data.get("command_line"),
                    "timestamp": data.get("timestamp"),
                    "severity": "medium"
                })
        
        cursor.execute('''
            SELECT data FROM telemetry
            WHERE event_type = 'network_connection'
            AND timestamp > datetime('now', '-1 hour')
        ''')
        
        network_events = cursor.fetchall()
        
        for event in network_events:
            data = json.loads(event[0])
            remote_addr = data.get("remote_address", "")
            if any(port in remote_addr for port in [":443", ":80", ":22", ":3389"]):
                if "unknown" not in remote_addr:
                    anomalies.append({
                        "type": "external_connection",
                        "remote_address": remote_addr,
                        "process": data.get("process_name"),
                        "timestamp": data.get("timestamp"),
                        "severity": "low"
                    })
        
        conn.close()
        return anomalies
    
    def generate_iocs(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        iocs = {
            "file_hashes": [],
            "ip_addresses": [],
            "domains": [],
            "processes": [],
            "registry_keys": []
        }
        
        cursor.execute('''
            SELECT data FROM telemetry
            WHERE event_type IN ('file_creation', 'file_modification')
            AND timestamp > datetime('now', '-24 hours')
        ''')
        
        file_events = cursor.fetchall()
        for event in file_events:
            data = json.loads(event[0])
            if "file_hash" in data:
                iocs["file_hashes"].append(data["file_hash"])
        
        cursor.execute('''
            SELECT data FROM telemetry
            WHERE event_type = 'network_connection'
            AND timestamp > datetime('now', '-24 hours')
        ''')
        
        network_events = cursor.fetchall()
        for event in network_events:
            data = json.loads(event[0])
            remote_addr = data.get("remote_address", "")
            if ":" in remote_addr:
                ip = remote_addr.split(":")[0]
                if not ip.startswith("127.") and not ip.startswith("192.168."):
                    iocs["ip_addresses"].append(ip)
        
        conn.close()
        return iocs
