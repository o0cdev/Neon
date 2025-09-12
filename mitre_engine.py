
import json
import requests
import subprocess
import threading
import time
import os
from datetime import datetime
import sqlite3

class MitreAttackEngine:
    def __init__(self, db_path="neon_database.db"):
        self.db_path = db_path
        self.techniques = self.load_mitre_techniques()
        
    def load_mitre_techniques(self):
        techniques = {
            "T1055": {
                "name": "Process Injection",
                "tactics": ["Defense Evasion", "Privilege Escalation"],
                "platforms": ["Windows", "macOS", "Linux"],
                "commands": [
                    "powershell.exe -Command \"Get-Process | Where-Object {$_.ProcessName -eq 'explorer'} | Select-Object Id\"",
                    "powershell.exe -Command \"$proc = Get-Process notepad; $proc.Modules\"",
                    "rundll32.exe kernel32.dll,CreateRemoteThread"
                ]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactics": ["Execution"],
                "platforms": ["Windows", "macOS", "Linux"],
                "commands": [
                    "powershell.exe -ExecutionPolicy Bypass -Command \"Get-ComputerInfo\"",
                    "cmd.exe /c \"systeminfo\"",
                    "wmic computersystem get model,name,manufacturer,systemtype"
                ]
            },
            "T1003": {
                "name": "OS Credential Dumping",
                "tactics": ["Credential Access"],
                "platforms": ["Windows", "macOS", "Linux"],
                "commands": [
                    "reg save HKLM\\SAM sam.save",
                    "reg save HKLM\\SECURITY security.save",
                    "reg save HKLM\\SYSTEM system.save"
                ]
            },
            "T1021": {
                "name": "Remote Services",
                "tactics": ["Lateral Movement"],
                "platforms": ["Windows", "macOS", "Linux"],
                "commands": [
                    "net use \\\\target\\c$ /user:domain\\username password",
                    "psexec \\\\target -u domain\\username -p password cmd",
                    "wmic /node:target process call create \"cmd.exe\""
                ]
            },
            "T1070": {
                "name": "Indicator Removal on Host",
                "tactics": ["Defense Evasion"],
                "platforms": ["Windows", "macOS", "Linux"],
                "commands": [
                    "wevtutil cl System",
                    "wevtutil cl Security",
                    "del /f /s /q C:\\Windows\\Temp\\*"
                ]
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "tactics": ["Discovery"],
                "platforms": ["Windows", "macOS", "Linux"],
                "commands": [
                    "dir C:\\ /s /b",
                    "tree C:\\ /f",
                    "forfiles /p C:\\ /s /m *.* /c \"cmd /c echo @path\""
                ]
            },
            "T1057": {
                "name": "Process Discovery",
                "tactics": ["Discovery"],
                "platforms": ["Windows", "macOS", "Linux"],
                "commands": [
                    "tasklist /v",
                    "wmic process list full",
                    "Get-Process | Format-Table -AutoSize"
                ]
            },
            "T1082": {
                "name": "System Information Discovery",
                "tactics": ["Discovery"],
                "platforms": ["Windows", "macOS", "Linux"],
                "commands": [
                    "systeminfo",
                    "wmic computersystem list full",
                    "Get-ComputerInfo | Format-List"
                ]
            },
            "T1016": {
                "name": "System Network Configuration Discovery",
                "tactics": ["Discovery"],
                "platforms": ["Windows", "macOS", "Linux"],
                "commands": [
                    "ipconfig /all",
                    "netsh interface show interface",
                    "route print"
                ]
            },
            "T1049": {
                "name": "System Network Connections Discovery",
                "tactics": ["Discovery"],
                "platforms": ["Windows", "macOS", "Linux"],
                "commands": [
                    "netstat -ano",
                    "netstat -rn",
                    "arp -a"
                ]
            }
        }
        return techniques
    
    def execute_technique(self, technique_id, safe_mode=True):
        if technique_id not in self.techniques:
            return {"error": "Technique not found"}
        
        technique = self.techniques[technique_id]
        results = {
            "technique_id": technique_id,
            "name": technique["name"],
            "timestamp": datetime.now().isoformat(),
            "commands_executed": [],
            "telemetry": [],
            "detections": []
        }
        
        if safe_mode:
            results["commands_executed"] = technique["commands"]
            results["telemetry"] = self.generate_mock_telemetry(technique_id)
            results["detections"] = self.generate_mock_detections(technique_id)
        else:
            for cmd in technique["commands"]:
                try:
                    if cmd.startswith("powershell"):
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                        results["commands_executed"].append({
                            "command": cmd,
                            "return_code": result.returncode,
                            "stdout": result.stdout[:1000],
                            "stderr": result.stderr[:1000]
                        })
                except Exception as e:
                    results["commands_executed"].append({
                        "command": cmd,
                        "error": str(e)
                    })
        
        self.store_execution_results(results)
        return results
    
    def generate_mock_telemetry(self, technique_id):
        telemetry_patterns = {
            "T1055": [
                {"event_id": 4688, "process_name": "powershell.exe", "command_line": "Get-Process explorer"},
                {"event_id": 4689, "process_name": "rundll32.exe", "command_line": "kernel32.dll,CreateRemoteThread"},
                {"event_id": 10, "source_process": "powershell.exe", "target_process": "explorer.exe"}
            ],
            "T1059": [
                {"event_id": 4688, "process_name": "powershell.exe", "command_line": "Get-ComputerInfo"},
                {"event_id": 4688, "process_name": "cmd.exe", "command_line": "systeminfo"},
                {"event_id": 4688, "process_name": "wmic.exe", "command_line": "computersystem get"}
            ],
            "T1003": [
                {"event_id": 4688, "process_name": "reg.exe", "command_line": "save HKLM\\SAM"},
                {"event_id": 4656, "object_name": "\\Registry\\Machine\\SAM", "access_mask": "0x20019"},
                {"event_id": 4663, "object_name": "\\Registry\\Machine\\SECURITY", "access_mask": "0x1"}
            ]
        }
        
        return telemetry_patterns.get(technique_id, [
            {"event_id": 4688, "process_name": "unknown.exe", "command_line": "generic_command"}
        ])
    
    def generate_mock_detections(self, technique_id):
        detection_patterns = {
            "T1055": [
                {"rule_name": "Process Injection Detected", "severity": "High", "confidence": 0.85},
                {"rule_name": "Suspicious PowerShell Activity", "severity": "Medium", "confidence": 0.72}
            ],
            "T1059": [
                {"rule_name": "Command Line Execution", "severity": "Medium", "confidence": 0.68},
                {"rule_name": "System Information Gathering", "severity": "Low", "confidence": 0.55}
            ],
            "T1003": [
                {"rule_name": "Credential Dumping Attempt", "severity": "Critical", "confidence": 0.95},
                {"rule_name": "Registry SAM Access", "severity": "High", "confidence": 0.88}
            ]
        }
        
        return detection_patterns.get(technique_id, [
            {"rule_name": "Generic Suspicious Activity", "severity": "Medium", "confidence": 0.60}
        ])
    
    def store_execution_results(self, results):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scenarios (technique_id, name, description, status, timestamp, telemetry_data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            results["technique_id"],
            results["name"],
            f"Executed {len(results['commands_executed'])} commands",
            "completed",
            results["timestamp"],
            json.dumps(results)
        ))
        
        conn.commit()
        conn.close()
    
    def get_execution_history(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scenarios ORDER BY timestamp DESC LIMIT 50
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        return results
    
    def generate_attack_chain(self, tactics):
        chain = []
        tactic_mapping = {
            "Initial Access": ["T1566", "T1190", "T1078"],
            "Execution": ["T1059", "T1053", "T1047"],
            "Persistence": ["T1547", "T1053", "T1136"],
            "Privilege Escalation": ["T1055", "T1068", "T1134"],
            "Defense Evasion": ["T1070", "T1027", "T1055"],
            "Credential Access": ["T1003", "T1110", "T1558"],
            "Discovery": ["T1083", "T1057", "T1082"],
            "Lateral Movement": ["T1021", "T1076", "T1105"],
            "Collection": ["T1005", "T1039", "T1113"],
            "Exfiltration": ["T1041", "T1048", "T1567"]
        }
        
        for tactic in tactics:
            if tactic in tactic_mapping:
                techniques = tactic_mapping[tactic]
                for tech in techniques:
                    if tech in self.techniques:
                        chain.append({
                            "tactic": tactic,
                            "technique": tech,
                            "name": self.techniques[tech]["name"]
                        })
                        break
        
        return chain
