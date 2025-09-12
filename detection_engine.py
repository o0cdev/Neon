

import json
import yaml
import re
import sqlite3
from datetime import datetime
import hashlib

class DetectionEngine:
    def __init__(self, db_path="neon_database.db"):
        self.db_path = db_path
        self.sigma_rules = {}
        self.suricata_rules = {}
        self.yara_rules = {}
        self.detection_stats = {}
        
    def load_sigma_rules(self):
        sigma_templates = {
            "process_injection": {
                "title": "Process Injection Detection",
                "description": "Detects process injection techniques",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "Image": ["*\\rundll32.exe", "*\\powershell.exe"],
                        "CommandLine": ["*CreateRemoteThread*", "*WriteProcessMemory*", "*VirtualAllocEx*"]
                    },
                    "condition": "selection"
                },
                "falsepositives": ["Legitimate software updates"],
                "level": "high"
            },
            "credential_dumping": {
                "title": "Credential Dumping Detection",
                "description": "Detects credential dumping attempts",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "Image": ["*\\reg.exe", "*\\vssadmin.exe"],
                        "CommandLine": ["*save*HKLM\\SAM*", "*save*HKLM\\SECURITY*", "*save*HKLM\\SYSTEM*"]
                    },
                    "condition": "selection"
                },
                "falsepositives": ["System backup operations"],
                "level": "critical"
            },
            "powershell_execution": {
                "title": "Suspicious PowerShell Execution",
                "description": "Detects suspicious PowerShell command execution",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "Image": "*\\powershell.exe",
                        "CommandLine": ["*-ExecutionPolicy Bypass*", "*-EncodedCommand*", "*-WindowStyle Hidden*"]
                    },
                    "condition": "selection"
                },
                "falsepositives": ["Administrative scripts"],
                "level": "medium"
            },
            "lateral_movement": {
                "title": "Lateral Movement Detection",
                "description": "Detects lateral movement techniques",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "Image": ["*\\psexec.exe", "*\\wmic.exe", "*\\net.exe"],
                        "CommandLine": ["*\\\\*", "*process call create*", "*use \\\\*"]
                    },
                    "condition": "selection"
                },
                "falsepositives": ["Network administration"],
                "level": "high"
            },
            "defense_evasion": {
                "title": "Defense Evasion Detection",
                "description": "Detects defense evasion techniques",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "Image": ["*\\wevtutil.exe", "*\\del.exe"],
                        "CommandLine": ["*cl System*", "*cl Security*", "*/f /s /q*"]
                    },
                    "condition": "selection"
                },
                "falsepositives": ["System maintenance"],
                "level": "high"
            }
        }
        
        self.sigma_rules = sigma_templates
        return sigma_templates
    
    def sigma_to_suricata(self, sigma_rule):
        rule_name = sigma_rule.get("title", "Unknown Rule")
        description = sigma_rule.get("description", "")
        level = sigma_rule.get("level", "medium")
        
        priority_map = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4
        }
        
        priority = priority_map.get(level, 3)
        
        detection = sigma_rule.get("detection", {})
        selection = detection.get("selection", {})
        
        suricata_content = []
        
        if "Image" in selection:
            images = selection["Image"] if isinstance(selection["Image"], list) else [selection["Image"]]
            for image in images:
                clean_image = image.replace("*\\", "").replace("*", "").replace("\\", "\\\\")
                suricata_content.append(f'content:"{clean_image}"; nocase;')
        
        if "CommandLine" in selection:
            cmdlines = selection["CommandLine"] if isinstance(selection["CommandLine"], list) else [selection["CommandLine"]]
            for cmdline in cmdlines:
                clean_cmd = cmdline.replace("*", "").replace("\\", "\\\\")
                suricata_content.append(f'content:"{clean_cmd}"; nocase;')
        
        content_str = " ".join(suricata_content) if suricata_content else 'content:"suspicious"; nocase;'
        
        suricata_rule = f'''alert tcp any any -> any any (msg:"{rule_name}"; {content_str} sid:1000001; priority:{priority}; rev:1; classtype:trojan-activity;)'''
        
        return suricata_rule
    
    def convert_all_sigma_rules(self):
        self.load_sigma_rules()
        converted_rules = {}
        
        for rule_id, sigma_rule in self.sigma_rules.items():
            suricata_rule = self.sigma_to_suricata(sigma_rule)
            converted_rules[rule_id] = {
                "sigma": sigma_rule,
                "suricata": suricata_rule,
                "conversion_time": datetime.now().isoformat()
            }
            
            self.store_detection_rule("suricata", suricata_rule, rule_id)
        
        return converted_rules
    
    def generate_yara_rules(self):
        yara_templates = {
            "malicious_powershell": '''
rule Malicious_PowerShell_Commands
{
    meta:
        description = "Detects malicious PowerShell command patterns"
        author = "Neon Platform"
        date = "2024-01-01"
        
    strings:
        $cmd1 = "powershell.exe -ExecutionPolicy Bypass" nocase
        $cmd2 = "powershell.exe -EncodedCommand" nocase
        $cmd3 = "powershell.exe -WindowStyle Hidden" nocase
        $cmd4 = "IEX (New-Object" nocase
        $cmd5 = "DownloadString" nocase
        $cmd6 = "Invoke-Expression" nocase
        
    condition:
        any of ($cmd*)
}''',
            "credential_dumping": '''
rule Credential_Dumping_Tools
{
    meta:
        description = "Detects credential dumping tool usage"
        author = "Neon Platform"
        date = "2024-01-01"
        
    strings:
        $reg1 = "reg save HKLM\\SAM" nocase
        $reg2 = "reg save HKLM\\SECURITY" nocase
        $reg3 = "reg save HKLM\\SYSTEM" nocase
        $tool1 = "mimikatz" nocase
        $tool2 = "procdump" nocase
        $tool3 = "lsass" nocase
        
    condition:
        any of ($reg*) or any of ($tool*)
}''',
            "process_injection": '''
rule Process_Injection_Techniques
{
    meta:
        description = "Detects process injection techniques"
        author = "Neon Platform"
        date = "2024-01-01"
        
    strings:
        $api1 = "CreateRemoteThread" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "VirtualAllocEx" nocase
        $api4 = "SetThreadContext" nocase
        $api5 = "QueueUserAPC" nocase
        
    condition:
        2 of ($api*)
}'''
        }
        
        self.yara_rules = yara_templates
        return yara_templates
    
    def analyze_telemetry_with_rules(self, telemetry_data):
        detections = []
        
        for rule_id, sigma_rule in self.sigma_rules.items():
            detection = sigma_rule.get("detection", {})
            selection = detection.get("selection", {})
            
            match_score = 0
            total_criteria = 0
            
            if "Image" in selection:
                total_criteria += 1
                images = selection["Image"] if isinstance(selection["Image"], list) else [selection["Image"]]
                process_name = telemetry_data.get("process_name", "")
                
                for image in images:
                    pattern = image.replace("*", ".*").replace("\\", "\\\\")
                    if re.search(pattern, process_name, re.IGNORECASE):
                        match_score += 1
                        break
            
            if "CommandLine" in selection:
                total_criteria += 1
                cmdlines = selection["CommandLine"] if isinstance(selection["CommandLine"], list) else [selection["CommandLine"]]
                command_line = telemetry_data.get("command_line", "")
                
                for cmdline in cmdlines:
                    pattern = cmdline.replace("*", ".*").replace("\\", "\\\\")
                    if re.search(pattern, command_line, re.IGNORECASE):
                        match_score += 1
                        break
            
            if total_criteria > 0 and match_score > 0:
                confidence = match_score / total_criteria
                
                detection_result = {
                    "rule_id": rule_id,
                    "rule_name": sigma_rule.get("title", "Unknown"),
                    "severity": sigma_rule.get("level", "medium"),
                    "confidence": confidence,
                    "matched_criteria": match_score,
                    "total_criteria": total_criteria,
                    "timestamp": datetime.now().isoformat(),
                    "telemetry_source": telemetry_data.get("source", "unknown")
                }
                
                detections.append(detection_result)
                self.update_detection_stats(rule_id, detection_result)
        
        return detections
    
    def store_detection_rule(self, rule_type, rule_content, rule_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        effectiveness_score = self.calculate_rule_effectiveness(rule_id)
        false_positive_rate = self.calculate_false_positive_rate(rule_id)
        
        cursor.execute('''
            INSERT INTO detections (rule_type, rule_content, effectiveness_score, false_positive_rate, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (rule_type, rule_content, effectiveness_score, false_positive_rate, datetime.now()))
        
        conn.commit()
        conn.close()
    
    def calculate_rule_effectiveness(self, rule_id):
        if rule_id in self.detection_stats:
            stats = self.detection_stats[rule_id]
            total_events = stats.get("total_events", 1)
            true_positives = stats.get("true_positives", 0)
            return true_positives / total_events if total_events > 0 else 0.5
        return 0.5
    
    def calculate_false_positive_rate(self, rule_id):
        if rule_id in self.detection_stats:
            stats = self.detection_stats[rule_id]
            total_detections = stats.get("total_detections", 1)
            false_positives = stats.get("false_positives", 0)
            return false_positives / total_detections if total_detections > 0 else 0.1
        return 0.1
    
    def update_detection_stats(self, rule_id, detection_result):
        if rule_id not in self.detection_stats:
            self.detection_stats[rule_id] = {
                "total_detections": 0,
                "true_positives": 0,
                "false_positives": 0,
                "total_events": 0
            }
        
        self.detection_stats[rule_id]["total_detections"] += 1
        self.detection_stats[rule_id]["total_events"] += 1
        
        if detection_result["confidence"] > 0.7:
            self.detection_stats[rule_id]["true_positives"] += 1
        elif detection_result["confidence"] < 0.3:
            self.detection_stats[rule_id]["false_positives"] += 1
    
    def optimize_rules(self):
        optimized_rules = {}
        
        for rule_id, sigma_rule in self.sigma_rules.items():
            if rule_id in self.detection_stats:
                stats = self.detection_stats[rule_id]
                effectiveness = self.calculate_rule_effectiveness(rule_id)
                fp_rate = self.calculate_false_positive_rate(rule_id)
                
                if effectiveness < 0.3 or fp_rate > 0.5:
                    optimized_rule = self.enhance_rule_specificity(sigma_rule)
                    optimized_rules[rule_id] = optimized_rule
                elif effectiveness > 0.8 and fp_rate < 0.1:
                    optimized_rule = self.broaden_rule_coverage(sigma_rule)
                    optimized_rules[rule_id] = optimized_rule
                else:
                    optimized_rules[rule_id] = sigma_rule
            else:
                optimized_rules[rule_id] = sigma_rule
        
        return optimized_rules
    
    def enhance_rule_specificity(self, sigma_rule):
        enhanced_rule = sigma_rule.copy()
        detection = enhanced_rule.get("detection", {})
        selection = detection.get("selection", {})
        
        if "CommandLine" in selection:
            cmdlines = selection["CommandLine"]
            if isinstance(cmdlines, list):
                enhanced_cmdlines = []
                for cmd in cmdlines:
                    if not cmd.startswith("*") or not cmd.endswith("*"):
                        enhanced_cmd = f"*{cmd.strip('*')}*"
                        enhanced_cmdlines.append(enhanced_cmd)
                    else:
                        enhanced_cmdlines.append(cmd)
                selection["CommandLine"] = enhanced_cmdlines
        
        enhanced_rule["detection"]["selection"] = selection
        return enhanced_rule
    
    def broaden_rule_coverage(self, sigma_rule):
        broadened_rule = sigma_rule.copy()
        detection = broadened_rule.get("detection", {})
        selection = detection.get("selection", {})
        
        if "Image" in selection:
            images = selection["Image"]
            if isinstance(images, list):
                broadened_images = []
                for img in images:
                    broadened_images.append(img)
                    if "powershell" in img.lower():
                        broadened_images.append("*\\pwsh.exe")
                    elif "cmd" in img.lower():
                        broadened_images.append("*\\cmd.exe")
                selection["Image"] = broadened_images
        
        broadened_rule["detection"]["selection"] = selection
        return broadened_rule
    
    def generate_detection_report(self):
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_rules": len(self.sigma_rules),
            "rule_statistics": {},
            "top_performing_rules": [],
            "rules_needing_optimization": []
        }
        
        for rule_id, stats in self.detection_stats.items():
            effectiveness = self.calculate_rule_effectiveness(rule_id)
            fp_rate = self.calculate_false_positive_rate(rule_id)
            
            rule_stat = {
                "rule_id": rule_id,
                "effectiveness": effectiveness,
                "false_positive_rate": fp_rate,
                "total_detections": stats["total_detections"],
                "performance_score": effectiveness * (1 - fp_rate)
            }
            
            report["rule_statistics"][rule_id] = rule_stat
            
            if rule_stat["performance_score"] > 0.8:
                report["top_performing_rules"].append(rule_stat)
            elif rule_stat["performance_score"] < 0.3:
                report["rules_needing_optimization"].append(rule_stat)
        
        report["top_performing_rules"].sort(key=lambda x: x["performance_score"], reverse=True)
        report["rules_needing_optimization"].sort(key=lambda x: x["performance_score"])
        
        return report
