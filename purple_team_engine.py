
import json
import threading
import time
import sqlite3
from datetime import datetime, timedelta
import random
import subprocess

class PurpleTeamEngine:
    def __init__(self, db_path="neon_database.db"):
        self.db_path = db_path
        self.active_exercises = {}
        self.red_team_scenarios = {}
        self.blue_team_responses = {}
        self.exercise_metrics = {}
        
    def create_attack_scenario(self, scenario_name, techniques, duration_minutes=60):
        scenario_id = f"scenario_{int(time.time())}"
        
        scenario = {
            "id": scenario_id,
            "name": scenario_name,
            "techniques": techniques,
            "duration": duration_minutes,
            "status": "created",
            "created_at": datetime.now().isoformat(),
            "red_team_actions": [],
            "blue_team_detections": [],
            "metrics": {
                "detection_rate": 0.0,
                "response_time": 0.0,
                "false_positives": 0,
                "true_positives": 0
            }
        }
        
        self.red_team_scenarios[scenario_id] = scenario
        return scenario_id
    
    def execute_purple_team_exercise(self, scenario_id):
        if scenario_id not in self.red_team_scenarios:
            return {"error": "Scenario not found"}
        
        scenario = self.red_team_scenarios[scenario_id]
        scenario["status"] = "running"
        scenario["start_time"] = datetime.now().isoformat()
        
        self.active_exercises[scenario_id] = scenario
        
        red_thread = threading.Thread(
            target=self.execute_red_team_actions,
            args=(scenario_id,),
            daemon=True
        )
        
        blue_thread = threading.Thread(
            target=self.monitor_blue_team_response,
            args=(scenario_id,),
            daemon=True
        )
        
        red_thread.start()
        blue_thread.start()
        
        return {"status": "exercise_started", "scenario_id": scenario_id}
    
    def execute_red_team_actions(self, scenario_id):
        scenario = self.active_exercises[scenario_id]
        techniques = scenario["techniques"]
        duration = scenario["duration"]
        
        start_time = time.time()
        end_time = start_time + (duration * 60)
        
        action_interval = (duration * 60) / len(techniques)
        
        for i, technique in enumerate(techniques):
            if time.time() > end_time:
                break
            
            action_result = self.simulate_attack_technique(technique)
            
            red_action = {
                "technique": technique,
                "timestamp": datetime.now().isoformat(),
                "result": action_result,
                "detection_expected": True,
                "stealth_level": random.choice(["low", "medium", "high"])
            }
            
            scenario["red_team_actions"].append(red_action)
            
            self.log_red_team_action(scenario_id, red_action)
            
            time.sleep(action_interval)
        
        scenario["status"] = "completed"
        scenario["end_time"] = datetime.now().isoformat()
        
        self.calculate_exercise_metrics(scenario_id)
    
    def simulate_attack_technique(self, technique):
        technique_simulations = {
            "T1055": {
                "name": "Process Injection",
                "actions": [
                    "Enumerate target processes",
                    "Allocate memory in target process",
                    "Write shellcode to allocated memory",
                    "Create remote thread"
                ],
                "artifacts": [
                    "Suspicious API calls detected",
                    "Memory allocation in foreign process",
                    "Cross-process thread creation"
                ]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "actions": [
                    "Execute PowerShell with bypass policy",
                    "Run encoded commands",
                    "Download and execute remote script"
                ],
                "artifacts": [
                    "PowerShell execution with suspicious parameters",
                    "Base64 encoded command execution",
                    "Network connection from PowerShell"
                ]
            },
            "T1003": {
                "name": "OS Credential Dumping",
                "actions": [
                    "Access LSASS process memory",
                    "Extract SAM database",
                    "Dump cached credentials"
                ],
                "artifacts": [
                    "LSASS process access",
                    "Registry SAM hive access",
                    "Credential extraction tools"
                ]
            },
            "T1021": {
                "name": "Remote Services",
                "actions": [
                    "Establish remote connection",
                    "Execute commands on remote system",
                    "Transfer files laterally"
                ],
                "artifacts": [
                    "Remote login events",
                    "Lateral movement indicators",
                    "File transfer activities"
                ]
            },
            "T1070": {
                "name": "Indicator Removal",
                "actions": [
                    "Clear event logs",
                    "Delete temporary files",
                    "Modify timestamps"
                ],
                "artifacts": [
                    "Event log clearing",
                    "File deletion patterns",
                    "Timestamp manipulation"
                ]
            }
        }
        
        if technique in technique_simulations:
            sim = technique_simulations[technique]
            return {
                "technique_name": sim["name"],
                "actions_performed": sim["actions"],
                "artifacts_generated": sim["artifacts"],
                "success": True,
                "stealth_rating": random.uniform(0.3, 0.9)
            }
        else:
            return {
                "technique_name": "Unknown Technique",
                "actions_performed": ["Generic malicious activity"],
                "artifacts_generated": ["Suspicious behavior detected"],
                "success": False,
                "stealth_rating": 0.1
            }
    
    def monitor_blue_team_response(self, scenario_id):
        scenario = self.active_exercises[scenario_id]
        duration = scenario["duration"]
        
        start_time = time.time()
        end_time = start_time + (duration * 60)
        
        detection_rules = [
            {
                "name": "Process Injection Detection",
                "techniques": ["T1055"],
                "detection_probability": 0.85,
                "response_time": random.uniform(30, 180)
            },
            {
                "name": "PowerShell Execution Detection",
                "techniques": ["T1059"],
                "detection_probability": 0.75,
                "response_time": random.uniform(15, 120)
            },
            {
                "name": "Credential Dumping Detection",
                "techniques": ["T1003"],
                "detection_probability": 0.90,
                "response_time": random.uniform(45, 300)
            },
            {
                "name": "Lateral Movement Detection",
                "techniques": ["T1021"],
                "detection_probability": 0.70,
                "response_time": random.uniform(60, 240)
            },
            {
                "name": "Log Clearing Detection",
                "techniques": ["T1070"],
                "detection_probability": 0.80,
                "response_time": random.uniform(20, 150)
            }
        ]
        
        while time.time() < end_time and scenario["status"] == "running":
            for red_action in scenario["red_team_actions"]:
                technique = red_action["technique"]
                
                for rule in detection_rules:
                    if technique in rule["techniques"]:
                        detection_chance = random.random()
                        
                        if detection_chance < rule["detection_probability"]:
                            detection = {
                                "rule_name": rule["name"],
                                "technique_detected": technique,
                                "timestamp": datetime.now().isoformat(),
                                "confidence": random.uniform(0.6, 0.95),
                                "response_time": rule["response_time"],
                                "analyst_action": self.generate_analyst_response(technique)
                            }
                            
                            scenario["blue_team_detections"].append(detection)
                            scenario["metrics"]["true_positives"] += 1
                            
                            self.log_blue_team_detection(scenario_id, detection)
                        else:
                            scenario["metrics"]["false_positives"] += 1
            
            time.sleep(30)
    
    def generate_analyst_response(self, technique):
        response_templates = {
            "T1055": [
                "Isolated suspicious process",
                "Collected memory dump for analysis",
                "Blocked process injection attempt",
                "Escalated to incident response team"
            ],
            "T1059": [
                "Blocked PowerShell execution",
                "Analyzed command line parameters",
                "Quarantined suspicious script",
                "Updated PowerShell logging policy"
            ],
            "T1003": [
                "Protected LSASS process",
                "Reset compromised credentials",
                "Implemented additional monitoring",
                "Initiated forensic investigation"
            ],
            "T1021": [
                "Blocked lateral movement attempt",
                "Isolated affected systems",
                "Reviewed network connections",
                "Updated firewall rules"
            ],
            "T1070": [
                "Restored event logs from backup",
                "Implemented log forwarding",
                "Enhanced log monitoring",
                "Documented evidence tampering"
            ]
        }
        
        if technique in response_templates:
            return random.choice(response_templates[technique])
        else:
            return "Generic incident response action taken"
    
    def calculate_exercise_metrics(self, scenario_id):
        scenario = self.active_exercises[scenario_id]
        
        total_techniques = len(scenario["techniques"])
        detected_techniques = len(scenario["blue_team_detections"])
        
        detection_rate = detected_techniques / total_techniques if total_techniques > 0 else 0
        
        response_times = [d["response_time"] for d in scenario["blue_team_detections"]]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        scenario["metrics"]["detection_rate"] = detection_rate
        scenario["metrics"]["response_time"] = avg_response_time
        
        self.exercise_metrics[scenario_id] = scenario["metrics"]
        
        self.store_exercise_results(scenario_id)
    
    def log_red_team_action(self, scenario_id, action):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO telemetry (source, event_type, data, timestamp, processed)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            "red_team",
            "attack_simulation",
            json.dumps(action),
            action["timestamp"],
            False
        ))
        
        conn.commit()
        conn.close()
    
    def log_blue_team_detection(self, scenario_id, detection):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO telemetry (source, event_type, data, timestamp, processed)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            "blue_team",
            "detection_alert",
            json.dumps(detection),
            detection["timestamp"],
            False
        ))
        
        conn.commit()
        conn.close()
    
    def store_exercise_results(self, scenario_id):
        scenario = self.active_exercises[scenario_id]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scenarios (technique_id, name, description, status, timestamp, telemetry_data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            scenario_id,
            scenario["name"],
            f"Purple team exercise with {len(scenario['techniques'])} techniques",
            scenario["status"],
            scenario["created_at"],
            json.dumps(scenario)
        ))
        
        conn.commit()
        conn.close()
    
    def generate_exercise_report(self, scenario_id):
        if scenario_id not in self.active_exercises:
            return {"error": "Exercise not found"}
        
        scenario = self.active_exercises[scenario_id]
        metrics = scenario["metrics"]
        
        report = {
            "exercise_id": scenario_id,
            "exercise_name": scenario["name"],
            "duration": scenario["duration"],
            "status": scenario["status"],
            "summary": {
                "total_techniques": len(scenario["techniques"]),
                "techniques_detected": len(scenario["blue_team_detections"]),
                "detection_rate": f"{metrics['detection_rate']:.2%}",
                "average_response_time": f"{metrics['response_time']:.1f} seconds",
                "true_positives": metrics["true_positives"],
                "false_positives": metrics["false_positives"]
            },
            "red_team_actions": scenario["red_team_actions"],
            "blue_team_detections": scenario["blue_team_detections"],
            "recommendations": self.generate_recommendations(scenario),
            "generated_at": datetime.now().isoformat()
        }
        
        return report
    
    def generate_recommendations(self, scenario):
        recommendations = []
        metrics = scenario["metrics"]
        
        if metrics["detection_rate"] < 0.7:
            recommendations.append({
                "category": "Detection Coverage",
                "priority": "High",
                "recommendation": "Improve detection rules for undetected techniques",
                "details": "Consider implementing additional monitoring for missed attack vectors"
            })
        
        if metrics["response_time"] > 300:
            recommendations.append({
                "category": "Response Time",
                "priority": "Medium",
                "recommendation": "Optimize incident response procedures",
                "details": "Review and streamline detection-to-response workflows"
            })
        
        if metrics["false_positives"] > metrics["true_positives"]:
            recommendations.append({
                "category": "Rule Tuning",
                "priority": "High",
                "recommendation": "Reduce false positive rate",
                "details": "Fine-tune detection rules to minimize false alerts"
            })
        
        if len(scenario["blue_team_detections"]) == 0:
            recommendations.append({
                "category": "Detection Capability",
                "priority": "Critical",
                "recommendation": "Implement basic detection capabilities",
                "details": "No detections were triggered during the exercise"
            })
        
        return recommendations
    
    def get_exercise_history(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT technique_id, name, timestamp, telemetry_data
            FROM scenarios
            WHERE technique_id LIKE 'scenario_%'
            ORDER BY timestamp DESC
            LIMIT 20
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        exercises = []
        for result in results:
            try:
                scenario_data = json.loads(result[3])
                exercise_summary = {
                    "id": result[0],
                    "name": result[1],
                    "timestamp": result[2],
                    "status": scenario_data.get("status", "unknown"),
                    "detection_rate": scenario_data.get("metrics", {}).get("detection_rate", 0),
                    "techniques_count": len(scenario_data.get("techniques", []))
                }
                exercises.append(exercise_summary)
            except:
                continue
        
        return exercises
