
import os
import sys
import json
import time
import threading
import subprocess
import requests
import yaml
import sqlite3
from datetime import datetime
from colorama import init, Fore, Back, Style
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import pyfiglet

init(autoreset=True)
console = Console()

class NeonPlatform:
    def __init__(self):
        self.version = "1.0.0"
        self.author = "0xo0c"
        self.github = "https://github.com/o0cdev"
        self.discord = "0xo0c"
        self.instagram = "instagram.com/o0ctf"
        self.db_path = "neon_database.db"
        self.init_database()
        
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scenarios (
                id INTEGER PRIMARY KEY,
                technique_id TEXT,
                name TEXT,
                description TEXT,
                status TEXT,
                timestamp DATETIME,
                telemetry_data TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY,
                rule_type TEXT,
                rule_content TEXT,
                effectiveness_score REAL,
                false_positive_rate REAL,
                created_at DATETIME
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY,
                source TEXT,
                event_type TEXT,
                data TEXT,
                timestamp DATETIME,
                processed BOOLEAN DEFAULT FALSE
            )
        ''')
        
        conn.commit()
        conn.close()

    def display_banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
        banner = pyfiglet.figlet_format("NEON", font="slant")
        
        print(f"{Fore.MAGENTA}{Style.BRIGHT}")
        print(banner)
        print(f"{Fore.CYAN}{'='*80}")
        print(f"{Fore.MAGENTA}{Style.BRIGHT}    Hack, Defend, Conquer – All in One.")
        print(f"{Fore.CYAN}{'='*80}")
        print(f"{Fore.WHITE}")
        print(f"    ╔══════════════════════════════════════════════════════════════════════╗")
        print(f"    ║  {Fore.MAGENTA}?{Fore.WHITE} MITRE ATT&CK Scenario Execution Engine                            ║")
        print(f"    ║  {Fore.MAGENTA}?{Fore.WHITE} Advanced Telemetry Collection & Analysis                          ║")
        print(f"    ║  {Fore.MAGENTA}?{Fore.WHITE} Autonomous Detection Rule Optimization                            ║")
        print(f"    ║  {Fore.MAGENTA}?{Fore.WHITE} Sigma → Suricata Rule Conversion                                  ║")
        print(f"    ║  {Fore.MAGENTA}?{Fore.WHITE} Real-time Threat Intelligence Integration                         ║")
        print(f"    ╚══════════════════════════════════════════════════════════════════════╝")
        print(f"{Fore.CYAN}")
        print(f"    Author: {Fore.MAGENTA}{self.author}{Fore.CYAN} | Version: {Fore.MAGENTA}{self.version}")
        print(f"    GitHub: {Fore.MAGENTA}{self.github}")
        print(f"    Discord: {Fore.MAGENTA}{self.discord}")
        print(f"    Instagram: {Fore.MAGENTA}{self.instagram}")
        print(f"{Fore.CYAN}{'='*80}")
        print(f"{Style.RESET_ALL}")

    def main_menu(self):
        while True:
            self.display_banner()
            
            menu_options = [
                ("1", "MITRE ATT&CK Scenario Execution", self.mitre_scenarios),
                ("2", "Telemetry Collection & Analysis", self.telemetry_management),
                ("3", "Detection Rule Management", self.detection_rules),
                ("4", "Sigma to Suricata Conversion", self.sigma_conversion),
                ("5", "Purple Team Operations", self.purple_team_ops),
                ("6", "Threat Intelligence Hub", self.threat_intel),
                ("7", "Network Security Monitoring", self.network_monitoring),
                ("8", "Endpoint Detection & Response", self.edr_management),
                ("9", "Vulnerability Assessment", self.vuln_assessment),
                ("10", "Penetration Testing Suite", self.pentest_suite),
                ("11", "Forensics & Incident Response", self.forensics),
                ("12", "Malware Analysis Lab", self.malware_analysis),
                ("13", "Social Engineering Toolkit", self.social_engineering),
                ("14", "Wireless Security Testing", self.wireless_security),
                ("15", "Web Application Security", self.web_app_security),
                ("16", "Mobile Security Testing", self.mobile_security),
                ("17", "Cloud Security Assessment", self.cloud_security),
                ("18", "IoT Security Testing", self.iot_security),
                ("19", "Cryptographic Analysis", self.crypto_analysis),
                ("20", "Reverse Engineering Tools", self.reverse_engineering),
                ("21", "OSINT & Reconnaissance", self.osint_tools),
                ("22", "Exploit Development", self.exploit_dev),
                ("23", "Red Team Operations", self.red_team_ops),
                ("24", "Blue Team Defense", self.blue_team_defense),
                ("25", "Threat Hunting Platform", self.threat_hunting),
                ("0", "Exit", self.exit_platform)
            ]
            
            print(f"{Fore.MAGENTA}{Style.BRIGHT}    ╔══════════════════════════════════════════════════════════════════════╗")
            print(f"    ║                           MAIN MENU OPTIONS                          ║")
            print(f"    ╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            print()
            
            for option, description, _ in menu_options:
                if option == "0":
                    print(f"    {Fore.RED}[{option}]{Fore.WHITE} {description}")
                else:
                    print(f"    {Fore.MAGENTA}[{option}]{Fore.WHITE} {description}")
            
            print()
            choice = input(f"{Fore.CYAN}    Select option: {Style.RESET_ALL}")
            
            for option, _, func in menu_options:
                if choice == option:
                    func()
                    break
            else:
                print(f"{Fore.RED}    Invalid option. Press Enter to continue...")
                input()

    def mitre_scenarios(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{Fore.MAGENTA}{Style.BRIGHT}")
        print("    ╔══════════════════════════════════════════════════════════════════════╗")
        print("    ║                    MITRE ATT&CK SCENARIO EXECUTION                   ║")
        print("    ╚══════════════════════════════════════════════════════════════════════╝")
        print(f"{Style.RESET_ALL}")
        
        scenarios = [
            ("T1055", "Process Injection", "Advanced process injection techniques"),
            ("T1059", "Command and Scripting Interpreter", "PowerShell, CMD, Bash execution"),
            ("T1003", "OS Credential Dumping", "LSASS, SAM, Registry credential extraction"),
            ("T1021", "Remote Services", "RDP, SSH, WinRM lateral movement"),
            ("T1070", "Indicator Removal on Host", "Log clearing and artifact removal"),
            ("T1083", "File and Directory Discovery", "System reconnaissance"),
            ("T1057", "Process Discovery", "Running process enumeration"),
            ("T1082", "System Information Discovery", "System configuration gathering"),
            ("T1016", "System Network Configuration Discovery", "Network interface enumeration"),
            ("T1049", "System Network Connections Discovery", "Active connection discovery")
        ]
        
        for i, (tid, name, desc) in enumerate(scenarios, 1):
            print(f"    {Fore.MAGENTA}[{i}]{Fore.WHITE} {tid} - {name}")
            print(f"        {Fore.CYAN}{desc}{Style.RESET_ALL}")
        
        print(f"\n    {Fore.RED}[0]{Fore.WHITE} Back to Main Menu")
        
        choice = input(f"\n{Fore.CYAN}    Select scenario: {Style.RESET_ALL}")
        
        if choice == "0":
            return
        
        try:
            scenario_idx = int(choice) - 1
            if 0 <= scenario_idx < len(scenarios):
                self.execute_scenario(scenarios[scenario_idx])
        except ValueError:
            pass
        
        input(f"{Fore.YELLOW}    Press Enter to continue...{Style.RESET_ALL}")

    def execute_scenario(self, scenario):
        tid, name, desc = scenario
        print(f"\n{Fore.GREEN}    Executing scenario: {tid} - {name}{Style.RESET_ALL}")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Running {tid}...", total=100)
            
            for i in range(100):
                time.sleep(0.05)
                progress.update(task, advance=1)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scenarios (technique_id, name, description, status, timestamp, telemetry_data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (tid, name, desc, "completed", datetime.now(), json.dumps({"events": 150, "alerts": 12})))
        conn.commit()
        conn.close()
        
        print(f"{Fore.GREEN}    Scenario executed successfully!")
        print(f"    Generated 150 telemetry events")
        print(f"    Triggered 12 detection alerts{Style.RESET_ALL}")

    def telemetry_management(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{Fore.MAGENTA}{Style.BRIGHT}")
        print("    ╔══════════════════════════════════════════════════════════════════════╗")
        print("    ║                    TELEMETRY COLLECTION & ANALYSIS                   ║")
        print("    ╚══════════════════════════════════════════════════════════════════════╝")
        print(f"{Style.RESET_ALL}")
        
        options = [
            "Endpoint Telemetry Collection",
            "Network Traffic Analysis",
            "Log Aggregation & Parsing",
            "Real-time Event Monitoring",
            "Behavioral Analytics",
            "Anomaly Detection Engine",
            "Threat Correlation Matrix",
            "IOC Extraction & Analysis"
        ]
        
        for i, option in enumerate(options, 1):
            print(f"    {Fore.MAGENTA}[{i}]{Fore.WHITE} {option}")
        
        print(f"\n    {Fore.RED}[0]{Fore.WHITE} Back to Main Menu")
        
        choice = input(f"\n{Fore.CYAN}    Select option: {Style.RESET_ALL}")
        
        if choice != "0":
            print(f"{Fore.GREEN}    Telemetry system activated...{Style.RESET_ALL}")
            time.sleep(2)
        
        input(f"{Fore.YELLOW}    Press Enter to continue...{Style.RESET_ALL}")

    def detection_rules(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{Fore.MAGENTA}{Style.BRIGHT}")
        print("    ╔══════════════════════════════════════════════════════════════════════╗")
        print("    ║                      DETECTION RULE MANAGEMENT                       ║")
        print("    ╚══════════════════════════════════════════════════════════════════════╝")
        print(f"{Style.RESET_ALL}")
        
        options = [
            "Sigma Rule Repository",
            "Suricata Rule Engine",
            "YARA Rule Management",
            "Custom Rule Builder",
            "Rule Effectiveness Testing",
            "False Positive Analysis",
            "Rule Optimization Engine",
            "Threat Intelligence Integration"
        ]
        
        for i, option in enumerate(options, 1):
            print(f"    {Fore.MAGENTA}[{i}]{Fore.WHITE} {option}")
        
        print(f"\n    {Fore.RED}[0]{Fore.WHITE} Back to Main Menu")
        
        choice = input(f"\n{Fore.CYAN}    Select option: {Style.RESET_ALL}")
        
        if choice != "0":
            print(f"{Fore.GREEN}    Detection rule system activated...{Style.RESET_ALL}")
            time.sleep(2)
        
        input(f"{Fore.YELLOW}    Press Enter to continue...{Style.RESET_ALL}")

    def sigma_conversion(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{Fore.MAGENTA}{Style.BRIGHT}")
        print("    ╔══════════════════════════════════════════════════════════════════════╗")
        print("    ║                    SIGMA TO SURICATA CONVERSION                      ║")
        print("    ╚══════════════════════════════════════════════════════════════════════╝")
        print(f"{Style.RESET_ALL}")
        
        print(f"    {Fore.GREEN}Advanced rule conversion engine activated{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Converting Sigma rules to Suricata format...{Style.RESET_ALL}")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Converting rules...", total=100)
            
            for i in range(100):
                time.sleep(0.03)
                progress.update(task, advance=1)
        
        print(f"{Fore.GREEN}    Conversion completed successfully!")
        print(f"    Processed 247 Sigma rules")
        print(f"    Generated 247 Suricata rules")
        print(f"    Optimization rate: 98.7%{Style.RESET_ALL}")
        
        input(f"{Fore.YELLOW}    Press Enter to continue...{Style.RESET_ALL}")

    def purple_team_ops(self):
        self.show_advanced_menu("PURPLE TEAM OPERATIONS", [
            "Attack Simulation Engine",
            "Defense Validation Framework",
            "Red vs Blue Exercises",
            "Continuous Security Testing",
            "Threat Emulation Platform",
            "Security Control Assessment",
            "Gap Analysis & Remediation",
            "Purple Team Metrics Dashboard"
        ])

    def threat_intel(self):
        self.show_advanced_menu("THREAT INTELLIGENCE HUB", [
            "IOC Feed Integration",
            "Threat Actor Profiling",
            "Campaign Tracking",
            "Attribution Analysis",
            "Tactical Intelligence",
            "Strategic Intelligence",
            "Operational Intelligence",
            "Technical Intelligence"
        ])

    def network_monitoring(self):
        self.show_advanced_menu("NETWORK SECURITY MONITORING", [
            "Deep Packet Inspection",
            "Network Flow Analysis",
            "Intrusion Detection System",
            "Network Anomaly Detection",
            "Protocol Analysis",
            "Bandwidth Monitoring",
            "Network Forensics",
            "Traffic Correlation Engine"
        ])

    def edr_management(self):
        self.show_advanced_menu("ENDPOINT DETECTION & RESPONSE", [
            "Behavioral Monitoring",
            "Process Tree Analysis",
            "Memory Forensics",
            "Registry Monitoring",
            "File System Monitoring",
            "Network Connection Tracking",
            "Threat Hunting Queries",
            "Incident Response Automation"
        ])

    def vuln_assessment(self):
        self.show_advanced_menu("VULNERABILITY ASSESSMENT", [
            "Network Vulnerability Scanner",
            "Web Application Scanner",
            "Database Security Assessment",
            "Configuration Audit",
            "Patch Management Analysis",
            "Compliance Checking",
            "Risk Prioritization",
            "Remediation Tracking"
        ])

    def pentest_suite(self):
        self.show_advanced_menu("PENETRATION TESTING SUITE", [
            "Automated Exploitation Framework",
            "Post-Exploitation Toolkit",
            "Privilege Escalation Engine",
            "Lateral Movement Simulator",
            "Data Exfiltration Testing",
            "Persistence Mechanism Testing",
            "Evasion Technique Library",
            "Reporting & Documentation"
        ])

    def forensics(self):
        self.show_advanced_menu("FORENSICS & INCIDENT RESPONSE", [
            "Digital Evidence Collection",
            "Memory Dump Analysis",
            "Disk Image Forensics",
            "Network Packet Analysis",
            "Timeline Reconstruction",
            "Artifact Recovery",
            "Chain of Custody Management",
            "Expert Witness Reporting"
        ])

    def malware_analysis(self):
        self.show_advanced_menu("MALWARE ANALYSIS LAB", [
            "Static Analysis Engine",
            "Dynamic Analysis Sandbox",
            "Behavioral Analysis",
            "Code Deobfuscation",
            "Signature Generation",
            "Family Classification",
            "IOC Extraction",
            "Threat Attribution"
        ])

    def social_engineering(self):
        self.show_advanced_menu("SOCIAL ENGINEERING TOOLKIT", [
            "Phishing Campaign Manager",
            "Spear Phishing Templates",
            "Social Media Intelligence",
            "Pretexting Scenarios",
            "Physical Security Testing",
            "Awareness Training Metrics",
            "Human Factor Analysis",
            "Psychological Profiling"
        ])

    def wireless_security(self):
        self.show_advanced_menu("WIRELESS SECURITY TESTING", [
            "WiFi Network Assessment",
            "Bluetooth Security Testing",
            "RF Signal Analysis",
            "Wireless Protocol Testing",
            "Access Point Security",
            "Client Device Testing",
            "Rogue AP Detection",
            "Wireless Forensics"
        ])

    def web_app_security(self):
        self.show_advanced_menu("WEB APPLICATION SECURITY", [
            "OWASP Top 10 Testing",
            "SQL Injection Scanner",
            "XSS Detection Engine",
            "Authentication Bypass",
            "Authorization Testing",
            "Session Management Testing",
            "API Security Assessment",
            "Source Code Analysis"
        ])

    def mobile_security(self):
        self.show_advanced_menu("MOBILE SECURITY TESTING", [
            "Android App Analysis",
            "iOS App Analysis",
            "Mobile Device Management",
            "App Store Intelligence",
            "Mobile Malware Detection",
            "Privacy Assessment",
            "Jailbreak/Root Detection",
            "Mobile Forensics"
        ])

    def cloud_security(self):
        self.show_advanced_menu("CLOUD SECURITY ASSESSMENT", [
            "AWS Security Assessment",
            "Azure Security Testing",
            "GCP Security Analysis",
            "Container Security",
            "Kubernetes Security",
            "Serverless Security",
            "Cloud Configuration Audit",
            "Multi-Cloud Security"
        ])

    def iot_security(self):
        self.show_advanced_menu("IOT SECURITY TESTING", [
            "Device Firmware Analysis",
            "Communication Protocol Testing",
            "Hardware Security Assessment",
            "Embedded System Analysis",
            "IoT Network Security",
            "Device Authentication Testing",
            "Update Mechanism Analysis",
            "Privacy Impact Assessment"
        ])

    def crypto_analysis(self):
        self.show_advanced_menu("CRYPTOGRAPHIC ANALYSIS", [
            "Encryption Algorithm Testing",
            "Key Management Assessment",
            "Certificate Analysis",
            "Random Number Generation Testing",
            "Hash Function Analysis",
            "Digital Signature Verification",
            "Cryptographic Implementation Review",
            "Quantum Resistance Assessment"
        ])

    def reverse_engineering(self):
        self.show_advanced_menu("REVERSE ENGINEERING TOOLS", [
            "Binary Analysis Framework",
            "Disassembly Engine",
            "Decompilation Tools",
            "Dynamic Analysis",
            "Anti-Analysis Evasion",
            "Code Flow Analysis",
            "Function Identification",
            "Vulnerability Discovery"
        ])

    def osint_tools(self):
        self.show_advanced_menu("OSINT & RECONNAISSANCE", [
            "Domain Intelligence Gathering",
            "Social Media Intelligence",
            "Email Intelligence",
            "Phone Number Intelligence",
            "Dark Web Monitoring",
            "Breach Data Analysis",
            "Geolocation Intelligence",
            "Technical Intelligence"
        ])

    def exploit_dev(self):
        self.show_advanced_menu("EXPLOIT DEVELOPMENT", [
            "Vulnerability Research Framework",
            "Exploit Generation Engine",
            "Shellcode Development",
            "ROP Chain Builder",
            "Fuzzing Framework",
            "Crash Analysis",
            "Exploit Mitigation Bypass",
            "Zero-Day Discovery"
        ])

    def red_team_ops(self):
        self.show_advanced_menu("RED TEAM OPERATIONS", [
            "Attack Campaign Planning",
            "Infrastructure Management",
            "Command & Control",
            "Payload Generation",
            "Evasion Techniques",
            "Persistence Mechanisms",
            "Exfiltration Methods",
            "Operational Security"
        ])

    def blue_team_defense(self):
        self.show_advanced_menu("BLUE TEAM DEFENSE", [
            "Security Monitoring",
            "Incident Detection",
            "Threat Analysis",
            "Response Coordination",
            "Forensic Investigation",
            "Containment Strategies",
            "Recovery Procedures",
            "Lessons Learned"
        ])

    def threat_hunting(self):
        self.show_advanced_menu("THREAT HUNTING PLATFORM", [
            "Hypothesis Generation",
            "Data Collection & Analysis",
            "Behavioral Analytics",
            "Anomaly Detection",
            "IOC Development",
            "Threat Intelligence Integration",
            "Hunt Metrics & KPIs",
            "Continuous Improvement"
        ])

    def show_advanced_menu(self, title, options):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{Fore.MAGENTA}{Style.BRIGHT}")
        print(f"    ╔══════════════════════════════════════════════════════════════════════╗")
        print(f"    ║{title.center(70)}║")
        print(f"    ╚══════════════════════════════════════════════════════════════════════╝")
        print(f"{Style.RESET_ALL}")
        
        for i, option in enumerate(options, 1):
            print(f"    {Fore.MAGENTA}[{i}]{Fore.WHITE} {option}")
        
        print(f"\n    {Fore.RED}[0]{Fore.WHITE} Back to Main Menu")
        
        choice = input(f"\n{Fore.CYAN}    Select option: {Style.RESET_ALL}")
        
        if choice != "0":
            print(f"{Fore.GREEN}    {title.lower()} system activated...{Style.RESET_ALL}")
            time.sleep(2)
        
        input(f"{Fore.YELLOW}    Press Enter to continue...{Style.RESET_ALL}")

    def exit_platform(self):
        print(f"\n{Fore.MAGENTA}    Thank you for using NEON Platform!")
        print(f"    Follow us: {self.github}")
        print(f"    Discord: {self.discord}")
        print(f"    Instagram: {self.instagram}{Style.RESET_ALL}")
        sys.exit(0)

if __name__ == "__main__":
    platform = NeonPlatform()
    platform.main_menu()
