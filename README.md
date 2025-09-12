# NEON - Purple Team Autonomous Platform
![1](https://raw.githubusercontent.com/o0cdev/Neon/refs/heads/main/png/Showcase.png)

## Overview
NEON is the most advanced Purple Team cybersecurity platform designed for autonomous threat simulation, detection, and response. Built by 0xo0c, this platform integrates MITRE ATT&CK scenarios, real-time telemetry collection, and intelligent detection rule optimization.
## About

![About](https://github.com/o0cdev/Neon/blob/main/png/About.png?raw=true)

## Features

### Core Capabilities
- **MITRE ATT&CK Scenario Execution**: Automated execution of attack techniques with comprehensive telemetry generation
- **Advanced Telemetry Collection**: Multi-source data collection from endpoints, network sensors, and system monitors
- **Intelligent Detection Engine**: Sigma rule management with automatic Suricata conversion
- **Purple Team Operations**: Autonomous red vs blue team exercises with real-time metrics
- **Threat Intelligence Integration**: Advanced IOC enrichment and threat actor attribution
- **Real-time Analytics**: Behavioral analysis and anomaly detection

### Advanced Modules
- Network Security Monitoring
- Endpoint Detection & Response
- Vulnerability Assessment
- Penetration Testing Suite
- Forensics & Incident Response
- Malware Analysis Lab
- Social Engineering Toolkit
- Wireless Security Testing
- Web Application Security
- Mobile Security Testing
- Cloud Security Assessment
- IoT Security Testing
- Cryptographic Analysis
- Reverse Engineering Tools
- OSINT & Reconnaissance
- Exploit Development
- Red Team Operations
- Blue Team Defense
- Threat Hunting Platform
## Disclaimer

![Disclaime](https://raw.githubusercontent.com/o0cdev/Neon/refs/heads/main/png/Disclaimer.jpg)

## Installation

### Requirements
```bash
pip install -r requirements.txt
```

### Quick Start
```bash
python neon.py
```

## Architecture

### Core Engines
1. **MITRE Engine** (`mitre_engine.py`) - Attack scenario execution and simulation
2. **Telemetry Engine** (`telemetry_engine.py`) - Multi-source data collection and processing
3. **Detection Engine** (`detection_engine.py`) - Rule management and optimization
4. **Purple Team Engine** (`purple_team_engine.py`) - Autonomous team exercises
5. **Threat Intel Engine** (`threat_intel_engine.py`) - Intelligence integration and analysis

### Database Schema
- **Scenarios**: Attack execution tracking
- **Telemetry**: Multi-source event storage
- **Detections**: Rule effectiveness metrics

## Usage Examples

### Execute MITRE Technique
```python
from mitre_engine import MitreAttackEngine

engine = MitreAttackEngine()
result = engine.execute_technique("T1055", safe_mode=True)
```

### Start Telemetry Collection
```python
from telemetry_engine import TelemetryEngine

telemetry = TelemetryEngine()
telemetry.start_collection()
```

### Convert Sigma to Suricata
```python
from detection_engine import DetectionEngine

detector = DetectionEngine()
converted_rules = detector.convert_all_sigma_rules()
```

### Run Purple Team Exercise
```python
from purple_team_engine import PurpleTeamEngine

purple_team = PurpleTeamEngine()
scenario_id = purple_team.create_attack_scenario(
    "Advanced Persistent Threat Simulation",
    ["T1055", "T1059", "T1003", "T1021"]
)
purple_team.execute_purple_team_exercise(scenario_id)
```

## Configuration

### API Keys (Optional)
Set environment variables for enhanced threat intelligence:
- `VIRUSTOTAL_API_KEY`
- `SHODAN_API_KEY`
- `OTX_API_KEY`

### Database
SQLite database automatically created at `neon_database.db`

## Advanced Features

### Autonomous Detection Rule Optimization
- Real-time rule effectiveness analysis
- Automatic false positive reduction
- Dynamic rule enhancement based on telemetry

### Threat Actor Attribution
- Advanced attribution analysis using TTPs
- Confidence scoring and evidence correlation
- STIX 2.1 export capability

### Purple Team Metrics
- Detection rate analysis
- Response time optimization
- Continuous improvement recommendations

## Author Information
- **Author**: 0xo0c
- **GitHub**: https://github.com/o0cdev
- **Discord**: 0xo0c
- **Instagram**: instagram.com/o0ctf

## License
Advanced Cybersecurity Research Platform - All Rights Reserved

## Disclaimer
This tool is designed for authorized security testing and research purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

---

*NEON Platform - The Ultimate Purple Team Autonomous Cybersecurity Arsenal*
