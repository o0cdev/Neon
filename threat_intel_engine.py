
import json
import requests
import hashlib
import time
import sqlite3
from datetime import datetime, timedelta
import threading
import base64

class ThreatIntelligenceEngine:
    def __init__(self, db_path="neon_database.db"):
        self.db_path = db_path
        self.intel_sources = {}
        self.ioc_database = {}
        self.threat_actors = {}
        self.campaigns = {}
        self.attribution_data = {}
        
    def initialize_threat_intel_sources(self):
        self.intel_sources = {
            "misp": {
                "name": "MISP Threat Intelligence",
                "url": "https://misp-galaxy.org",
                "api_key": None,
                "enabled": True,
                "last_update": None
            },
            "otx": {
                "name": "AlienVault OTX",
                "url": "https://otx.alienvault.com/api/v1",
                "api_key": None,
                "enabled": True,
                "last_update": None
            },
            "virustotal": {
                "name": "VirusTotal",
                "url": "https://www.virustotal.com/vtapi/v2",
                "api_key": None,
                "enabled": True,
                "last_update": None
            },
            "shodan": {
                "name": "Shodan",
                "url": "https://api.shodan.io",
                "api_key": None,
                "enabled": True,
                "last_update": None
            },
            "internal": {
                "name": "Internal Intelligence",
                "url": "local",
                "api_key": None,
                "enabled": True,
                "last_update": None
            }
        }
        
    def load_threat_actors(self):
        self.threat_actors = {
            "APT1": {
                "name": "Comment Crew",
                "aliases": ["PLA Unit 61398", "Comment Group"],
                "country": "China",
                "motivation": "Espionage",
                "first_seen": "2006",
                "techniques": ["T1566", "T1059", "T1055", "T1003"],
                "tools": ["WEBC2", "BACKDOOR.BARKIOFORK", "TROJAN.ECLTYS"],
                "targets": ["Government", "Financial", "Technology"],
                "confidence": 0.95
            },
            "APT28": {
                "name": "Fancy Bear",
                "aliases": ["Sofacy", "Pawn Storm", "Sednit"],
                "country": "Russia",
                "motivation": "Espionage",
                "first_seen": "2007",
                "techniques": ["T1566", "T1190", "T1068", "T1055"],
                "tools": ["X-Tunnel", "CHOPSTICK", "SOURFACE"],
                "targets": ["Government", "Military", "Media"],
                "confidence": 0.98
            },
            "APT29": {
                "name": "Cozy Bear",
                "aliases": ["The Dukes", "CozyDuke", "Office Monkeys"],
                "country": "Russia",
                "motivation": "Espionage",
                "first_seen": "2008",
                "techniques": ["T1566", "T1059", "T1027", "T1070"],
                "tools": ["HAMMERTOSS", "COZYCAR", "MINIDIONIS"],
                "targets": ["Government", "Healthcare", "Energy"],
                "confidence": 0.96
            },
            "Lazarus": {
                "name": "Lazarus Group",
                "aliases": ["HIDDEN COBRA", "Guardians of Peace"],
                "country": "North Korea",
                "motivation": "Financial, Espionage",
                "first_seen": "2009",
                "techniques": ["T1566", "T1055", "T1105", "T1041"],
                "tools": ["BADCALL", "RATANKBA", "TYPEFRAME"],
                "targets": ["Financial", "Cryptocurrency", "Entertainment"],
                "confidence": 0.94
            },
            "FIN7": {
                "name": "Carbanak",
                "aliases": ["Carbanak Group", "Navigator Group"],
                "country": "Unknown",
                "motivation": "Financial",
                "first_seen": "2013",
                "techniques": ["T1566", "T1059", "T1055", "T1021"],
                "tools": ["CARBANAK", "DRIFTPIN", "HALFBAKED"],
                "targets": ["Financial", "Retail", "Hospitality"],
                "confidence": 0.92
            }
        }
        
    def load_ioc_feeds(self):
        mock_iocs = {
            "file_hashes": [
                {
                    "hash": "d41d8cd98f00b204e9800998ecf8427e",
                    "type": "MD5",
                    "malware_family": "Emotet",
                    "threat_actor": "TA542",
                    "first_seen": "2024-01-01",
                    "confidence": 0.95
                },
                {
                    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "type": "SHA256",
                    "malware_family": "TrickBot",
                    "threat_actor": "Wizard Spider",
                    "first_seen": "2024-01-02",
                    "confidence": 0.88
                }
            ],
            "ip_addresses": [
                {
                    "ip": "192.0.2.1",
                    "type": "C2",
                    "malware_family": "Cobalt Strike",
                    "threat_actor": "APT29",
                    "first_seen": "2024-01-01",
                    "confidence": 0.92
                },
                {
                    "ip": "198.51.100.1",
                    "type": "Exfiltration",
                    "malware_family": "Unknown",
                    "threat_actor": "APT28",
                    "first_seen": "2024-01-03",
                    "confidence": 0.85
                }
            ],
            "domains": [
                {
                    "domain": "malicious-example.com",
                    "type": "C2",
                    "malware_family": "Qakbot",
                    "threat_actor": "TA551",
                    "first_seen": "2024-01-01",
                    "confidence": 0.90
                },
                {
                    "domain": "phishing-site.net",
                    "type": "Phishing",
                    "malware_family": "Credential Harvester",
                    "threat_actor": "Unknown",
                    "first_seen": "2024-01-04",
                    "confidence": 0.87
                }
            ],
            "urls": [
                {
                    "url": "http://malicious-example.com/payload.exe",
                    "type": "Malware Download",
                    "malware_family": "Dridex",
                    "threat_actor": "Evil Corp",
                    "first_seen": "2024-01-02",
                    "confidence": 0.93
                }
            ]
        }
        
        self.ioc_database = mock_iocs
        return mock_iocs
    
    def enrich_ioc(self, ioc_value, ioc_type):
        enrichment_data = {
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "enrichment_timestamp": datetime.now().isoformat(),
            "sources": [],
            "threat_intelligence": {}
        }
        
        if ioc_type == "hash":
            for hash_ioc in self.ioc_database.get("file_hashes", []):
                if hash_ioc["hash"].lower() == ioc_value.lower():
                    enrichment_data["threat_intelligence"] = {
                        "malware_family": hash_ioc["malware_family"],
                        "threat_actor": hash_ioc["threat_actor"],
                        "confidence": hash_ioc["confidence"],
                        "first_seen": hash_ioc["first_seen"]
                    }
                    enrichment_data["sources"].append("internal_database")
                    break
        
        elif ioc_type == "ip":
            for ip_ioc in self.ioc_database.get("ip_addresses", []):
                if ip_ioc["ip"] == ioc_value:
                    enrichment_data["threat_intelligence"] = {
                        "type": ip_ioc["type"],
                        "malware_family": ip_ioc["malware_family"],
                        "threat_actor": ip_ioc["threat_actor"],
                        "confidence": ip_ioc["confidence"],
                        "first_seen": ip_ioc["first_seen"]
                    }
                    enrichment_data["sources"].append("internal_database")
                    break
        
        elif ioc_type == "domain":
            for domain_ioc in self.ioc_database.get("domains", []):
                if domain_ioc["domain"] == ioc_value:
                    enrichment_data["threat_intelligence"] = {
                        "type": domain_ioc["type"],
                        "malware_family": domain_ioc["malware_family"],
                        "threat_actor": domain_ioc["threat_actor"],
                        "confidence": domain_ioc["confidence"],
                        "first_seen": domain_ioc["first_seen"]
                    }
                    enrichment_data["sources"].append("internal_database")
                    break
        
        if not enrichment_data["sources"]:
            enrichment_data["threat_intelligence"] = {
                "status": "unknown",
                "confidence": 0.0,
                "recommendation": "Further investigation required"
            }
        
        return enrichment_data
    
    def analyze_threat_attribution(self, indicators):
        attribution_scores = {}
        
        for actor_name, actor_data in self.threat_actors.items():
            score = 0.0
            matches = []
            
            for indicator in indicators:
                if indicator.get("malware_family") in str(actor_data.get("tools", [])):
                    score += 0.3
                    matches.append(f"Tool match: {indicator.get('malware_family')}")
                
                if indicator.get("technique") in actor_data.get("techniques", []):
                    score += 0.2
                    matches.append(f"Technique match: {indicator.get('technique')}")
                
                if indicator.get("target_sector") in actor_data.get("targets", []):
                    score += 0.1
                    matches.append(f"Target match: {indicator.get('target_sector')}")
            
            if score > 0:
                attribution_scores[actor_name] = {
                    "score": min(score, 1.0),
                    "confidence": actor_data.get("confidence", 0.5) * score,
                    "matches": matches,
                    "actor_info": actor_data
                }
        
        sorted_attribution = sorted(
            attribution_scores.items(),
            key=lambda x: x[1]["confidence"],
            reverse=True
        )
        
        return dict(sorted_attribution[:3])
    
    def generate_threat_report(self, time_range_hours=24):
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=time_range_hours)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT data FROM telemetry
            WHERE timestamp BETWEEN ? AND ?
            AND event_type IN ('process_creation', 'network_connection', 'file_creation')
        ''', (start_time.isoformat(), end_time.isoformat()))
        
        telemetry_events = cursor.fetchall()
        conn.close()
        
        threat_indicators = []
        for event in telemetry_events:
            try:
                data = json.loads(event[0])
                
                if data.get("process_name") in ["powershell.exe", "cmd.exe", "wmic.exe"]:
                    threat_indicators.append({
                        "type": "suspicious_process",
                        "value": data.get("process_name"),
                        "technique": "T1059",
                        "confidence": 0.7
                    })
                
                if "CreateRemoteThread" in data.get("command_line", ""):
                    threat_indicators.append({
                        "type": "process_injection",
                        "value": data.get("command_line"),
                        "technique": "T1055",
                        "confidence": 0.8
                    })
                
            except:
                continue
        
        attribution_analysis = self.analyze_threat_attribution(threat_indicators)
        
        report = {
            "report_id": f"threat_report_{int(time.time())}",
            "generated_at": datetime.now().isoformat(),
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "hours": time_range_hours
            },
            "summary": {
                "total_events": len(telemetry_events),
                "threat_indicators": len(threat_indicators),
                "potential_actors": len(attribution_analysis)
            },
            "threat_indicators": threat_indicators,
            "attribution_analysis": attribution_analysis,
            "recommendations": self.generate_threat_recommendations(threat_indicators, attribution_analysis)
        }
        
        return report
    
    def generate_threat_recommendations(self, indicators, attribution):
        recommendations = []
        
        if len(indicators) > 10:
            recommendations.append({
                "priority": "High",
                "category": "Incident Response",
                "recommendation": "High volume of threat indicators detected",
                "action": "Initiate incident response procedures and isolate affected systems"
            })
        
        if any(attr["confidence"] > 0.8 for attr in attribution.values()):
            top_actor = max(attribution.items(), key=lambda x: x[1]["confidence"])
            recommendations.append({
                "priority": "Critical",
                "category": "Attribution",
                "recommendation": f"High confidence attribution to {top_actor[0]}",
                "action": f"Review {top_actor[1]['actor_info']['name']} TTPs and implement specific countermeasures"
            })
        
        technique_counts = {}
        for indicator in indicators:
            technique = indicator.get("technique")
            if technique:
                technique_counts[technique] = technique_counts.get(technique, 0) + 1
        
        if technique_counts:
            most_common = max(technique_counts.items(), key=lambda x: x[1])
            recommendations.append({
                "priority": "Medium",
                "category": "Detection Enhancement",
                "recommendation": f"Frequent use of technique {most_common[0]}",
                "action": f"Enhance detection rules for {most_common[0]} and related techniques"
            })
        
        return recommendations
    
    def update_threat_intelligence(self):
        self.initialize_threat_intel_sources()
        self.load_threat_actors()
        self.load_ioc_feeds()
        
        update_summary = {
            "timestamp": datetime.now().isoformat(),
            "sources_updated": len(self.intel_sources),
            "actors_loaded": len(self.threat_actors),
            "iocs_loaded": sum(len(iocs) for iocs in self.ioc_database.values()),
            "status": "completed"
        }
        
        return update_summary
    
    def search_threat_intelligence(self, query, search_type="all"):
        results = {
            "query": query,
            "search_type": search_type,
            "results": [],
            "timestamp": datetime.now().isoformat()
        }
        
        if search_type in ["all", "actors"]:
            for actor_name, actor_data in self.threat_actors.items():
                if query.lower() in actor_name.lower() or \
                   query.lower() in actor_data.get("name", "").lower() or \
                   any(query.lower() in alias.lower() for alias in actor_data.get("aliases", [])):
                    results["results"].append({
                        "type": "threat_actor",
                        "name": actor_name,
                        "data": actor_data
                    })
        
        if search_type in ["all", "iocs"]:
            for ioc_type, ioc_list in self.ioc_database.items():
                for ioc in ioc_list:
                    for key, value in ioc.items():
                        if query.lower() in str(value).lower():
                            results["results"].append({
                                "type": f"ioc_{ioc_type}",
                                "match_field": key,
                                "data": ioc
                            })
                            break
        
        return results
    
    def create_custom_ioc(self, ioc_value, ioc_type, metadata):
        custom_ioc = {
            "value": ioc_value,
            "type": ioc_type,
            "metadata": metadata,
            "created_at": datetime.now().isoformat(),
            "source": "custom",
            "confidence": metadata.get("confidence", 0.5)
        }
        
        if ioc_type not in self.ioc_database:
            self.ioc_database[ioc_type] = []
        
        self.ioc_database[ioc_type].append(custom_ioc)
        
        return custom_ioc
    
    def export_threat_intelligence(self, format_type="json"):
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "threat_actors": self.threat_actors,
            "ioc_database": self.ioc_database,
            "intel_sources": self.intel_sources
        }
        
        if format_type == "json":
            return json.dumps(export_data, indent=2)
        elif format_type == "stix":
            return self.convert_to_stix(export_data)
        else:
            return export_data
    
    def convert_to_stix(self, data):
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{hashlib.md5(str(time.time()).encode()).hexdigest()}",
            "spec_version": "2.1",
            "objects": []
        }
        
        for actor_name, actor_data in data["threat_actors"].items():
            stix_actor = {
                "type": "threat-actor",
                "id": f"threat-actor--{hashlib.md5(actor_name.encode()).hexdigest()}",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "name": actor_data.get("name", actor_name),
                "labels": ["nation-state"] if actor_data.get("country") else ["unknown"],
                "aliases": actor_data.get("aliases", []),
                "goals": [actor_data.get("motivation", "unknown")]
            }
            stix_bundle["objects"].append(stix_actor)
        
        return json.dumps(stix_bundle, indent=2)
