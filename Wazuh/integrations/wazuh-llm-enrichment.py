#!/usr/bin/env python3
import json
import argparse
import requests
import os
import logging
import socket
from datetime import datetime
from ipaddress import ip_address, IPv4Address
from openai import OpenAI

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='/var/log/wazuh-llm-enrichment.log'
)
logger = logging.getLogger('wazuh-llm-enrichment')

# DeepSeek LLM API configuration
NOVITA_API_KEY = os.environ.get("NOVITA_API_KEY", "sk_2lt4Gtb5wZMjf1AspNJQZBbdauVWt2ZdpaU0_Fy9inE")
DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.novita.ai/v3/openai")
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek/deepseek-v3-turbo")

# IP Intelligence API (AbuseIPDB)
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "d77955e80f7acb91f12dbf368d8165f807bcc3700bd51dcfc1da1ae7baa7aeee3f2084601fb62185")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Path to Wazuh alerts file
WAZUH_ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

def read_alerts_from_file(file_path):
    """Read alerts from the Wazuh alerts file"""
    try:
        alerts = []
        with open(file_path, 'r') as file:
            for line in file:
                if line.strip():
                    alerts.append(json.loads(line))
        return alerts
    except Exception as e:
        logger.error(f"Failed to read alerts from file {file_path}: {e}")
        raise

def filter_alerts_by_rule_id(alerts, rule_ids):
    """Filter alerts by specific rule IDs"""
    filtered_alerts = [alert for alert in alerts if alert.get('rule', {}).get('id') in rule_ids]
    return filtered_alerts

def get_ip_intelligence(ip):
    """Get IP intelligence information from AbuseIPDB"""
    ip_info = {
        "is_valid": False,
        "type": "Unknown",
        "hostname": "Unknown",
        "country": "Unknown",
        "isp": "Unknown",
        "risk_score": "Unknown",
        "recent_reports": 0,
        "is_known_malicious": False
    }

    # Basic IP validation
    try:
        ip_obj = ip_address(ip)
        ip_info["is_valid"] = True
        ip_info["type"] = "IPv4" if isinstance(ip_obj, IPv4Address) else "IPv6"
    except ValueError:
        return ip_info

    # Try to get hostname
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        ip_info["hostname"] = hostname
    except (socket.herror, socket.gaierror):
        ip_info["hostname"] = "No hostname found"

    # Check if AbuseIPDB API key is provided
    if not ABUSEIPDB_API_KEY:
        return ip_info

    # Query AbuseIPDB for reputation data
    try:
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json',
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90',
            'verbose': True
        }
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json().get('data', {})
            ip_info["country"] = data.get('countryName', 'Unknown')
            ip_info["isp"] = data.get('isp', 'Unknown')
            ip_info["risk_score"] = data.get('abuseConfidenceScore', 0)
            ip_info["recent_reports"] = data.get('totalReports', 0)
            ip_info["is_known_malicious"] = ip_info["risk_score"] > 50
        else:
            logger.warning(f"Failed to get IP intelligence: {response.status_code}")
    except Exception as e:
        logger.error(f"Error querying AbuseIPDB: {e}")

    return ip_info

def analyze_with_deepseek(alert_data, ip_info):
    """Send alert data to DeepSeek v3 Turbo LLM for analysis and enrichment"""
    try:
        # Extract relevant information from the alert
        source_ip = alert_data.get('data', {}).get('srcip', 'Unknown')
        dest_ip = alert_data.get('data', {}).get('dstip', 'Unknown')
        username = alert_data.get('data', {}).get('srcuser', 'Unknown')
        rule_id = alert_data.get('rule', {}).get('id', 'Unknown')
        rule_description = alert_data.get('rule', {}).get('description', 'Unknown')
        timestamp = alert_data.get('timestamp', 'Unknown')
        location = alert_data.get('location', 'Unknown')

        # Create a client for DeepSeek
        client = OpenAI(
            base_url=DEEPSEEK_BASE_URL,
            api_key=NOVITA_API_KEY,
        )

        # Create prompt for the LLM with IP intelligence
        system_prompt = """
        You are a cybersecurity threat analyst expert. Your task is to analyze brute force attack alerts
        and provide detailed intelligence and actionable insights. Format your response as a valid JSON object.
        """

        user_prompt = f"""
        Analyze this brute force attack alert from Wazuh and provide enriched information:

        Alert Details:
        - Source IP: {source_ip}
        - Destination IP: {dest_ip}
        - Target Username: {username}
        - Rule ID: {rule_id}
        - Rule Description: {rule_description}
        - Timestamp: {timestamp}
        - Location: {location}

        Source IP Intelligence:
        - Valid IP: {ip_info['is_valid']}
        - IP Type: {ip_info['type']}
        - Hostname: {ip_info['hostname']}
        - Country: {ip_info['country']}
        - ISP: {ip_info['isp']}
        - Risk Score: {ip_info['risk_score']}
        - Recent Reports: {ip_info['recent_reports']}
        - Known Malicious: {ip_info['is_known_malicious']}

        Please provide the following as a JSON object:
        {{
          "threat_assessment": {{
            "severity": "SCORE_FROM_1_TO_10",
            "explanation": "Detailed explanation of the threat severity",
            "confidence": "SCORE_FROM_1_TO_10"
          }},
          "attacker_profile": {{
            "likely_actor_type": "Individual/Group/Nation-state/etc",
            "sophistication_level": "Low/Medium/High",
            "possible_motivations": ["List", "of", "motivations"],
            "likely_origin": "Best guess based on IP intelligence"
          }},
          "technical_analysis": {{
            "attack_pattern": "Description of the attack pattern",
            "targeted_vulnerabilities": ["List", "of", "potential", "vulnerabilities"],
            "attack_phase": "Initial Access/Lateral Movement/etc"
          }},
          "recommended_actions": [
            "Detailed action 1",
            "Detailed action 2"
          ],
          "false_positive_indicators": [
            "Indicator 1",
            "Indicator 2"
          ],
          "additional_iocs_to_hunt": [
            "IOC description 1",
            "IOC description 2"
          ],
          "similar_incidents": "Description of similar incidents in the threat landscape"
        }}
        """

        # Call DeepSeek LLM
        response = client.chat.completions.create(
            model=DEEPSEEK_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            max_tokens=2048,
            temperature=0.7,
            response_format={"type": "json_object"},
            extra_body={
                "top_k": 50,
                "repetition_penalty": 1,
                "min_p": 0
            }
        )

        # Extract the LLM response
        llm_response = response.choices[0].message.content
        enrichment = json.loads(llm_response)

        # Add metadata about the enrichment
        enrichment["meta"] = {
            "timestamp": datetime.now().isoformat(),
            "model_used": DEEPSEEK_MODEL,
            "version": "1.0",
            "ip_intelligence_source": "AbuseIPDB" if ABUSEIPDB_API_KEY else "Basic validation only"
        }

        return enrichment
    except Exception as e:
        logger.error(f"Failed to analyze with DeepSeek LLM: {e}")
        return {
            "error": str(e),
            "status": "failed",
            "timestamp": datetime.now().isoformat()
        }

def process_alerts(rule_ids):
    """Main function to process Wazuh alerts"""
    try:
        logger.info("Processing Wazuh alerts")

        # Read alerts from file
        alerts = read_alerts_from_file(WAZUH_ALERTS_FILE)

        # Filter alerts by rule IDs
        filtered_alerts = filter_alerts_by_rule_id(alerts, rule_ids)

        for alert in filtered_alerts:
            alert_id = alert.get('id', 'Unknown')
            logger.info(f"Processing alert ID: {alert_id}")

            # Get source IP from alert
            source_ip = alert.get('data', {}).get('srcip', 'Unknown')

            # Get IP intelligence
            ip_info = get_ip_intelligence(source_ip)

            # Send to DeepSeek LLM for analysis
            enrichment_data = analyze_with_deepseek(alert, ip_info)

            # Log the enrichment data
            logger.info(f"Enrichment data for alert {alert_id}: {json.dumps(enrichment_data, indent=2)}")

        logger.info("Finished processing alerts")
        return True
    except Exception as e:
        logger.error(f"Failed to process alerts: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Enrich Wazuh brute force alerts with DeepSeek LLM analysis')
    parser.add_argument('--rule-ids', nargs='+', type=int, help='List of rule IDs to process', default=[5760, 5763])
    args = parser.parse_args()

    success = process_alerts(args.rule_ids)
    exit(0 if success else 1)
