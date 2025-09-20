import os
import requests
import json
import re
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def lookup_threat_intel(ip_address):
    """Looks up an IP address using the AbuseIPDB API."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"status": "error", "reason": "AbuseIPDB API key not configured."}
    
    if ip_address.startswith(('192.168.', '10.', '127.')):
        return {"status": "benign", "reason": "Private/Internal IP Address."}

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': api_key}
    try:
        response = requests.get(url=url, headers=headers, params=params, timeout=5)
        response.raise_for_status() 

        try:
            data = response.json().get('data', {})
        except requests.exceptions.JSONDecodeError:
            print(f"DEBUG: AbuseIPDB sent a non-JSON response: {response.text}")
            return {"status": "error", "reason": "Invalid API response. Check API key or rate limits."}
            
        score = data.get('abuseConfidenceScore', 0)
        
        if score >= 90:
            status = "malicious"
            reason = f"High risk (Score: {score}). Reported by {data.get('numDistinctUsers', 'N/A')} users."
        elif score >= 50:
            status = "suspicious"
            reason = f"Suspicious (Score: {score}). Total reports: {data.get('totalReports', 'N/A')}."
        else:
            status = "benign"
            reason = f"Low risk (Score: {score})."
        return {"status": status, "reason": reason}
    except requests.exceptions.RequestException as e:
        return {"status": "error", "reason": f"API request failed: {e}"}
    except Exception as e:
        return {"status": "error", "reason": f"An unexpected error occurred: {e}"}


def summarize_with_gemini(analysis_results):
    """
    Uses the Gemini API to generate a natural language summary of the findings.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "Gemini API key not configured. Cannot generate AI summary."

    high_risk_iocs = [res for res in analysis_results if res['status'] in ['malicious', 'suspicious']]
    if not high_risk_iocs:
        return "No significant threats were found in the provided network traffic."

    prompt = (
        "You are a professional cybersecurity analyst. Based on the following list of "
        "Indicators of Compromise (IOCs) found in a network capture, provide a brief, "
        "executive summary of the potential threats. Group related findings if possible.\n\n"
        "IOC Data:\n"
        f"{json.dumps(high_risk_iocs, indent=2)}\n\n"
        "Executive Summary:"
    )

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}
    data = {"contents": [{"parts": [{"text": prompt}]}]}

    try:
        response = requests.post(url, headers=headers, json=data, timeout=20)
        response.raise_for_status()
        result = response.json()
        summary = result['candidates'][0]['content']['parts'][0]['text']
        
        summary = summary.replace('**', '')
        summary = re.sub(r'([^:\n]+):', r'<b>\1</b>:', summary)
        
        return summary
    except requests.exceptions.RequestException as e:
        return f"Error contacting Gemini API: {e}"
    except (KeyError, IndexError, requests.exceptions.JSONDecodeError):
        return f"Could not parse Gemini API response. Raw response: {response.text}"
    except Exception as e:
        return f"An unexpected error occurred during AI summarization: {e}"