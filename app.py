import os
from flask import Flask, request
import requests
from scapy.all import rdpcap, IP, DNS, DNSRR
from dotenv import load_dotenv
import json
import re # <-- New import for regular expressions

# Load environment variables from .env file
load_dotenv()

# Create the Flask application instance
app = Flask(__name__)

# --- Setup Upload Folder with Absolute Path ---
basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def parse_pcap_data(pcap_path):
    """
    Robustly parses a PCAP file to extract all unique IPv4 addresses and domain names.
    Handles mixed traffic and malformed packets.
    """
    found_ips = set()
    found_domains = set()
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return [], []

    for packet in packets:
        try:
            if packet.haslayer(IP):
                found_ips.add(packet[IP].src)
                found_ips.add(packet[IP].dst)
            if packet.haslayer(DNS):
                if packet[DNS].qd and isinstance(packet[DNS].qd.qname, bytes):
                    domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                    found_domains.add(domain)
                if packet[DNS].an:
                    for i in range(packet[DNS].ancount):
                        dns_record = packet[DNS].an[i]
                        if isinstance(dns_record, DNSRR) and dns_record.type == 1:
                            found_ips.add(dns_record.rdata)
        except Exception:
            pass # Ignore packets that can't be parsed
    return list(found_ips), list(found_domains)


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

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}
    data = {"contents": [{"parts": [{"text": prompt}]}]}

    try:
        response = requests.post(url, headers=headers, json=data, timeout=20)
        response.raise_for_status()
        result = response.json()
        summary = result['candidates'][0]['content']['parts'][0]['text']
        
        # Remove the Markdown bold characters
        summary = summary.replace('**', '')
        
        # --- NEW MODIFICATION: Make text before colons bold using HTML tags ---
        summary = re.sub(r'([^:\n]+):', r'<b>\1</b>:', summary)
        # --- END OF NEW MODIFICATION ---
        
        return summary
    except requests.exceptions.RequestException as e:
        return f"Error contacting Gemini API: {e}"
    except (KeyError, IndexError, requests.exceptions.JSONDecodeError):
        return f"Could not parse Gemini API response. Raw response: {response.text}"
    except Exception as e:
        return f"An unexpected error occurred during AI summarization: {e}"


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            return 'No selected file'

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        ips, domains = parse_pcap_data(file_path)
        
        analysis_results = []
        for ip in ips:
            status_data = lookup_threat_intel(ip)
            analysis_results.append({
                "ioc": ip, "type": "IP",
                "status": status_data["status"], "reason": status_data["reason"]
            })
        for domain in domains:
             analysis_results.append({
                "ioc": domain, "type": "Domain",
                "status": "not_analyzed", "reason": "Domain analysis not yet implemented."
            })

        ai_summary = summarize_with_gemini(analysis_results)
        return generate_html_report(analysis_results, ai_summary)

    return '''
    <!doctype html><title>Upload PCAP File</title><h1>Upload PCAP File for Analysis</h1>
    <form method=post enctype=multipart/form-data><input type=file name=file><input type=submit value=Upload></form>
    '''

def generate_html_report(results, ai_summary=""): 
    ai_summary_html = f"<h2>AI-Generated Executive Summary</h2><p>{ai_summary.replace(os.linesep, '<br>')}</p><hr>"
    
    html_string = f"""
    <html><head><title>PCAP Threat Report</title>
    <style>
        body {{ font-family: sans-serif; margin: 2em; }} table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #dddddd; text-align: left; padding: 8px; }} th {{ background-color: #f2f2f2; }}
        .status-benign {{ color: green; font-weight: bold; }} .status-malicious {{ color: red; font-weight: bold; }}
        .status-suspicious {{ color: orange; font-weight: bold; }} .status-not_analyzed, .status-error {{ color: grey; }}
        .filter-buttons button {{ margin: 0 5px 10px 0; padding: 8px 12px; }}
        p {{ white-space: pre-wrap; }} 
    </style>
    <script>
        function filterTable(status) {{
            let table = document.getElementById('resultsTable'); let rows = table.getElementsByTagName('tr');
            for (let i = 1; i < rows.length; i++) {{
                let cell = rows[i].getElementsByTagName('td')[2];
                if (cell) {{
                    let rowStatus = cell.textContent || cell.innerText;
                    if (status === 'All' || rowStatus.trim() === status) {{ rows[i].style.display = ''; }}
                    else {{ rows[i].style.display = 'none'; }}
                }}
            }}
        }}
    </script>
    </head><body><h1>PCAP Threat Intelligence Report</h1>
    {ai_summary_html}
    <h2>Detailed Findings</h2>
    <div class="filter-buttons">
    <button onclick="filterTable('All')">All</button><button onclick="filterTable('benign')">Benign</button>
    <button onclick="filterTable('malicious')">Malicious</button><button onclick="filterTable('suspicious')">Suspicious</button>
    <button onclick="filterTable('not_analyzed')">Not Analyzed</button></div>
    <table id="resultsTable"><thead><tr><th>IOC</th><th>Type</th><th>Status</th><th>Reason</th></tr></thead><tbody>
    """
    for item in results:
        status_class = f"status-{item['status']}"
        html_string += f"""<tr><td>{item['ioc']}</td><td>{item['type']}</td>
        <td class="{status_class}">{item['status']}</td><td>{item['reason']}</td></tr>"""
    html_string += "</tbody></table></body></html>"
    return html_string

if __name__ == '__main__':
    app.run(debug=True)