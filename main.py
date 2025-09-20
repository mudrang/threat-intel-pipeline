import os
from flask import Flask, request

# --- MODIFICATION: Import statements updated to match new filenames ---
from pcap_parsing_module import parse_pcap_data
from threat_intelligence_module import lookup_threat_intel, summarize_with_gemini
# --- END OF MODIFICATION ---

# Create the Flask application instance
app = Flask(__name__)

# --- Setup Upload Folder with Absolute Path ---
basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            return 'No selected file'

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # 1. Call the parser module
        ips, domains = parse_pcap_data(file_path)
        
        analysis_results = []
        # 2. Call the enrichment module for each IP
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
        
        # 3. Call the enrichment module for the AI summary
        ai_summary = summarize_with_gemini(analysis_results)
        
        # 4. Call the reporting function
        return generate_html_report(analysis_results, ai_summary)

    # This is the HTML for the upload form
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
        .filter-buttons button {{ margin: 0 5px 10px 0; padding: 8px 12px; cursor: pointer; border-radius: 5px; border: 1px solid #ccc;}}
        .copy-button {{ background-color: #007bff; color: white; }}
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

        function copyMaliciousIPs() {{
            const table = document.getElementById('resultsTable');
            const rows = table.getElementsByTagName('tr');
            const maliciousIps = [];

            for (let i = 1; i < rows.length; i++) {{
                const cells = rows[i].getElementsByTagName('td');
                if (cells.length > 2) {{
                    const ioc = cells[0].textContent.trim();
                    const type = cells[1].textContent.trim();
                    const status = cells[2].textContent.trim();
                    
                    if (type === 'IP' && status === 'malicious') {{
                        maliciousIps.push(ioc);
                    }}
                }}
            }}

            if (maliciousIps.length > 0) {{
                const textToCopy = maliciousIps.join('\\n');
                navigator.clipboard.writeText(textToCopy).then(() => {{
                    const button = document.getElementById('copyBtn');
                    button.textContent = 'Copied!';
                    setTimeout(() => {{ button.textContent = 'Copy Malicious IPs'; }}, 2000);
                }}, () => {{
                    alert('Failed to copy IPs.');
                }});
            }} else {{
                alert('No malicious IPs found to copy.');
            }}
        }}
    </script>
    </head><body><h1>PCAP Threat Intelligence Report</h1>
    {ai_summary_html}
    <h2>Detailed Findings</h2>
    <div class="filter-buttons">
    <button onclick="filterTable('All')">All</button><button onclick="filterTable('benign')">Benign</button>
    <button onclick="filterTable('malicious')">Malicious</button><button onclick="filterTable('suspicious')">Suspicious</button>
    
    <button id="copyBtn" class="copy-button" onclick="copyMaliciousIPs()">Copy Malicious IPs</button>
    
    </div>
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