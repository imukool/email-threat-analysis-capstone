import streamlit as st
import plotly.graph_objects as go
from google import genai
import os
import json
import re
import hashlib
import requests
import base64
from email import policy
from email.parser import BytesParser
from dotenv import load_dotenv

# Optional DNS import for active domain checking
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ==========================================
# LOAD SECRETS
# ==========================================
load_dotenv()
SYSTEM_API_KEY = os.getenv("GEMINI_API_KEY")

try:
    VT_API_KEY = st.secrets["VT_API_KEY"]
    VT_AVAILABLE = True
except (KeyError, FileNotFoundError):
    VT_API_KEY = None
    VT_AVAILABLE = False

# ==========================================
# PAGE CONFIG & HACKER THEME CSS
# ==========================================
st.set_page_config(page_title="Email Threat Analyzer", layout="wide")

st.markdown("""
    <style>
    .stApp { background-color: #0e1117; color: #00ff00; font-family: 'Courier New', Courier, monospace; }
    h1, h2, h3 { color: #00ff00 !important; }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea, .stSelectbox>div>div>select {
        background-color: #1a1c23; color: #00ff00; border: 1px solid #00ff00;
        font-family: 'Courier New', Courier, monospace; border-radius: 6px; outline: none !important;
    }
    .stTextInput>div>div>input:focus, .stTextArea>div>div>textarea:focus, .stSelectbox>div>div>select:focus {
        border-color: #00ff00 !important; box-shadow: 0 0 0 1px #00ff00 !important;
    }
    .stTextArea>div>div>textarea { resize: vertical; }
    .stTextArea>div>div>textarea::-webkit-resizer { background-color: #1a1c23; }
    .stTextInput>div>div>input:disabled { color: #00ff00; background-color: #0e1117; border: 1px dashed #00ff00; }
    .stButton>button { background-color: #00ff00; color: #0e1117; font-weight: bold; border: 2px solid #00ff00; border-radius: 5px; }
    .stButton>button:hover { background-color: #0e1117; color: #00ff00; border: 2px solid #00ff00; }
    .expander-content { border: 1px solid #00ff00; padding: 10px; border-radius: 5px; background-color: #1a1c23; }
    </style>
""", unsafe_allow_html=True)

# ==========================================
# VIRUSTOTAL API LOGIC
# ==========================================
def check_file_hash(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    return requests.get(url, headers=headers).json()

def check_url_report(api_key, target_url):
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    return requests.get(url, headers=headers).json()

# ==========================================
# CORE SCORING LOGIC (100 PT MATRIX)
# ==========================================
DANGEROUS_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
    '.jar', '.zip', '.rar', '.7z', '.iso', '.dll', '.sys', '.msi',
    '.hta', '.ps1', '.psm1', '.reg', '.scf', '.lnk', '.inf'
]

def calculate_attachment_score(attachments_input):
    if not attachments_input: return 0
    score = sum(10 for att in (a.strip().lower() for a in attachments_input.split(','))
                if any(att.endswith(ext) for ext in DANGEROUS_EXTENSIONS))
    return min(score, 20)

def calculate_url_score(urls_input):
    if not urls_input: return 0
    urls = [url.strip() for url in urls_input.split('\n') if url.strip()]
    score = 3 if urls else 0
    for url in urls:
        if any(p in url.lower() for p in ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly']): score += 5
        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url): score += 7
    return min(score, 15)

def calculate_auth_score(spf, dkim, dmarc):
    score = sum(5 for metric in [spf, dkim, dmarc] if metric == "Fail")
    return min(score, 15)

def calculate_domain_score(domain):
    if not domain: return 0
    score = 0
    domain = domain.lower().strip()
    if domain in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']: score += 3
    if domain.count('-') > 1: score += 4
    if any(char.isdigit() for char in domain.split('.')[0]): score += 3
    return min(score, 10)

def calculate_vt_score(urls_input, att_details, api_key):
    if not api_key: return 0, "No VT API key. Bypassing scan."

    score = 0
    summary = []

    # Restrict to 2 of each to avoid hitting the 4 req/min Free Tier limit
    urls = [u.strip() for u in urls_input.split('\n') if u.strip()][:2]
    hashes = [att['hash'] for att in att_details if att.get('hash') and att['hash'] != "ERROR"][:2]

    if not urls and not hashes:
        return 0, "No extractable URLs or Hashes to scan."

    for url in urls:
        try:
            res = check_url_report(api_key, url)
            if 'data' in res and 'attributes' in res['data']:
                malicious = res['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                if malicious > 0:
                    score += 15
                    summary.append(f"URL flagged by {malicious} vendors.")
        except Exception: pass

    for h in hashes:
        try:
            res = check_file_hash(api_key, h)
            if 'data' in res and 'attributes' in res['data']:
                malicious = res['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                if malicious > 0:
                    score += 15
                    summary.append(f"Hash flagged by {malicious} vendors.")
        except Exception: pass

    final_score = min(score, 30)
    summary_text = " | ".join(summary) if summary else "0 malicious flags detected across scanned artifacts."
    return final_score, summary_text

def analyze_language_with_genai(subject, body, api_key):
    if not api_key: return 0, "No API key found. AI Language analysis bypassed."
    if not subject and not body: return 0, "Insufficient text data for AI analysis."
    try:
        client = genai.Client(api_key=api_key)
        prompt = f"""
        Analyze the following email Subject and Body.
        1. Evaluate the "Urgent or threatening language" factor (0 to 10).
        2. Provide a 2-3 sentence "Threat Summary & Recommendation".
        Subject: {subject}
        Body: {body}
        Return ONLY a valid JSON object with keys: "language_score" (int 0-10) and "summary" (string).
        """
        response = client.models.generate_content(model='gemini-2.5-flash', contents=prompt)
        clean_text = response.text.replace('```json', '').replace('```', '').strip()
        result = json.loads(clean_text)
        return max(0, min(int(result.get("language_score", 0)), 10)), str(result.get("summary", "Analysis completed."))
    except Exception as e:
        return 0, f"Error during AI analysis: {str(e)}"

# --- Automated Header, DNS & Attachment Logic ---
def verify_dns_records(domain):
    spf_status, dmarc_status = 'NONE', 'NONE'
    if not DNS_AVAILABLE or not domain: return spf_status, dmarc_status
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if 'v=spf1' in rdata.to_text(): spf_status = 'PASS'
    except: pass
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in answers:
            if 'v=DMARC1' in rdata.to_text(): dmarc_status = 'PASS'
    except: pass
    return spf_status, dmarc_status

def extract_auth_status(msg, sender_domain):
    auth_results = str(msg.get('Authentication-Results', '')).lower()
    received_spf = str(msg.get('Received-SPF', '')).lower()

    spf = "Fail" if 'fail' in auth_results or 'fail' in received_spf else "Pass" if 'pass' in auth_results or 'pass' in received_spf else "None"
    dkim = "Fail" if 'dkim=fail' in auth_results else "Pass" if 'dkim=pass' in auth_results else "None"
    dmarc = "Fail" if 'dmarc=fail' in auth_results else "Pass" if 'dmarc=pass' in auth_results else "None"

    dns_spf, dns_dmarc = verify_dns_records(sender_domain)
    if spf == "None" and dns_spf == "PASS": spf = "Pass"
    if dmarc == "None" and dns_dmarc == "PASS": dmarc = "Pass"
    return spf, dkim, dmarc

def extract_attachments(msg):
    attachments, file_names = [], []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart': continue
            if part.get('Content-Disposition') is None: continue

            filename = part.get_filename()
            if filename:
                payload = part.get_payload(decode=True)
                file_hash = hashlib.sha256(payload).hexdigest() if payload else "ERROR"
                size = len(payload) if payload else 0
                file_names.append(filename)
                attachments.append({"name": filename, "hash": file_hash, "size": f"{size / 1024:.2f} KB"})
    return ", ".join(file_names), attachments

# ==========================================
# DASHBOARD UI
# ==========================================
st.title("EMAIL THREAT ANALYZER")
st.markdown("---")

with st.sidebar:
    st.header("System Config")
    if SYSTEM_API_KEY: st.success("✅ GenAI Key Loaded")
    else: st.error("❌ GenAI Key Missing")
    if DNS_AVAILABLE: st.success("✅ DNS Resolver Active")
    else: st.warning("⚠️ DNS Resolver Offline")
    if VT_AVAILABLE: st.success("✅ VirusTotal Key Loaded")
    else: st.error("❌ VirusTotal Key Missing")

    st.markdown("---")
    st.markdown("**Scoring Matrix:**")
    st.markdown("- VirusTotal Intel: 0-30")
    st.markdown("- Attachments: 0-20")
    st.markdown("- URLs: 0-15")
    st.markdown("- Auth Failures: 0-15")
    st.markdown("- Domain: 0-10")
    st.markdown("- AI Language: 0-10")

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("INPUT DATA")
    uploaded_file = st.file_uploader("Upload .eml file for deep scan", type=['eml'])

    def_domain, def_subject, def_body, def_urls, def_attachments = "", "", "", "", ""
    def_spf, def_dkim, def_dmarc = "None", "None", "None"
    att_details = []

    if uploaded_file:
        msg = BytesParser(policy=policy.default).parsebytes(uploaded_file.getvalue())
        def_subject = str(msg.get('Subject', ''))
        sender = str(msg.get('From', ''))

        extracted_email = re.search(r'[\w\.-]+@[\w\.-]+', sender)
        if extracted_email: def_domain = extracted_email.group(0).split('@')[-1]

        body_parts, html_parts = [], []
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))
                if ctype == 'text/plain' and 'attachment' not in cdispo:
                    payload = part.get_payload(decode=True)
                    if payload: body_parts.append(payload.decode(errors='ignore'))
                elif ctype == 'text/html' and 'attachment' not in cdispo:
                    payload = part.get_payload(decode=True)
                    if payload: html_parts.append(payload.decode(errors='ignore'))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                if msg.get_content_type() == 'text/html': html_parts.append(payload.decode(errors='ignore'))
                else: body_parts.append(payload.decode(errors='ignore'))

        def_body = "\n".join(body_parts)
        if not def_body and html_parts:
            def_body = re.sub(r'<[^>]+>', ' ', "\n".join(html_parts))
            def_body = re.sub(r'\s+', ' ', def_body).strip()

        found_urls = set()
        found_urls.update(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', def_body))
        for html_content in html_parts:
            found_urls.update(re.findall(r'href=[\'"]?(https?://[^\'" >]+)', html_content, re.IGNORECASE))
            found_urls.update(re.findall(r'https?://[^\s<>"\']+', html_content))

        def_urls = "\n".join(list(found_urls))
        def_spf, def_dkim, def_dmarc = extract_auth_status(msg, def_domain)
        def_attachments, att_details = extract_attachments(msg)

    sender_domain = st.text_input("Sender Domain", value=def_domain)
    email_subject = st.text_input("Email Subject", value=def_subject)
    email_body = st.text_area("Email Body", value=def_body, height=150)
    urls_found = st.text_area("URLs Found (One per line)", value=def_urls, height=100)

    st.text_input("Attachments Detected", value=def_attachments, disabled=True)
    if att_details:
        with st.expander("View Attachment Hashes (SHA-256)"):
            for att in att_details: st.markdown(f"**{att['name']}**<br>`{att['hash']}`", unsafe_allow_html=True)

    st.markdown("**Authentication Status (Auto-Detected)**")
    auth_col1, auth_col2, auth_col3 = st.columns(3)
    with auth_col1: spf_status = st.text_input("SPF", value=def_spf, disabled=True)
    with auth_col2: dkim_status = st.text_input("DKIM", value=def_dkim, disabled=True)
    with auth_col3: dmarc_status = st.text_input("DMARC", value=def_dmarc, disabled=True)

    analyze_button = st.button("INITIATE SCAN", use_container_width=True)

with col2:
    st.subheader("ANALYSIS RESULTS")
    if analyze_button:
        with st.spinner("Analyzing vectors and querying intel..."):
            score_vt, vt_summary = calculate_vt_score(urls_found, att_details, VT_API_KEY)
            score_attach = calculate_attachment_score(def_attachments)
            score_urls = calculate_url_score(urls_found)
            score_auth = calculate_auth_score(spf_status, dkim_status, dmarc_status)
            score_domain = calculate_domain_score(sender_domain)
            score_lang, ai_summary = analyze_language_with_genai(email_subject, email_body, SYSTEM_API_KEY)

            total_score = score_vt + score_attach + score_urls + score_auth + score_domain + score_lang
            classification = "SAFE" if total_score <= 30 else "SUSPICIOUS" if total_score <= 65 else "MALICIOUS"
            color = "green" if total_score <= 30 else "yellow" if total_score <= 65 else "red"

            fig_gauge = go.Figure(go.Indicator(
                mode = "gauge+number", value = total_score,
                title = {'text': f"THREAT LEVEL: {classification}", 'font': {'color': color, 'family': 'Courier New'}},
                gauge = {
                    'axis': {'range': [0, 100], 'tickcolor': "#00ff00"},
                    'bar': {'color': "rgba(0,0,0,0)"},
                    'bgcolor': "#1a1c23", 'borderwidth': 2, 'bordercolor': "#00ff00",
                    'steps': [
                        {'range': [0, 30], 'color': "rgba(0, 255, 0, 0.6)"},
                        {'range': [30, 65], 'color': "rgba(255, 255, 0, 0.6)"},
                        {'range': [65, 100], 'color': "rgba(255, 0, 0, 0.6)"}
                    ],
                    'threshold': {'line': {'color': "#ffffff", 'width': 4}, 'thickness': 0.75, 'value': total_score}
                }
            ))
            fig_gauge.update_layout(paper_bgcolor="#0e1117", font={'color': "#00ff00"}, height=300)
            st.plotly_chart(fig_gauge, use_container_width=True)

            # Updated Breakdown Bar Chart to include VirusTotal Intel
            fig_bar = go.Figure(data=[
                go.Bar(
                    name='Assigned',
                    x=['VT Intel', 'Attach', 'URLs', 'Auth', 'Domain', 'AI Language'],
                    y=[score_vt, score_attach, score_urls, score_auth, score_domain, score_lang],
                    marker_color='#00ff00',
                    text=[score_vt, score_attach, score_urls, score_auth, score_domain, score_lang],
                    textposition='auto'
                )
            ])
            fig_bar.update_layout(
                title="Threat Vector Breakdown",
                paper_bgcolor="#0e1117", plot_bgcolor="#0e1117",
                font={'color': "#00ff00", 'family': 'Courier New'},
                height=350,
                yaxis=dict(range=[0, 35], showgrid=True, gridcolor='#1a1c23', zerolinecolor='#00ff00'),
                margin=dict(l=20, r=20, t=40, b=20)
            )
            st.plotly_chart(fig_bar, use_container_width=True)

            st.markdown("### 🌐 External Intel Summary")
            st.info(vt_summary)

            st.markdown("### 🤖 AI Threat Summary")
            st.info(ai_summary)

st.markdown("---")
st.subheader("EXTERNAL THREAT INTELLIGENCE (VIRUSTOTAL)")
with st.expander("🔍 Manual VirusTotal Scanner"):
    if not VT_AVAILABLE:
        st.error("VirusTotal API key not found in Streamlit secrets.")
    else:
        vt_col1, vt_col2 = st.columns(2)
        with vt_col1:
            st.markdown("**Scan a URL**")
            target_vt_url = st.text_input("Enter URL to check")
            if st.button("Fetch URL Report", key="vt_url_btn"):
                if target_vt_url:
                    with st.spinner("Querying VirusTotal..."):
                        st.json(check_url_report(VT_API_KEY, target_vt_url))
        with vt_col2:
            st.markdown("**Scan a File Hash**")
            target_vt_hash = st.text_input("Enter SHA-256 Hash")
            if st.button("Fetch Hash Report", key="vt_hash_btn"):
                if target_vt_hash:
                    with st.spinner("Querying VirusTotal..."):
                        st.json(check_file_hash(VT_API_KEY, target_vt_hash))
