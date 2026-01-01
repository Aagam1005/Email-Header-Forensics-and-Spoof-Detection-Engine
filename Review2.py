#!/usr/bin/env python3
"""
Email Forensics — Web UI (single-file)
Original light-themed AI-style interface.
REPLACEMENT: Speedometer Gauge instead of Circular Meter.
MODEL UPDATE: Uses mshenoda/roberta-spam (High Accuracy) + Truncation Fix.
PDF UPDATE: Custom Logo, Title, and Compact Spacing.
LOGIC UPDATE: NLP Label acts as Master Override.
STABILITY UPDATE: UI truncates massive text previews to prevent browser freezing.

Run:
    pip install flask flask-cors fpdf transformers torch
    python forensics_ui.py
Open http://127.0.0.1:5000
"""
from flask import Flask, request, jsonify, render_template_string, send_file, url_for
from flask_cors import CORS
import os, re, io, json
from email import policy
from email.parser import BytesParser, Parser
from email.message import EmailMessage
from fpdf import FPDF

# Optional libs (graceful)
HAVE_DKIM = HAVE_SPF = HAVE_DNS = HAVE_SCAPY = HAVE_TRANSFORMERS = False
try:
    import dkim; HAVE_DKIM = True
except Exception:
    HAVE_DKIM = False
try:
    import spf; HAVE_SPF = True
except Exception:
    HAVE_SPF = False
try:
    import dns.resolver; HAVE_DNS = True
except Exception:
    HAVE_DNS = False
try:
    from scapy.all import rdpcap; HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False

# --- MODEL CONFIGURATION ---
MODEL_NAME = "mshenoda/roberta-spam" 
MODEL_ACCURACY = "~99%"
nlp_pipeline = None
nlp_load_status = "NLP model not loaded."

try:
    from transformers import pipeline
    HAVE_TRANSFORMERS = True
except Exception:
    HAVE_TRANSFORMERS = False

# Regex / constants
RECEIVED_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
DOUBLE_EXT_RE = re.compile(r"\.(\w+)\.(exe|scr|bat|com|js|vbs|docm|xlsm|jar)$", re.IGNORECASE)
SUSPICIOUS_EXT = {"exe","scr","bat","com","js","vbs","docm","xlsm","jar"}


# Parsing helpers
def parse_eml_bytes(data: bytes) -> EmailMessage:
    try:
        return BytesParser(policy=policy.default).parsebytes(data)
    except Exception:
        text = data.decode("utf-8", errors="ignore")
        return Parser(policy=policy.default).parsestr(text)

def extract_received_ips(msg):
    rcvd = msg.get_all("Received") or []
    ips=[]
    for h in rcvd:
        found = RECEIVED_IP_RE.findall(h)
        for ip in found:
            parts=ip.split(".")
            try:
                if len(parts)==4 and all(0<=int(p)<=255 for p in parts):
                    ips.append(ip)
            except Exception:
                pass
    return list(reversed(ips)) if ips else ips

def get_from_and_return_path(msg):
    from_hdr = msg.get("From")
    ret = msg.get("Return-Path") or msg.get("Envelope-From") or None
    return from_hdr, ret

def extract_subject_and_body(msg):
    subject = msg.get("Subject","")
    body_parts=[]
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get_content_disposition() or "")
            if disp=="attachment": continue
            if ctype=="text/plain":
                try: text = part.get_content()
                except:
                    try: text = part.get_payload(decode=True).decode("utf-8",errors="ignore")
                    except: text = ""
                body_parts.append(text)
            elif ctype=="text/html" and not body_parts:
                try: html = part.get_content()
                except:
                    try: html = part.get_payload(decode=True).decode("utf-8",errors="ignore")
                    except: html = ""
                text = re.sub(r"<[^>]+>"," ", html)
                body_parts.append(text)
    else:
        ctype = msg.get_content_type()
        if ctype in ("text/plain","text/html"):
            try: body = msg.get_content()
            except:
                try: body = msg.get_payload(decode=True).decode("utf-8",errors="ignore")
                except: body = ""
            if ctype=="text/html":
                body = re.sub(r"<[^>]+>"," ", body)
            body_parts.append(body)
    body_text = "\n\n".join(p for p in body_parts if p)
    return subject or "", body_text or ""

# SPF/DKIM/DMARC wrappers (graceful)
def spf_check(ip, mail_from=None, helo=None):
    if not HAVE_SPF:
        return {"ok":False,"error":"pyspf not installed"}
    try:
        mail_from = mail_from or "-"
        helo = helo or "unknown"
        res = spf.check2(i=ip, s=mail_from, h=helo)
        return {"ok":True,"result":res[0],"explanation":res[1],"spf_record":res[2]}
    except Exception as e:
        return {"ok":False,"error":str(e)}

def dkim_check(raw_bytes):
    if not HAVE_DKIM:
        return {"ok":False,"error":"dkimpy not installed"}
    try:
        verified = dkim.verify(raw_bytes)
        return {"ok":True,"verified":bool(verified)}
    except Exception as e:
        return {"ok":False,"error":str(e)}

def dmarc_lookup(domain):
    if not HAVE_DNS:
        return {"ok":False,"error":"dnspython not installed"}
    try:
        qname = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(qname,"TXT")
        txts = [b"".join(r.strings).decode("utf-8") for r in answers]
        txt = " ".join(txts)
        policy={}
        for part in [p.strip() for p in txt.split(";") if p.strip()]:
            if "=" in part:
                k,v = part.split("=",1)
                policy[k.lower()] = v
        return {"ok":True,"record":txt,"policy":policy}
    except Exception as e:
        return {"ok":False,"error":str(e)}

# Heuristics
def detect_display_name_spoof(from_header):
    if not from_header:
        return {"ok":False,"error":"No From header"}
    m = re.match(r"\s*([^<]+)\s*<(.+@.+)>", from_header)
    if m:
        display = m.group(1).strip(' "')
        addr = m.group(2); dom = addr.split("@")[-1].lower()
        words = re.findall(r"[A-Za-z]{3,}", display)
        suspicious=False; reasons=[]
        for w in words:
            if w.lower() in dom: continue
            if len(w)>=4 and w[0].isupper():
                suspicious=True
                reasons.append(f"Display contains '{w}' but domain is '{dom}'")
        return {"ok":True,"suspicious":suspicious,"reasons":reasons,"display":display,"addr":addr}
    return {"ok":True,"suspicious":False,"reason":"No display name / simple address"}

def detect_hidden_attachments(msg):
    findings=[]
    if msg.is_multipart():
        for part in msg.iter_attachments():
            filename=part.get_filename(); ctype=part.get_content_type()
            if filename:
                if DOUBLE_EXT_RE.search(filename):
                    findings.append({"type":"double_ext","filename":filename})
                ext = os.path.splitext(filename)[1].lower().lstrip(".")
                if ext in SUSPICIOUS_EXT:
                    findings.append({"type":"suspicious_ext","filename":filename})
            else:
                findings.append({"type":"no_filename","detail":f"attachment type {ctype}"})
            if ctype in ("application/x-msdownload","application/x-dosexec") or ctype.startswith("application/x-"):
                findings.append({"type":"suspicious_ctype","ctype":ctype,"filename":filename})
    else:
        cd = msg.get("Content-Disposition")
        if cd and "attachment" in cd.lower():
            m=re.search(r'filename="?([^";]+)"?', cd)
            fname = m.group(1) if m else None
            findings.append({"type":"singlepart_attach","filename":fname})
    return {"ok":True,"findings":findings}

# NLP loader/classifier
def load_nlp_model():
    global nlp_pipeline, nlp_load_status
    if not HAVE_TRANSFORMERS:
        nlp_load_status = "NLP Error: transformers library not installed."
        return
    try:
        nlp_pipeline = pipeline("text-classification", model=MODEL_NAME)
        nlp_load_status = "NLP Model Loaded Successfully."
    except Exception as e:
        nlp_pipeline = None
        nlp_load_status = f"NLP Error: Failed to load model. {e}"

def nlp_classify(text):
    if nlp_pipeline is None:
        return {"ok":False,"error":"NLP not loaded"}
    if not text or len(text.strip())==0:
        return {"ok":True,"label":"LABEL_0","score":0.0,"note":"empty"}
    try:
        # TRUNCATION FIX
        res = nlp_pipeline(text, truncation=True, max_length=512)
        out = res[0] if isinstance(res,list) and res else res
        return {"ok":True,"label":out.get("label"),"score":float(out.get("score",0.0))}
    except Exception as e:
        return {"ok":False,"error":str(e)}

# Risk compute
def compute_risk(report, nlp_result=None):
    # This 'technical_score' tracks headers/attachments, 
    # but NLP will Override it at the end.
    technical_score = 0
    reasons = []

    # 1. SPF Check
    spf = report.get("spf",{})
    if spf.get("ok") and spf.get("result"):
        rf = spf.get("result").lower()
        if rf=="pass":
            reasons.append("SPF passed"); technical_score-=1
        elif rf in ("neutral","none"):
            reasons.append(f"SPF: {rf}")
        else:
            reasons.append(f"SPF failed: {rf}"); technical_score+=2
    else:
        reasons.append("SPF unavailable"); technical_score+=1

    # 2. DKIM Check
    dkim = report.get("dkim",{})
    if dkim.get("ok") and dkim.get("verified"):
        reasons.append("Valid DKIM"); technical_score-=1
    else:
        if dkim.get("ok"):
            reasons.append("DKIM not verified"); technical_score+=2
        else:
            reasons.append("DKIM unavailable"); technical_score+=1

    # 3. DMARC Check
    dmarc = report.get("dmarc",{})
    if dmarc.get("ok") and dmarc.get("policy"):
        p = dmarc.get("policy").get("p","none")
        reasons.append(f"DMARC: {p}")
        if p=="reject": technical_score-=1
    else:
        reasons.append("DMARC missing"); technical_score+=1

    # 4. Display Name Spoofing
    dsp = report.get("display_spoof",{})
    if dsp.get("ok") and dsp.get("suspicious"):
        reasons.append("Display-name impersonation likely"); technical_score+=2

    # 5. Attachment Checks
    att = report.get("attachments",{})
    if att.get("ok") and att.get("findings"):
        reasons.append("Suspicious attachments present"); technical_score+=2

    if report.get("mismatches"):
        reasons.append("Return-Path vs From mismatch"); technical_score+=2

    # --- MASTER OVERRIDE: NLP LOGIC ---
    # We initiate score with technical_score, but NLP dictates the final zone.
    score = technical_score

    if nlp_result:
        if not nlp_result.get("ok"):
            reasons.append("NLP unavailable")
        else:
            lab = str(nlp_result.get("label","LABEL_0")); sc = float(nlp_result.get("score",0.0))
            
            if lab.upper()=="LABEL_1" or "SPAM" in lab.upper():
                # --- NLP DETECTED SPAM (LABEL_1) ---
                reasons.append(f"NLP: Spam detected ({sc:.2f})")
                
                # FORCE RED ZONE (Risk)
                # Ensure score is at least 5 (High Risk threshold is 3)
                score = 5 
                
            else:
                # --- NLP DETECTED SAFE (LABEL_0) ---
                reasons.append(f"NLP: Clean content ({sc:.2f})")
                
                # FORCE GREEN ZONE (Safe)
                # Ensure score is <= 0 (Green threshold)
                score = -2

    # Final Verdict Calculation
    if score<=0: verdict="SAFE"
    elif score<=2: verdict="MAYBE"
    else: verdict="RISK"
    
    return {"score":score,"verdict":verdict,"reasons":reasons}

# Analysis function
def analyze_bytes(raw_bytes):
    try:
        msg = parse_eml_bytes(raw_bytes)
    except Exception as e:
        return {"ok":False,"error":f"parse failed: {e}"}
    report={}
    report["headers"] = dict(msg.items())
    report["from"], report["return_path"] = get_from_and_return_path(msg)
    report["received_ips"] = extract_received_ips(msg)
    ip = report["received_ips"][0] if report["received_ips"] else None

    try: report["spf"] = spf_check(ip, mail_from=(report["return_path"] or msg.get("From") or None)) if ip else {"ok":False,"error":"No IP"}
    except Exception as e: report["spf"] = {"ok":False,"error":str(e)}
    try: report["dkim"] = dkim_check(raw_bytes)
    except Exception as e: report["dkim"] = {"ok":False,"error":str(e)}

    try:
        from_hdr = report["from"] or ""
        m = re.search(r"<([^>]+@[^>]+)>", from_hdr)
        if m: domain = m.group(1).split("@")[-1]
        else:
            tok = from_hdr.split()[-1] if from_hdr else ""
            domain = tok.split("@")[-1] if "@" in tok else None
        if domain: report["dmarc"] = dmarc_lookup(domain)
        else: report["dmarc"] = {"ok":False,"error":"no domain"}
    except Exception as e: report["dmarc"] = {"ok":False,"error":str(e)}

    try: report["display_spoof"] = detect_display_name_spoof(report["from"])
    except Exception as e: report["display_spoof"] = {"ok":False,"error":str(e)}
    try: report["attachments"] = detect_hidden_attachments(msg)
    except Exception as e: report["attachments"] = {"ok":False,"error":str(e)}

    try:
        from_addr=None; m=re.search(r"<([^>]+@[^>]+)>", report["from"] or "")
        if m: from_addr=m.group(1)
        else:
            if report["from"] and "@" in report["from"]: from_addr = report["from"].strip()
        report["mismatches"]=[]
        if report["return_path"] and from_addr:
            rp = re.sub(r"[<>]","", report["return_path"]).strip()
            if "@" in rp:
                if rp.split("@")[-1].lower() != from_addr.split("@")[-1].lower():
                    report["mismatches"].append({"type":"domain_mismatch"})
    except Exception:
        pass

    subj, body = extract_subject_and_body(msg)
    report["subject"]=subj
    report["body_snippet"]=body[:400]
    report["full_body"]=body
    return {"ok":True,"report":report}

# Flask app
app = Flask(__name__, static_folder='static')
CORS(app) # Enable CORS for extensions

INDEX = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AI Email Forensics</title>
<link rel="icon" type="image/png" href="{{ url_for('static', filename='main.png') }}">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{
  --bg:#f5f7fb; --card:#ffffff; --muted:#64748b; --accent:#0f172a;
  --accent-2: #2563eb; --safe:#16a34a; --warn:#f59e0b; --risk:#ef4444;
  font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
}
*{box-sizing:border-box}
body{margin:0; background:linear-gradient(180deg,var(--bg),#ffffff); color:var(--accent); -webkit-font-smoothing:antialiased; overflow-x: hidden;}
.container{max-width:1150px;margin:28px auto;padding:18px}

.header{display:flex; justify-content: space-between; align-items:center; gap:14px}
.header-left { display:flex; align-items:center; gap:14px; }

.logo{width:60px;height:60px;border-radius:12px;display:flex;align-items:center;justify-content:center;}
.logo img{width:100%;height:100%;}
h1{margin:0;font-size:20px}
.lead{margin:0;color:var(--muted);font-size:13px}

/* Landing Page Styles */
#landing-screen {
  position: fixed; top: 0; left: 0; width: 100%; height: 100vh;
  background: linear-gradient(135deg, #f0f4f8 0%, #ffffff 100%);
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  z-index: 9999; transition: opacity 0.6s ease-out;
  overflow: hidden; 
}
.landing-content { text-align: center; animation: fadeIn 0.8s ease-out; display:flex; flex-direction:column; align-items:center; z-index: 10; position:relative; }
.landing-logo-big { 
  width: 140px; height: 140px; margin-bottom: 24px; border-radius: 24px; 
  box-shadow: 0 20px 40px rgba(0,0,0,0.08); 
  display: flex; align-items: center; justify-content: center; background: white;
}
.landing-logo-big img { width: 100%; height: 100%; object-fit: cover; border-radius: 24px; }
.landing-title { font-size: 48px; font-weight: 900; margin: 0; letter-spacing: -1.5px; color: var(--accent); }
.landing-subtitle { font-size: 16px; color: var(--muted); margin-top: 12px; margin-bottom: 40px; letter-spacing: 3px; text-transform: uppercase; font-weight: 600; }
.btn-enter { 
  background: var(--accent-2); color: white; padding: 16px 48px; font-size: 18px; 
  border-radius: 99px; border: none; cursor: pointer; font-weight: 700;
  box-shadow: 0 10px 25px rgba(37, 99, 235, 0.3);
  transition: all 0.2s ease;
}
.btn-enter:hover { transform: translateY(-3px); box-shadow: 0 15px 35px rgba(37, 99, 235, 0.4); }

/* Background Watermark */
.bg-watermark {
    position: absolute;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    width: 80vh; height: 80vh; 
    opacity: 0.04;  
    pointer-events: none;
    z-index: 0;
    background-image: url("{{ url_for('static', filename='main.png') }}");
    background-repeat: no-repeat;
    background-position: center;
    background-size: contain;
}

@keyframes fadeIn { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }

/* App Styles */
#app-interface { display: none; opacity: 0; transition: opacity 0.8s ease-in; }

.grid{display:grid;grid-template-columns:1fr 380px;gap:18px;margin-top:18px}
.panel{background:var(--card);border-radius:12px;padding:14px;box-shadow:0 8px 24px rgba(2,6,23,0.04);border:1px solid rgba(2,6,23,0.03)}
.controls{display:flex;gap:8px;flex-wrap:wrap}
.btn{background:var(--accent-2);color:white;padding:8px 12px;border-radius:10px;border:none;cursor:pointer;font-weight:600}
.btn.alt{background:transparent;border:1px solid rgba(37,99,235,0.12);color:var(--accent)}
.btn.alt:hover{background:rgba(37,99,235,0.05);}

.filebox{display:inline-block;padding:8px 10px;border-radius:10px;border:1px dashed rgba(2,6,23,0.06);background:linear-gradient(180deg, rgba(15,23,42,0.02), rgba(15,23,42,0.01));color:var(--muted);cursor:pointer}
.small{font-size:13px;color:var(--muted)}

textarea, pre {
    width:100%;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, "Roboto Mono", monospace;
    font-size:13px;
    border-radius:10px;
    border:1px solid rgba(2,6,23,0.04);
    padding:10px;
    background:#fbfdff;
    color:#071529;
    /* Stability Fixes */
    word-break: break-all;
    white-space: pre-wrap;
    overflow-y: auto;
}

.report{
    margin-top:12px;
    max-height:420px;
    overflow-y:auto; 
    border-radius:10px;
    padding:10px;
    background:#fcfdff;
    border:1px solid rgba(2,6,23,0.03);
}

.footer{margin-top:14px;color:var(--muted);font-size:13px;text-align:center}

/* Loading Overlay */
#loading-overlay {
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(255,255,255,0.8);
    backdrop-filter: blur(2px);
    display: none; align-items: center; justify-content: center;
    flex-direction: column;
    z-index: 10000;
}
.spinner {
    width: 40px; height: 40px; border: 4px solid #e2e8f0; border-top: 4px solid var(--accent-2);
    border-radius: 50%; animation: spin 1s linear infinite;
}
@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }

/* --- SPEEDOMETER STYLES --- */
.gauge-container {
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 20px 0;
}

.gauge {
    position: relative;
    width: 220px;
    height: 110px; /* Half of width */
    overflow: hidden;
}

.gauge-bg {
    width: 220px;
    height: 220px;
    background: conic-gradient(from 270deg, #16a34a 0deg, #f59e0b 90deg, #ef4444 180deg, transparent 180deg);
    border-radius: 50%;
    position: absolute;
    top: 0; left: 0;
}

.gauge-mask {
    width: 180px;
    height: 180px;
    background: var(--card); /* Match card background to create donut */
    border-radius: 50%;
    position: absolute;
    top: 20px; left: 20px;
    z-index: 1;
}

.gauge-needle {
    position: absolute;
    bottom: 0;
    left: 50%;
    width: 4px;
    height: 100px;
    background: #0f172a;
    transform-origin: bottom center;
    transform: rotate(-90deg); /* Start at far left */
    transition: transform 1.2s cubic-bezier(0.25, 1, 0.5, 1);
    z-index: 2;
    border-radius: 4px;
}
.gauge-needle::after {
    content: '';
    position: absolute;
    bottom: -6px; left: -6px;
    width: 16px; height: 16px;
    background: #0f172a;
    border-radius: 50%;
}

.gauge-score {
    position: absolute;
    bottom: 0;
    left: 50%;
    transform: translateX(-50%);
    font-size: 32px;
    font-weight: 800;
    z-index: 3;
    color: var(--accent);
}

.gauge-labels {
    width: 220px;
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    color: var(--muted);
    font-weight: 600;
    margin-top: 4px;
}

aside .verdict-wrap{display:flex;gap:12px;align-items:center}
.badge{padding:10px 12px;border-radius:10px;font-weight:800;display:inline-block;color:white}
.badge.safe{background:var(--safe)}
.badge.maybe{background:var(--warn); color:#081124}
.badge.risk{background:var(--risk)}
.meta{display:flex;flex-direction:column;gap:8px;margin-top:12px}
.pill{display:inline-block;padding:8px 10px;border-radius:999px;background:linear-gradient(180deg,#fcfeff,#fbfdff);border:1px solid rgba(2,6,23,0.03);color:var(--muted);font-weight:600}

.stat-grid{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.stat{min-width:120px;padding:10px;border-radius:10px;background:linear-gradient(180deg,#fff,#fbfdff);border:1px solid rgba(2,6,23,0.03);display:flex;flex-direction:column;gap:6px}
.stat .k{font-size:12px;color:var(--muted)}
.stat .v{font-weight:700;color:var(--accent-2)}


/* responsive */
@media (max-width:980px){
  .grid{grid-template-columns:1fr}
  .header{flex-direction:column; align-items:flex-start;}
  .btn.alt.nav{width:100%;}
}
</style>
</head>
<body>

<!-- Loading Overlay -->
<div id="loading-overlay">
    <div class="spinner"></div>
    <div style="margin-top:15px; font-weight:600; color:#0f172a;">Processing large file...</div>
</div>

<!-- Landing Screen -->
<div id="landing-screen">
  <div class="bg-watermark"></div>
  <div class="landing-content">
    <div class="landing-logo-big">
      <img src="{{ url_for('static', filename='main.png') }}" alt="Logo">
    </div>
    <h1 class="landing-title">SILENTCELL</h1>
    <div class="landing-subtitle">UNCOVER THE UNSEEN</div>
    <button class="btn-enter" id="enterBtn">INITIALIZE ANALYSIS</button>
  </div>
</div>

<!-- Main App -->
<div id="app-interface">
  <div class="container">
    <div class="header">
      <div class="header-left">
          <div class="logo" aria-hidden="true">
              <img src="{{ url_for('static', filename='main.png') }}" alt="Logo">
          </div>
          <div>
            <h1>SILENTCELL</h1>
            <p class="lead">BYTEBREACH FORENSICS DASHBOARD</p>
          </div>
      </div>
      <button class="btn alt nav" id="backBtn">Back to Home</button>
    </div>

    <div class="grid">
      <div>
        <div class="panel">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <div class="small">Input</div>
              <strong>Upload .eml or paste raw message</strong>
            </div>
            <div class="controls">
              <label class="filebox">
                <input id="file-eml" type="file" accept=".eml" style="display:none">
                Upload .eml
              </label>
              <label class="filebox">
                <input id="file-pcap" type="file" accept=".pcap,.pcapng" style="display:none">
                Upload pcap
              </label>
              <button class="btn" id="runBtn">Analyze</button>
            </div>
          </div>

          <div style="margin-top:12px">
            <div class="small">Raw message</div>
            <textarea id="raw" rows="12" placeholder="Paste raw RFC822 message or upload .eml"></textarea>
            <div style="display:flex;gap:8px;margin-top:10px;align-items:center">
              <button class="btn alt" id="clearBtn">Clear</button>
              <div class="small" id="nlpStatus">{{ nlp_status }}</div>
            </div>
            <div style="margin-top:10px" id="fileStatus" class="small"></div>
          </div>
        </div>

        <div class="panel" style="margin-top:14px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div><strong>Detailed Report</strong><div class="small">Full analysis output</div></div>
            <div>
              <button class="btn alt" id="exportBtn">Export</button>
            </div>
          </div>
          <pre id="report" class="report">No analysis performed yet.</pre>
        </div>
      </div>

      <aside>
        <div class="panel">
          <div class="gauge-container">
            <div style="margin-bottom:15px; text-align:center;">
                <div class="small">Risk Analysis</div>
                <strong style="font-size:16px">Threat Score</strong>
            </div>
            <div class="gauge">
                <div class="gauge-bg"></div>
                <div class="gauge-mask"></div>
                <div class="gauge-needle" id="gaugeNeedle"></div>
                <div class="gauge-score" id="gaugeScoreText">--</div>
            </div>
            <div class="gauge-labels">
                <span>SAFE</span>
                <span style="transform:translateX(5px)">RISK</span>
            </div>
          </div>

          <div style="display:flex;justify-content:space-between;align-items:center;margin-top:20px; border-top:1px solid #eee; padding-top:15px">
            <div class="meta">
              <div id="fromEl" class="small">From: N/A</div>
              <div id="rpEl" class="small">Return-Path: N/A</div>
              <div id="ipsEl" class="small">IPs: N/A</div>
            </div>
            <div>
              <div id="badge" class="badge maybe">NO DATA</div>
            </div>
          </div>

          <div style="margin-top:12px">
            <div class="small">Checks</div>
            <div class="stat-grid">
              <div class="stat"><div class="k">SPF</div><div id="spfVal" class="v">N/A</div></div>
              <div class="stat"><div class="k">DKIM</div><div id="dkimVal" class="v">N/A</div></div>
              <div class="stat"><div class="k">DMARC</div><div id="dmarcVal" class="v">N/A</div></div>
            </div>
          </div>

          <div style="margin-top:12px">
            <div class="small">NLP Analysis</div>
            <div style="margin-top:8px"><span id="nlpVal" class="pill">NLP: not run</span></div>
             <div class="small" style="margin-top: 6px;">Model Accuracy: {{ model_accuracy }}</div>
          </div>

          <div style="margin-top:12px">
            <div class="small">Recommendation</div>
            <div style="margin-top:8px;border-radius:8px;padding:10px;background:linear-gradient(180deg,#fff,#fbfdff);border:1px solid rgba(2,6,23,0.03)" id="recommend">
              No assessment yet.
            </div>
          </div>
        </div>
      </aside>
    </div>
    <div class="footer">Local-first • Optional model: {{ model_name }} • scapy available: {{ scapy }}</div>
  </div>
</div>

<script>
const landingScreen = document.getElementById('landing-screen');
const appInterface = document.getElementById('app-interface');
const enterBtn = document.getElementById('enterBtn');
const backBtn = document.getElementById('backBtn');
const loadingOverlay = document.getElementById('loading-overlay');

enterBtn.addEventListener('click', () => {
  landingScreen.style.opacity = '0';
  setTimeout(() => {
    landingScreen.style.display = 'none';
    appInterface.style.display = 'block';
    void appInterface.offsetWidth;
    appInterface.style.opacity = '1';
  }, 600);
});

backBtn.addEventListener('click', () => {
  appInterface.style.opacity = '0';
  setTimeout(() => {
    appInterface.style.display = 'none';
    landingScreen.style.display = 'flex';
    void landingScreen.offsetWidth;
    landingScreen.style.opacity = '1';
  }, 600);
});

const fileEml = document.getElementById('file-eml');
const filePcap = document.getElementById('file-pcap');
const raw = document.getElementById('raw');
const runBtn = document.getElementById('runBtn');
const clearBtn = document.getElementById('clearBtn');
const reportEl = document.getElementById('report');
const badge = document.getElementById('badge');
const gaugeNeedle = document.getElementById('gaugeNeedle');
const gaugeScoreText = document.getElementById('gaugeScoreText');
const fromEl = document.getElementById('fromEl');
const rpEl = document.getElementById('rpEl');
const ipsEl = document.getElementById('ipsEl');
const spfVal = document.getElementById('spfVal');
const dkimVal = document.getElementById('dkimVal');
const dmarcVal = document.getElementById('dmarcVal');
const nlpVal = document.getElementById('nlpVal');
const recommend = document.getElementById('recommend');
const exportBtn = document.getElementById('exportBtn');
const fileStatus = document.getElementById('fileStatus');
let lastPayload = null;

document.querySelectorAll('.filebox').forEach((lbl, idx) => {
  const inp = lbl.querySelector('input');
  if(!inp){
    const hidden = document.createElement('input');
    hidden.type='file'; hidden.style.display='none';
    if (idx===0) hidden.accept='.eml';
    else hidden.accept='.pcap,.pcapng';
    lbl.appendChild(hidden);
    hidden.addEventListener('change', onFileChange);
    return;
  }
  inp.addEventListener('change', onFileChange);
});

function onFileChange(evt){
  const f = evt.target.files[0];
  if(!f) return;
  fileStatus.textContent = `Loaded ${f.name} — ${(f.size/1024).toFixed(1)} KB`;
  if (f.name.toLowerCase().endsWith('.eml')){
    // Limit raw text display to 500KB to prevent browser freeze on load
    if(f.size > 500000) {
        raw.value = "File too large to display raw content preview. Click Analyze to process.";
    } else {
        f.arrayBuffer().then(buf=>{
          raw.value = new TextDecoder('utf-8',{fatal:false}).decode(buf);
        });
    }
  }
}

document.getElementById('file-pcap')?.addEventListener('change', (e)=>{ fileStatus.textContent = 'PCAP attached'; });

clearBtn.addEventListener('click', ()=>{ 
    raw.value=''; reportEl.textContent='No analysis performed yet.'; fileStatus.textContent='';
    resetGauge();
});

function resetGauge() {
    gaugeNeedle.style.transform = 'rotate(-90deg)';
    gaugeScoreText.textContent = '--';
    badge.textContent = 'NO DATA';
    badge.className = 'badge maybe';
}

runBtn.addEventListener('click', async ()=>{
  runBtn.disabled = true;
  loadingOverlay.style.display = 'flex'; // SHOW LOADING
  reportEl.textContent = 'Analyzing…';
  
  try{
    const fd = new FormData();
    fd.append('raw', new Blob([raw.value || ''], {type:'text/plain'}), 'raw.txt');
    const pcapInput = document.getElementById('file-pcap');
    if (pcapInput && pcapInput.files && pcapInput.files[0]) fd.append('pcap', pcapInput.files[0]);
    
    const resp = await fetch('/analyze',{method:'POST',body:fd});
    const j = await resp.json();
    
    loadingOverlay.style.display = 'none'; // HIDE LOADING
    
    if(!j.ok){ reportEl.textContent = 'Error: '+(j.error||'unknown'); runBtn.disabled=false; return; }
    lastPayload = j;
    const a = j.assessment || {verdict:'NO DATA',score:0,reasons:[]};
    updateGaugeAndBadge(a.score, a.verdict);
    fromEl.textContent = 'From: ' + (j.report.from || 'N/A');
    rpEl.textContent = 'Return-Path: ' + (j.report.return_path || 'N/A');
    ipsEl.textContent = 'IPs: ' + ((j.report.received_ips && j.report.received_ips.join(', ')) || 'N/A');
    spfVal.textContent = j.report.spf && j.report.spf.result ? j.report.spf.result : (j.report.spf && j.report.spf.error) || 'N/A';
    dkimVal.textContent = j.report.dkim && j.report.dkim.verified ? 'OK' : (j.report.dkim && j.report.dkim.error) || 'FAIL';
    dmarcVal.textContent = j.report.dmarc && j.report.dmarc.policy ? (j.report.dmarc.policy.p || 'none') : (j.report.dmarc && j.report.dmarc.error) || 'N/A';
    nlpVal.textContent = j.nlp && j.nlp.ok ? (j.nlp.label + ' ' + (j.nlp.score||'')) : (j.nlp && j.nlp.error) || 'not run';
    recommend.textContent = a.verdict === 'SAFE' ? 'Looks safe — still exercise caution with unexpected content.' : (a.verdict === 'MAYBE' ? 'Verify sender by independent channel before interacting.' : 'High risk — do NOT click links or open attachments.');
    reportEl.textContent = prettyReportText(j);
  }catch(e){
    loadingOverlay.style.display = 'none';
    reportEl.textContent = 'Analysis error: '+(e.message||e);
  }
  runBtn.disabled=false;
});

function updateGaugeAndBadge(score, verdict){
  let pct = 0;
  if (score <= 0) pct = 10;
  else if (score <= 2) pct = 45;
  else pct = Math.min(100, 70 + (score - 3) * 10);
  const deg = (pct / 100 * 180) - 90;
  gaugeNeedle.style.transform = `rotate(${deg}deg)`;
  gaugeScoreText.textContent = pct.toFixed(0);
  badge.textContent = verdict;
  badge.className = 'badge ' + (verdict==='SAFE' ? 'safe' : verdict==='MAYBE' ? 'maybe' : 'risk');
}

function prettyReportText(j){
  try{
    const r = j.report; const a = j.assessment;
    let lines=[];
    lines.push(`Verdict: ${a.verdict} | Score: ${a.score}`);
    lines.push('');
    lines.push('From: ' + (r.from || 'N/A'));
    lines.push('Return-Path: ' + (r.return_path || 'N/A'));
    lines.push('Received IPs: ' + ((r.received_ips && r.received_ips.join(', ')) || 'N/A'));
    lines.push('');
    lines.push('SPF: ' + (r.spf && (r.spf.result || r.spf.error) || 'N/A'));
    lines.push('DKIM: ' + (r.dkim && (r.dkim.verified ? 'OK' : r.dkim.error) || 'N/A'));
    lines.push('DMARC: ' + (r.dmarc && (r.dmarc.record || r.dmarc.error) || 'N/A'));
    lines.push('');
    lines.push('Heuristics:');
    if (r.display_spoof && r.display_spoof.ok){
      lines.push(' - Display suspicious: ' + (r.display_spoof.suspicious ? (r.display_spoof.reasons||[]).join('; '): 'no'));
    } else lines.push(' - Display check: ' + (r.display_spoof && r.display_spoof.error || 'N/A'));
    lines.push(' - Attachments: ' + ((r.attachments && r.attachments.findings && r.attachments.findings.length) ? JSON.stringify(r.attachments.findings) : 'None flagged'));
    lines.push('');
    lines.push('NLP: ' + (j.nlp && (j.nlp.label ? j.nlp.label + ' ' + (j.nlp.score||'') : j.nlp.error) || 'not run'));
    lines.push('');
    lines.push('Reasons:');
    (a.reasons||[]).forEach(x=>lines.push(' - '+x));
    lines.push('');
    lines.push('Subject: ' + (r.subject||''));
    lines.push('');
    
    // --- STABILITY FIX: TRUNCATE PREVIEW ---
    let fullBody = r.full_body || '';
    if(fullBody.length > 3000) {
        fullBody = fullBody.substring(0, 3000) + '\n\n... [TEXT TRUNCATED FOR UI PERFORMANCE. SEE EXPORT FOR FULL CONTENT] ...';
    }
    
    lines.push('Message snippet:\n' + fullBody);
    return lines.join('\\n');
  }catch(e){
    return JSON.stringify(j,null,2);
  }
}

exportBtn.addEventListener('click', async () => {
    if (!lastPayload) {
        alert('No report to export');
        return;
    }
    try {
        const resp = await fetch('/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(lastPayload)
        });

        if (!resp.ok) {
            const errorData = await resp.json();
            alert('Export failed: ' + (errorData.error || 'Unknown server error'));
            return;
        }

        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'forensic_report.pdf';
        document.body.appendChild(a);
        a.click();

        setTimeout(() => {
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }, 100);

    } catch (e) {
        console.error("Export error:", e);
        alert('Export failed: An unexpected error occurred.');
    }
});
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(
        INDEX,
        model_name=MODEL_NAME,
        model_accuracy=MODEL_ACCURACY,
        scapy=str(HAVE_SCAPY),
        nlp_status=nlp_load_status
    )

@app.route("/analyze", methods=["POST"])
def route_analyze():
    raw_bytes = None
    if "raw" in request.files:
        raw_bytes = request.files["raw"].read()
    else:
        text = request.form.get("raw") or request.get_data(as_text=True) or ""
        raw_bytes = text.encode("utf-8", errors="ignore")

    if 'pcap' in request.files and HAVE_SCAPY:
        try:
            pcapf = request.files['pcap']
            bio = io.BytesIO(pcapf.read())
            pkts = rdpcap(bio)
            streams = {}
            for p in pkts:
                try:
                    if p.haslayer("TCP") and p.haslayer("Raw") and p.haslayer("IP"):
                        sport=int(p["TCP"].sport); dport=int(p["TCP"].dport)
                        if sport in (25,587) or dport in (25,587):
                            k=(p["IP"].src, p["IP"].dst, sport, dport)
                            streams.setdefault(k,b"")
                            streams[k]+=bytes(p["Raw"].load)
                except Exception:
                    continue
            cand=None; maxl=0
            for k,v in streams.items():
                if len(v)>maxl: maxl=len(v); cand=v
            if cand and (not raw_bytes or len(raw_bytes)<30):
                raw_bytes = cand
        except Exception:
            pass

    if not raw_bytes:
        return jsonify(ok=False, error="No data provided")

    res = analyze_bytes(raw_bytes)
    if not res.get("ok"):
        return jsonify(ok=False, error=res.get("error"))
    report = res["report"]

    nlp_res = None
    if nlp_pipeline is not None:
        try:
            text = (report.get("subject","") + "\n\n" + report.get("full_body","")).strip()
            nlp_res = nlp_classify(text)
        except Exception as e:
            nlp_res = {"ok":False,"error":str(e)}

    assessment = compute_risk(report, nlp_result=nlp_res)
    out = {"ok":True,"report":report,"nlp":nlp_res,"assessment":assessment}
    return jsonify(out)

class PDF(FPDF):
    def header(self):
        # --- CUSTOM LOGO ---
        # Look for static/main.png
        logo_path = os.path.join(app.static_folder, 'logo 1.png')
        if os.path.exists(logo_path):
            self.image(logo_path, 10, 8, 30) # x=10, y=8, width=25
        
        # --- CUSTOM NAME / TITLE ---
        self.set_font('Arial', 'B', 16)
        # Move to the right so we don't write over the logo
        self.cell(0, 10, 'SILENTCELL FORENSICS', 0, 1, 'C') 
        
        self.set_font('Arial', 'I', 10)
        self.cell(0, 5, 'UNCOVER THE UNSEEN', 0, 1, 'C')
        
        self.set_font('Arial', 'I', 10)
        self.cell(0, 5, 'Automated Email Analysis Report', 0, 1, 'C')
        
        # Line break to separate header from content
        self.ln(15) 

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 11)
        self.set_fill_color(240, 240, 240) # Light gray background for titles
        # cell(w, h, txt, border, ln, align, fill)
        self.cell(0, 8, f"  {title}", 0, 1, 'L', 1) 
        # Removed large ln() here to reduce space

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        # multi_cell(w, h, txt) -> h=5 is "Single Spacing" (Compact)
        self.multi_cell(0, 5, body)
        self.ln(3) # Small gap after section

    def add_report_section(self, title, data):
        self.chapter_title(title)
        self.chapter_body(data)

def sanitize_for_pdf(text):
    if not isinstance(text, str):
        text = str(text)
    return text.encode('latin-1', 'replace').decode('latin-1')

@app.route("/export", methods=["POST"])
def route_export():
    try:
        payload = request.get_json(force=True)
        if not payload:
            return jsonify(ok=False, error="no payload"), 400

        r = payload.get("report", {})
        a = payload.get("assessment", {})

        pdf = PDF()
        pdf.add_page()
        
        pdf.add_report_section("Verdict", sanitize_for_pdf(f"Verdict: {a.get('verdict')} | Score: {a.get('score')}"))
        pdf.add_report_section("From", sanitize_for_pdf(r.get("from")))
        pdf.add_report_section("Return-Path", sanitize_for_pdf(r.get("return_path")))
        pdf.add_report_section("Received IPs", sanitize_for_pdf(", ".join(r.get("received_ips", []) or ["N/A"])))
        pdf.add_report_section("SPF", sanitize_for_pdf(r.get("spf", {}).get("result") or r.get("spf", {}).get("error", "N/A")))
        dkim_status = str(r.get("dkim", {}).get("verified")) if r.get("dkim", {}).get("ok") else r.get("dkim", {}).get("error", "N/A")
        pdf.add_report_section("DKIM", sanitize_for_pdf(dkim_status))
        pdf.add_report_section("DMARC", sanitize_for_pdf(r.get("dmarc", {}).get("record") or r.get("dmarc", {}).get("error", "N/A")))

        reasons = "\n".join([f"- {reason}" for reason in a.get("reasons", [])])
        pdf.add_report_section("Reasons", sanitize_for_pdf(reasons))

        pdf.add_report_section("Subject", sanitize_for_pdf(r.get("subject") or ""))
        pdf.add_report_section("Body snippet", sanitize_for_pdf(r.get("full_body") or ""))
        
        pdf_bytes = pdf.output(dest='S').encode('latin-1')
        
        return send_file(
            io.BytesIO(pdf_bytes),
            as_attachment=True,
            download_name="forensic_report.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

if __name__ == "__main__":
    print("Attempting to load NLP model on startup...")
    load_nlp_model()
    print(nlp_load_status)
    print("Starting Flask application...")
    app.run(debug=True, port=5000)