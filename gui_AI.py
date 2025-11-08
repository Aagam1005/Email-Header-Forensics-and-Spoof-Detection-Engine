# #!/usr/bin/env python3
# """
# Email Header Forensics & Spoof Detection Engine with local NLP phishing detector.

# - Rule-based header checks (SPF/DKIM/DMARC heuristics)
# - Attachment heuristics
# - Optional pcap parsing (scapy)
# - Local NLP phishing detector (Hugging Face transformers)
#     * Model used: mrm8488/bert-tiny-finetuned-sms-spam-detection
#     * LABEL_1 => treated as 'spam' (RISK), LABEL_0 => 'ham' (SAFE)
# - GUI built with tkinter / ttk
# - Defensive: features gracefully degrade if optional libraries are missing
# """

# import os
# import re
# import sys
# import tkinter as tk
# from tkinter import filedialog, messagebox, scrolledtext, ttk
# from email import policy
# from email.parser import BytesParser, Parser
# from email.message import EmailMessage

# # Optional imports
# HAVE_DKIM = HAVE_SPF = HAVE_DNS = HAVE_SCAPY = HAVE_TRANSFORMERS = False
# try:
#     import dkim
#     HAVE_DKIM = True
# except Exception:
#     HAVE_DKIM = False

# try:
#     import spf
#     HAVE_SPF = True
# except Exception:
#     HAVE_SPF = False

# try:
#     import dns.resolver
#     HAVE_DNS = True
# except Exception:
#     HAVE_DNS = False

# try:
#     from scapy.all import rdpcap
#     HAVE_SCAPY = True
# except Exception:
#     HAVE_SCAPY = False

# # Transformers (NLP)
# MODEL_NAME = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
# nlp_pipeline = None
# try:
#     from transformers import pipeline, AutoConfig
#     # Lazy-load pipeline later to avoid long startup time
#     HAVE_TRANSFORMERS = True
# except Exception:
#     HAVE_TRANSFORMERS = False

# # ---------------- regex / constants ----------------
# RECEIVED_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
# DOUBLE_EXT_RE = re.compile(r"\.(\w+)\.(exe|scr|bat|com|js|vbs|docm|xlsm|jar)$", re.IGNORECASE)
# SUSPICIOUS_EXT = {"exe", "scr", "bat", "com", "js", "vbs", "docm", "xlsm", "jar"}

# # ---------------- email parsing helpers ----------------
# def parse_eml_bytes(data: bytes) -> EmailMessage:
#     """Parse raw email bytes into EmailMessage object (robust with fallbacks)."""
#     try:
#         return BytesParser(policy=policy.default).parsebytes(data)
#     except Exception:
#         text = data.decode("utf-8", errors="ignore")
#         return Parser(policy=policy.default).parsestr(text)

# def extract_received_ips(msg: EmailMessage) -> list:
#     rcvd = msg.get_all("Received") or []
#     ips = []
#     for header in rcvd:
#         found = RECEIVED_IP_RE.findall(header)
#         for ip in found:
#             parts = ip.split(".")
#             try:
#                 if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
#                     ips.append(ip)
#             except Exception:
#                 pass
#     # Received headers typically newest-first; return earliest-first for originating IP
#     if ips:
#         return list(reversed(ips))
#     return ips

# def get_from_and_return_path(msg: EmailMessage) -> tuple:
#     from_hdr = msg.get("From")
#     ret = msg.get("Return-Path") or msg.get("Envelope-From") or None
#     return from_hdr, ret

# def extract_subject_and_body(msg: EmailMessage) -> tuple:
#     """Return (subject, body_text). Body is plain text aggregated from parts; falls back to html stripped if needed."""
#     subject = msg.get("Subject", "")
#     body_parts = []
#     if msg.is_multipart():
#         for part in msg.walk():
#             ctype = part.get_content_type()
#             disp = str(part.get_content_disposition() or "")
#             if disp == "attachment":
#                 continue
#             if ctype == "text/plain":
#                 try:
#                     text = part.get_content()
#                 except Exception:
#                     try:
#                         text = part.get_payload(decode=True).decode("utf-8", errors="ignore")
#                     except Exception:
#                         text = ""
#                 body_parts.append(text)
#             elif ctype == "text/html" and not body_parts:
#                 # fallback to html (strip tags minimally)
#                 try:
#                     html = part.get_content()
#                 except Exception:
#                     try:
#                         html = part.get_payload(decode=True).decode("utf-8", errors="ignore")
#                     except Exception:
#                         html = ""
#                 # naive strip tags
#                 text = re.sub(r"<[^>]+>", " ", html)
#                 body_parts.append(text)
#     else:
#         ctype = msg.get_content_type()
#         if ctype in ("text/plain", "text/html"):
#             try:
#                 body = msg.get_content()
#             except Exception:
#                 try:
#                     body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
#                 except Exception:
#                     body = ""
#             if ctype == "text/html":
#                 body = re.sub(r"<[^>]+>", " ", body)
#             body_parts.append(body)
#     body_text = "\n\n".join(p for p in body_parts if p)
#     return subject or "", body_text or ""

# # ---------------- SPF / DKIM / DMARC wrappers ----------------
# def spf_check(ip: str, mail_from: str = None, helo: str = None) -> dict:
#     if not HAVE_SPF:
#         return {"ok": False, "error": "pyspf not installed"}
#     try:
#         if mail_from is None:
#             mail_from = "-"
#         if helo is None:
#             helo = "unknown"
#         res = spf.check2(i=ip, s=mail_from, h=helo)
#         return {"ok": True, "result": res[0], "explanation": res[1], "spf_record": res[2]}
#     except Exception as e:
#         return {"ok": False, "error": str(e)}

# def dkim_check(raw_bytes: bytes) -> dict:
#     if not HAVE_DKIM:
#         return {"ok": False, "error": "dkimpy not installed"}
#     try:
#         verified = dkim.verify(raw_bytes)
#         return {"ok": True, "verified": bool(verified)}
#     except Exception as e:
#         return {"ok": False, "error": str(e)}

# def dmarc_lookup(domain: str) -> dict:
#     if not HAVE_DNS:
#         return {"ok": False, "error": "dnspython not installed"}
#     try:
#         qname = f"_dmarc.{domain}"
#         answers = dns.resolver.resolve(qname, "TXT")
#         txts = [b"".join(r.strings).decode("utf-8") for r in answers]
#         txt = " ".join(txts)
#         policy = {}
#         for part in [p.strip() for p in txt.split(";") if p.strip()]:
#             if "=" in part:
#                 k, v = part.split("=", 1)
#                 policy[k.lower()] = v
#         return {"ok": True, "record": txt, "policy": policy}
#     except Exception as e:
#         return {"ok": False, "error": str(e)}

# # ---------------- heuristics ----------------
# def detect_display_name_spoof(from_header: str) -> dict:
#     if not from_header:
#         return {"ok": False, "error": "No From header"}
#     m = re.match(r"\s*([^<]+)\s*<(.+@.+)>", from_header)
#     if m:
#         display = m.group(1).strip(' "')
#         addr = m.group(2)
#         dom = addr.split("@")[-1].lower()
#         words = re.findall(r"[A-Za-z]{3,}", display)
#         suspicious = False
#         reasons = []
#         for w in words:
#             if w.lower() in dom:
#                 continue
#             if len(w) >= 4 and w[0].isupper():
#                 suspicious = True
#                 reasons.append(f"Display name contains '{w}' but email domain is '{dom}'")
#         return {"ok": True, "suspicious": suspicious, "reasons": reasons, "display": display, "addr": addr}
#     else:
#         return {"ok": True, "suspicious": False, "reason": "No display name / simple address"}

# def detect_hidden_attachments(msg: EmailMessage) -> dict:
#     findings = []
#     if msg.is_multipart():
#         for part in msg.iter_attachments():
#             filename = part.get_filename()
#             ctype = part.get_content_type()
#             if filename:
#                 if DOUBLE_EXT_RE.search(filename):
#                     findings.append({"type": "double_ext", "filename": filename, "detail": "Double extension"})
#                 ext = os.path.splitext(filename)[1].lower().lstrip(".")
#                 if ext in SUSPICIOUS_EXT:
#                     findings.append({"type": "suspicious_ext", "filename": filename, "detail": f"Executable extension .{ext}"})
#             else:
#                 findings.append({"type": "no_filename", "detail": f"Attachment with content-type {ctype} has no filename"})
#             if ctype in ("application/x-msdownload", "application/x-dosexec") or ctype.startswith("application/x-"):
#                 findings.append({"type": "suspicious_ctype", "filename": filename, "ctype": ctype})
#     else:
#         cd = msg.get("Content-Disposition")
#         if cd and "attachment" in cd.lower():
#             filename = re.search(r'filename="?([^";]+)"?', cd)
#             fname = filename.group(1) if filename else None
#             findings.append({"type": "singlepart_attach", "filename": fname, "detail": "Singlepart attachment-like header"})
#     return {"ok": True, "findings": findings}

# # ---------------- NLP model loader & classifier ----------------
# def load_nlp_model():
#     """Attempt to load the transformers pipeline. Returns (pipeline or None, message)."""
#     global nlp_pipeline
#     if not HAVE_TRANSFORMERS:
#         return None, "transformers library not installed"
#     try:
#         # Create a text-classification pipeline; we avoid setting device so it uses CPU unless torch/cuda specifies GPU.
#         nlp_pipeline = pipeline("text-classification", model=MODEL_NAME, truncation=True)
#         return nlp_pipeline, f"Loaded model {MODEL_NAME}"
#     except Exception as e:
#         nlp_pipeline = None
#         return None, f"Failed to load model: {e}"

# def nlp_classify(text: str) -> dict:
#     """Classify text using the loaded pipeline. Returns dict with label and score."""
#     if nlp_pipeline is None:
#         return {"ok": False, "error": "NLP model not loaded"}
#     # minimal length guard
#     if not text or len(text.strip()) == 0:
#         return {"ok": True, "label": "LABEL_0", "score": 0.0, "note": "empty text"}
#     try:
#         res = nlp_pipeline(text if len(text) < 2000 else text[:2000])  # pipeline returns list
#         if not res or not isinstance(res, list):
#             return {"ok": False, "error": "Unexpected model output"}
#         out = res[0]
#         # out example: {'label': 'LABEL_1', 'score': 0.95}
#         return {"ok": True, "label": out.get("label"), "score": float(out.get("score", 0.0))}
#     except Exception as e:
#         return {"ok": False, "error": str(e)}

# # ---------------- scoring & combining ----------------
# def compute_risk(report: dict, nlp_result: dict = None) -> dict:
#     """Combine header heuristics and optional NLP result to produce a score and verdict."""
#     score = 0
#     reasons = []

#     # SPF
#     spf = report.get("spf", {})
#     if spf.get("ok") and spf.get("result"):
#         rf = spf.get("result").lower()
#         if rf == "pass":
#             reasons.append("SPF passed")
#             score -= 1
#         elif rf in ("neutral", "none"):
#             reasons.append(f"SPF: {rf}")
#         else:
#             reasons.append(f"SPF failed: {rf}")
#             score += 2
#     else:
#         reasons.append("SPF unavailable")
#         score += 1

#     # DKIM
#     dkim = report.get("dkim", {})
#     if dkim.get("ok") and dkim.get("verified"):
#         reasons.append("Valid DKIM")
#         score -= 1
#     else:
#         if dkim.get("ok"):
#             reasons.append("DKIM not verified")
#             score += 2
#         else:
#             reasons.append("DKIM unavailable")
#             score += 1

#     # DMARC
#     dmarc = report.get("dmarc", {})
#     if dmarc.get("ok") and dmarc.get("policy"):
#         p = dmarc.get("policy").get("p", "none")
#         reasons.append(f"DMARC policy: {p}")
#         if p == "reject":
#             score -= 1
#         elif p == "quarantine":
#             score += 0
#     else:
#         reasons.append("DMARC missing or lookup failed")
#         score += 1

#     # Heuristics
#     dsp = report.get("display_spoof", {})
#     if dsp.get("ok") and dsp.get("suspicious"):
#         reasons.append("Display-name impersonation likely")
#         score += 2

#     # Attachments
#     att = report.get("attachments", {})
#     if att.get("ok") and att.get("findings"):
#         reasons.append("Suspicious attachments present")
#         score += 2

#     # Mismatch
#     mism = report.get("mismatches", [])
#     if mism:
#         reasons.append("Return-Path/From mismatch")
#         score += 2

#     # NLP result integration (if present)
#     if nlp_result:
#         if not nlp_result.get("ok"):
#             reasons.append("NLP unavailable")
#             score += 0
#         else:
#             label = str(nlp_result.get("label", "LABEL_0"))
#             sc = float(nlp_result.get("score", 0.0))
#             # For the chosen model: LABEL_1 ~ spam, LABEL_0 ~ ham
#             if label.upper() == "LABEL_1":
#                 # spam => increase risk, more if high confidence
#                 reasons.append(f"NLP: spam ({sc:.2f})")
#                 if sc >= 0.85:
#                     score += 3
#                 elif sc >= 0.6:
#                     score += 2
#                 else:
#                     score += 1
#             else:
#                 reasons.append(f"NLP: ham ({sc:.2f})")
#                 # give small safe credit for the NLP clean label
#                 if sc >= 0.9:
#                     score -= 1

#     # Final verdict mapping
#     if score <= 0:
#         verdict = "SAFE"
#     elif score <= 2:
#         verdict = "MAYBE"
#     else:
#         verdict = "RISK"

#     return {"score": score, "verdict": verdict, "reasons": reasons}

# # ---------------- top-level analysis ----------------
# def analyze(raw_bytes: bytes) -> dict:
#     report = {"ok": True, "errors": []}
#     try:
#         msg = parse_eml_bytes(raw_bytes)
#     except Exception as e:
#         return {"ok": False, "error": f"Failed to parse message: {e}"}

#     report["headers"] = dict(msg.items())
#     report["from"], report["return_path"] = get_from_and_return_path(msg)
#     report["received_ips"] = extract_received_ips(msg)

#     # SPF
#     ip = report["received_ips"][0] if report["received_ips"] else None
#     try:
#         report["spf"] = spf_check(ip, mail_from=(report["return_path"] or msg.get("From") or None)) if ip else {"ok": False, "error": "No originating IP found"}
#     except Exception as e:
#         report["spf"] = {"ok": False, "error": str(e)}

#     # DKIM
#     try:
#         report["dkim"] = dkim_check(raw_bytes)
#     except Exception as e:
#         report["dkim"] = {"ok": False, "error": str(e)}

#     # DMARC
#     try:
#         from_hdr = report["from"] or ""
#         m = re.search(r"<([^>]+@[^>]+)>", from_hdr)
#         if m:
#             domain = m.group(1).split("@")[-1]
#         else:
#             tok = from_hdr.split()[-1] if from_hdr else ""
#             domain = tok.split("@")[-1] if "@" in tok else None
#         if domain:
#             report["dmarc"] = dmarc_lookup(domain)
#         else:
#             report["dmarc"] = {"ok": False, "error": "Could not extract domain from From header"}
#     except Exception as e:
#         report["dmarc"] = {"ok": False, "error": str(e)}

#     # Heuristics
#     try:
#         report["display_spoof"] = detect_display_name_spoof(report["from"])
#     except Exception as e:
#         report["display_spoof"] = {"ok": False, "error": str(e)}

#     try:
#         report["attachments"] = detect_hidden_attachments(msg)
#     except Exception as e:
#         report["attachments"] = {"ok": False, "error": str(e)}

#     # Mismatches
#     try:
#         from_addr = None
#         m = re.search(r"<([^>]+@[^>]+)>", report["from"] or "")
#         if m:
#             from_addr = m.group(1)
#         else:
#             if report["from"] and "@" in report["from"]:
#                 from_addr = report["from"].strip()
#         report["mismatches"] = []
#         if report["return_path"] and from_addr:
#             rp = re.sub(r"[<>]", "", report["return_path"]).strip()
#             if "@" in rp:
#                 rp_addr = rp
#                 if rp_addr.split("@")[-1].lower() != from_addr.split("@")[-1].lower():
#                     report["mismatches"].append({"type": "domain_mismatch", "detail": f"Return-Path {rp_addr} domain differs from From {from_addr}"})
#     except Exception:
#         pass

#     # Extract subject/body for NLP
#     subject, body = extract_subject_and_body(msg)
#     report["subject"] = subject
#     report["body_snippet"] = body[:400]  # small snippet for UI

#     return report

# # ---------------- GUI ----------------
# class ForensicsGUI:
#     def __init__(self, root):
#         self.root = root
#         root.title("Email Header Forensics & NLP Phishing Detector")
#         root.geometry("1100x760")

#         # top toolbar
#         toolbar = ttk.Frame(root, padding=8)
#         toolbar.pack(side="top", fill="x")

#         ttk.Button(toolbar, text="Load .eml", command=self.load_eml).pack(side="left")
#         ttk.Button(toolbar, text="Paste", command=self.paste_raw).pack(side="left", padx=6)
#         ttk.Button(toolbar, text="Open pcap", command=self.open_pcap).pack(side="left", padx=6)
#         ttk.Button(toolbar, text="Run analysis", command=self.run_analysis).pack(side="right")
#         ttk.Button(toolbar, text="Export report", command=self.export_report).pack(side="right", padx=6)

#         self.status_var = tk.StringVar(value="No message loaded")
#         ttk.Label(root, textvariable=self.status_var).pack(side="top", fill="x", padx=10)

#         main = ttk.Frame(root)
#         main.pack(fill="both", expand=True, padx=10, pady=8)

#         # left: raw viewer
#         left = ttk.Frame(main)
#         left.pack(side="left", fill="both", expand=True)
#         ttk.Label(left, text="Raw message / headers", font=("Helvetica", 12, "bold")).pack(anchor="w")
#         self.raw_box = scrolledtext.ScrolledText(left, wrap="none", width=80)
#         self.raw_box.pack(fill="both", expand=True, pady=6)

#         # right: analysis & verdict
#         right = ttk.Frame(main, width=420)
#         right.pack(side="right", fill="both")
#         ttk.Label(right, text="Analysis & Verdict", font=("Helvetica", 12, "bold")).pack(anchor="w")

#         # Verdict banner
#         self.verdict_frame = tk.Frame(right, bd=2, relief="groove")
#         self.verdict_frame.pack(fill="x", pady=6)
#         self.verdict_label = tk.Label(self.verdict_frame, text="NO DATA", font=("Helvetica", 18, "bold"), pady=8)
#         self.verdict_label.pack(fill="both")

#         # NLP status
#         self.nlp_status_var = tk.StringVar(value="NLP: Not loaded")
#         ttk.Label(right, textvariable=self.nlp_status_var).pack(anchor="w", padx=4)

#         # indicators row
#         indicators = ttk.Frame(right)
#         indicators.pack(fill="x", pady=4)
#         self.spf_var = tk.StringVar(value="SPF: ?")
#         self.dkim_var = tk.StringVar(value="DKIM: ?")
#         self.dmarc_var = tk.StringVar(value="DMARC: ?")
#         ttk.Label(indicators, textvariable=self.spf_var, width=18).pack(side="left")
#         ttk.Label(indicators, textvariable=self.dkim_var, width=18).pack(side="left")
#         ttk.Label(indicators, textvariable=self.dmarc_var, width=18).pack(side="left")

#         ttk.Label(right, text="NLP Result / Score:", font=("Helvetica", 10, "bold")).pack(anchor="w", pady=(8,0))
#         self.nlp_out = ttk.Label(right, text="N/A")
#         self.nlp_out.pack(anchor="w", padx=4)

#         ttk.Label(right, text="Score & Reasons:", font=("Helvetica", 10, "bold")).pack(anchor="w", pady=(8,0))
#         self.out_box = scrolledtext.ScrolledText(right, wrap="word", height=18)
#         self.out_box.pack(fill="both", expand=True, pady=6)

#         ttk.Label(right, text="Recommendation:", font=("Helvetica", 10, "bold")).pack(anchor="w")
#         self.rec_text = tk.Text(right, height=3, wrap="word")
#         self.rec_text.pack(fill="x")
#         self.rec_text.configure(state="disabled")

#         # internal
#         self.raw_bytes = None
#         self.latest_report = None
#         self.nlp_loaded = False

#         # Try to load model in background-like fashion (but immediate here); handle gracefully
#         self.try_load_nlp_model()

#     def try_load_nlp_model(self):
#         if not HAVE_TRANSFORMERS:
#             self.nlp_status_var.set("NLP: transformers not installed (pip install transformers torch)")
#             self.nlp_loaded = False
#             return
#         # Attempt to load pipeline; errors handled and displayed
#         self.nlp_status_var.set("NLP: loading model (may take a moment)...")
#         self.root.update()
#         pipe, msg = load_nlp_model()
#         if pipe:
#             self.nlp_status_var.set(f"NLP: model loaded ({MODEL_NAME})")
#             self.nlp_loaded = True
#         else:
#             self.nlp_status_var.set(f"NLP load failed: {msg}")
#             self.nlp_loaded = False

#     def set_verdict_banner(self, verdict: str):
#         if verdict == "SAFE":
#             bg = "#2ecc71"; fg = "white"
#         elif verdict == "MAYBE":
#             bg = "#f39c12"; fg = "black"
#         else:
#             bg = "#e74c3c"; fg = "white"
#         self.verdict_label.config(text=verdict, bg=bg, fg=fg)
#         self.verdict_frame.config(bg=bg)

#     def load_eml(self):
#         path = filedialog.askopenfilename(title="Open .eml file", filetypes=[("EML files", "*.eml"), ("All files", "*.*")])
#         if not path:
#             return
#         try:
#             with open(path, "rb") as f:
#                 data = f.read()
#             self.raw_bytes = data
#             try:
#                 text = data.decode("utf-8")
#             except Exception:
#                 text = data.decode("latin1", errors="ignore")
#             self.raw_box.delete("1.0", tk.END)
#             self.raw_box.insert(tk.END, text)
#             self.status_var.set(f"Loaded {os.path.basename(path)}")
#         except Exception as e:
#             messagebox.showerror("Error", f"Failed to load file: {e}")

#     def paste_raw(self):
#         win = tk.Toplevel(self.root)
#         win.title("Paste raw headers/message")
#         txt = scrolledtext.ScrolledText(win, width=100, height=30)
#         txt.pack()
#         def save_and_close():
#             s = txt.get("1.0", tk.END)
#             try:
#                 self.raw_bytes = s.encode("utf-8")
#             except Exception:
#                 self.raw_bytes = s.encode("latin1", errors="ignore")
#             self.raw_box.delete("1.0", tk.END)
#             self.raw_box.insert(tk.END, s)
#             self.status_var.set("Raw message pasted")
#             win.destroy()
#         ttk.Button(win, text="Save", command=save_and_close).pack(pady=6)

#     def open_pcap(self):
#         if not HAVE_SCAPY:
#             messagebox.showwarning("scapy missing", "Scapy not installed (pip install scapy)")
#             return
#         path = filedialog.askopenfilename(title="Open pcap", filetypes=[("pcap files", "*.pcap;*.pcapng"), ("All files", "*.*")])
#         if not path:
#             return
#         try:
#             pkts = rdpcap(path)
#             streams = {}
#             for p in pkts:
#                 if p.haslayer("TCP") and p.haslayer("Raw") and p.haslayer("IP"):
#                     if p["TCP"].sport in (25,587) or p["TCP"].dport in (25,587):
#                         key = (p["IP"].src, p["IP"].dst, p["TCP"].sport, p["TCP"].dport)
#                         streams.setdefault(key, b"")
#                         streams[key] += bytes(p["Raw"].load)
#             cand = None; maxlen = 0
#             for k,v in streams.items():
#                 if len(v) > maxlen:
#                     maxlen = len(v); cand = v
#             if not cand:
#                 messagebox.showinfo("No SMTP", "No SMTP-like traffic found in pcap")
#                 return
#             try:
#                 text = cand.decode("utf-8", errors="ignore")
#             except Exception:
#                 text = cand.decode("latin1", errors="ignore")
#             self.raw_box.delete("1.0", tk.END)
#             self.raw_box.insert(tk.END, text)
#             self.raw_bytes = text.encode("utf-8", errors="ignore")
#             self.status_var.set(f"Loaded pcap: {os.path.basename(path)} (heuristic)")
#         except Exception as e:
#             messagebox.showerror("pcap error", f"Failed to parse pcap: {e}")

#     def run_analysis(self):
#         if not self.raw_bytes:
#             messagebox.showwarning("No message", "Load or paste a raw message first")
#             return
#         self.out_box.delete("1.0", tk.END)
#         self.out_box.insert(tk.END, "Running analysis...\n")
#         self.root.update()
#         try:
#             report = analyze(self.raw_bytes)
#             self.latest_report = report
#         except Exception as e:
#             messagebox.showerror("Error", f"Analysis failed: {e}")
#             return

#         # Run NLP classification if model loaded
#         nlp_res = None
#         if self.nlp_loaded:
#             subject = report.get("subject", "")
#             body = report.get("body_snippet", "")
#             text_for_nlp = (subject + "\n\n" + body).strip()
#             nlp_res = nlp_classify(text_for_nlp)
#             if not nlp_res.get("ok"):
#                 self.nlp_out.config(text=f"NLP error: {nlp_res.get('error')}")
#             else:
#                 lab = nlp_res.get("label")
#                 sc = nlp_res.get("score", 0.0)
#                 # Map LABEL_1 => Spam / RISK, LABEL_0 => Ham / SAFE
#                 mapped = "UNKNOWN"
#                 if lab is not None:
#                     if "1" in lab or lab.upper().endswith("1"):
#                         mapped = f"RISK (NLP: {sc:.2f})"
#                     else:
#                         mapped = f"SAFE (NLP: {sc:.2f})"
#                 self.nlp_out.config(text=mapped)
#         else:
#             self.nlp_out.config(text="NLP model not loaded")

#         # combine into final assessment
#         assessment = compute_risk(report, nlp_result=nlp_res)
#         self.latest_report["assessment"] = assessment

#         # update quick indicators
#         spf_res = report.get("spf", {})
#         dkim_res = report.get("dkim", {})
#         dmarc_res = report.get("dmarc", {})
#         spf_str = spf_res.get("result") if spf_res.get("ok") and spf_res.get("result") else (spf_res.get("error") or "N/A")
#         self.spf_var.set(f"SPF: {spf_str}")
#         dkim_str = "OK" if dkim_res.get("ok") and dkim_res.get("verified") else (dkim_res.get("error") or "FAIL")
#         self.dkim_var.set(f"DKIM: {dkim_str}")
#         dm_state = "N/A"
#         if dmarc_res.get("ok") and dmarc_res.get("policy"):
#             dm_state = dmarc_res.get("policy").get("p", "none")
#         elif dmarc_res.get("error"):
#             dm_state = dmarc_res.get("error")
#         self.dmarc_var.set(f"DMARC: {dm_state}")

#         # final verdict banner
#         self.set_verdict_banner(assessment.get("verdict", "NO DATA"))

#         # populate breakdown box
#         lines = []
#         lines.append("From: " + str(report.get("from")))
#         lines.append("Return-Path: " + str(report.get("return_path")))
#         lines.append("Received (earliest first): " + ", ".join(report.get("received_ips", []) or ["N/A"]))
#         lines.append("\nSPF:")
#         if spf_res.get("ok"):
#             lines.append(f"  Result: {spf_res.get('result')} | {spf_res.get('explanation')}")
#         else:
#             lines.append(f"  {spf_res.get('error')}")
#         lines.append("\nDKIM:")
#         if dkim_res.get("ok"):
#             lines.append(f"  Verified: {dkim_res.get('verified')}")
#         else:
#             lines.append(f"  {dkim_res.get('error')}")
#         lines.append("\nDMARC:")
#         if dmarc_res.get("ok"):
#             lines.append(f"  Record: {dmarc_res.get('record')}")
#             lines.append(f"  Policy: {dmarc_res.get('policy')}")
#         else:
#             lines.append(f"  {dmarc_res.get('error')}")

#         lines.append("\nHeuristics:")
#         dsp = report.get("display_spoof", {})
#         if dsp.get("ok"):
#             if dsp.get("suspicious"):
#                 lines.append("  Display-name suspicious: " + "; ".join(dsp.get("reasons", [])))
#             else:
#                 lines.append("  Display-name appears normal")
#         else:
#             lines.append("  " + dsp.get("error", "N/A"))

#         att = report.get("attachments", {})
#         if att.get("ok"):
#             if att.get("findings"):
#                 for f in att.get("findings"):
#                     lines.append("  Attachment: " + str(f))
#             else:
#                 lines.append("  No suspicious attachments detected")
#         else:
#             lines.append("  " + att.get("error", "Attachment check failed"))

#         mism = report.get("mismatches", [])
#         if mism:
#             for m in mism:
#                 lines.append("  Mismatch: " + str(m))

#         lines.append("\nNLP:")
#         if nlp_res is None:
#             lines.append("  NLP: not run or model not loaded")
#         else:
#             if nlp_res.get("ok"):
#                 lines.append(f"  Label: {nlp_res.get('label')} | score: {nlp_res.get('score'):.3f}")
#             else:
#                 lines.append("  NLP error: " + str(nlp_res.get("error")))

#         lines.append("\nAssessment:")
#         lines.append(f"  Verdict: {assessment.get('verdict')} | Score: {assessment.get('score')}")
#         lines.append("  Reasons:")
#         for r in assessment.get("reasons", []):
#             lines.append("   - " + r)

#         self.out_box.delete("1.0", tk.END)
#         self.out_box.insert(tk.END, "\n".join(lines) + "\n")

#         # Recommendation text
#         rec = self.generate_recommendation(assessment)
#         self.rec_text.configure(state="normal")
#         self.rec_text.delete("1.0", tk.END)
#         self.rec_text.insert(tk.END, rec)
#         self.rec_text.configure(state="disabled")

#         self.status_var.set("Analysis complete")

#     def generate_recommendation(self, assessment: dict) -> str:
#         v = assessment.get("verdict")
#         if v == "SAFE":
#             return "Message appears safe based on checks and NLP. Still exercise caution if unexpected."
#         if v == "MAYBE":
#             return "Message shows anomalies. Verify sender using an independent channel before clicking links or opening attachments."
#         return "High risk — treat as phishing. Do NOT open attachments or click links. Report to your security team."

#     def export_report(self):
#         if not self.latest_report:
#             messagebox.showwarning("No report", "Run analysis first")
#             return
#         path = filedialog.asksaveasfilename(title="Save report", defaultextension=".txt", filetypes=[("Text files", "*.txt")])
#         if not path:
#             return
#         try:
#             with open(path, "w", encoding="utf-8") as f:
#                 f.write(self.out_box.get("1.0", tk.END))
#                 f.write("\nRecommendation:\n")
#                 f.write(self.rec_text.get("1.0", tk.END))
#             messagebox.showinfo("Saved", f"Report saved to {path}")
#         except Exception as e:
#             messagebox.showerror("Error", f"Failed to save: {e}")

# # ---------------- main ----------------
# def main():
#     root = tk.Tk()
#     app = ForensicsGUI(root)
#     root.mainloop()

# if __name__ == "__main__":
#     main()

#!/usr/bin/env python3

#!/usr/bin/env python3
"""
Email Header Forensics & Spoof Detection Engine with local NLP phishing detector.

- Rule-based header checks (SPF/DKIM/DMARC heuristics)
- Attachment heuristics
- Optional pcap parsing (scapy)
- Local NLP phishing detector (Hugging Face transformers)
    * Model used: mrm8488/bert-tiny-finetuned-sms-spam-detection
    * LABEL_1 => treated as 'spam' (RISK), LABEL_0 => 'ham' (SAFE)
- Modern GUI built with PyQt5 and a custom moderate theme.
- Defensive: features gracefully degrade if optional libraries are missing
"""

import os
import re
import sys
from email import policy
from email.parser import BytesParser, Parser
from email.message import EmailMessage

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QFileDialog, QMessageBox,
    QInputDialog, QGroupBox, QAction, QToolBar, QStyle, QStatusBar, QSizePolicy
)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt, QSize

from fpdf import FPDF

# Optional imports
HAVE_DKIM = HAVE_SPF = HAVE_DNS = HAVE_SCAPY = HAVE_TRANSFORMERS = False
try:
    import dkim
    HAVE_DKIM = True
except Exception:
    HAVE_DKIM = False

try:
    import spf
    HAVE_SPF = True
except Exception:
    HAVE_SPF = False

try:
    import dns.resolver
    HAVE_DNS = True
except Exception:
    HAVE_DNS = False

try:
    from scapy.all import rdpcap
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False

# Transformers (NLP)
MODEL_NAME = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
nlp_pipeline = None
try:
    from transformers import pipeline, AutoConfig
    HAVE_TRANSFORMERS = True
except Exception:
    HAVE_TRANSFORMERS = False


# ---------------- regex / constants ----------------
RECEIVED_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
DOUBLE_EXT_RE = re.compile(r"\.(\w+)\.(exe|scr|bat|com|js|vbs|docm|xlsm|jar)$", re.IGNORECASE)
SUSPICIOUS_EXT = {"exe", "scr", "bat", "com", "js", "vbs", "docm", "xlsm", "jar"}

# ---------------- email parsing helpers ----------------
def parse_eml_bytes(data: bytes) -> EmailMessage:
    """Parse raw email bytes into EmailMessage object (robust with fallbacks)."""
    try:
        return BytesParser(policy=policy.default).parsebytes(data)
    except Exception:
        text = data.decode("utf-8", errors="ignore")
        return Parser(policy=policy.default).parsestr(text)

def extract_received_ips(msg: EmailMessage) -> list:
    rcvd = msg.get_all("Received") or []
    ips = []
    for header in rcvd:
        found = RECEIVED_IP_RE.findall(header)
        for ip in found:
            parts = ip.split(".")
            try:
                if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                    ips.append(ip)
            except Exception:
                pass
    if ips:
        return list(reversed(ips))
    return ips

def get_from_and_return_path(msg: EmailMessage) -> tuple:
    from_hdr = msg.get("From")
    ret = msg.get("Return-Path") or msg.get("Envelope-From") or None
    return from_hdr, ret

def extract_subject_and_body(msg: EmailMessage) -> tuple:
    """Return (subject, body_text). Body is plain text aggregated from parts; falls back to html stripped if needed."""
    subject = msg.get("Subject", "")
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get_content_disposition() or "")
            if disp == "attachment":
                continue
            if ctype == "text/plain":
                try:
                    text = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                except Exception:
                    text = part.get_content()
                body_parts.append(text or "")
            elif ctype == "text/html" and not body_parts:
                try:
                    html = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                except Exception:
                    html = part.get_content()
                text = re.sub(r"<[^>]+>", " ", html or "")
                body_parts.append(text)
    else:
        ctype = msg.get_content_type()
        if ctype in ("text/plain", "text/html"):
            try:
                body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
            except Exception:
                body = msg.get_content()
            if ctype == "text/html":
                body = re.sub(r"<[^>]+>", " ", body or "")
            body_parts.append(body or "")
    body_text = "\n\n".join(p for p in body_parts if p)
    return subject or "", body_text or ""

# ---------------- SPF / DKIM / DMARC wrappers ----------------
def spf_check(ip: str, mail_from: str = None, helo: str = None) -> dict:
    if not HAVE_SPF:
        return {"ok": False, "error": "pyspf not installed"}
    try:
        if mail_from is None: mail_from = "-"
        if helo is None: helo = "unknown"
        res = spf.check2(i=ip, s=mail_from, h=helo)
        return {"ok": True, "result": res[0], "explanation": res[1], "spf_record": res[2]}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def dkim_check(raw_bytes: bytes) -> dict:
    if not HAVE_DKIM:
        return {"ok": False, "error": "dkimpy not installed"}
    try:
        verified = dkim.verify(raw_bytes)
        return {"ok": True, "verified": bool(verified)}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def dmarc_lookup(domain: str) -> dict:
    if not HAVE_DNS:
        return {"ok": False, "error": "dnspython not installed"}
    try:
        qname = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(qname, "TXT")
        txts = [b"".join(r.strings).decode("utf-8") for r in answers]
        txt = " ".join(txts)
        policy = {}
        for part in [p.strip() for p in txt.split(";") if p.strip()]:
            if "=" in part:
                k, v = part.split("=", 1)
                policy[k.lower()] = v
        return {"ok": True, "record": txt, "policy": policy}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---------------- heuristics ----------------
def detect_display_name_spoof(from_header: str) -> dict:
    if not from_header: return {"ok": False, "error": "No From header"}
    m = re.match(r"\s*([^<]+)\s*<(.+@.+)>", from_header)
    if m:
        display, addr = m.group(1).strip(' "'), m.group(2)
        dom = addr.split("@")[-1].lower()
        words = re.findall(r"[A-Za-z]{3,}", display)
        suspicious, reasons = False, []
        for w in words:
            if w.lower() in dom: continue
            if len(w) >= 4 and w[0].isupper():
                suspicious = True
                reasons.append(f"Display name contains '{w}' but email domain is '{dom}'")
        return {"ok": True, "suspicious": suspicious, "reasons": reasons}
    return {"ok": True, "suspicious": False}

def detect_hidden_attachments(msg: EmailMessage) -> dict:
    findings = []
    if msg.is_multipart():
        for part in msg.iter_attachments():
            filename = part.get_filename()
            ctype = part.get_content_type()
            if filename:
                if DOUBLE_EXT_RE.search(filename):
                    findings.append(f"Double extension: {filename}")
                ext = os.path.splitext(filename)[1].lower().lstrip(".")
                if ext in SUSPICIOUS_EXT:
                    findings.append(f"Suspicious extension (.{ext}): {filename}")
            else:
                findings.append(f"Nameless attachment (type: {ctype})")
    return {"ok": True, "findings": findings}

# ---------------- NLP model loader & classifier ----------------
def load_nlp_model():
    """Attempt to load the transformers pipeline."""
    global nlp_pipeline
    if not HAVE_TRANSFORMERS: return None, "transformers library not installed"
    try:
        nlp_pipeline = pipeline("text-classification", model=MODEL_NAME, truncation=True)
        return nlp_pipeline, f"Loaded model {MODEL_NAME}"
    except Exception as e:
        nlp_pipeline = None
        return None, f"Failed to load model: {e}"

def nlp_classify(text: str) -> dict:
    """Classify text using the loaded pipeline."""
    if nlp_pipeline is None: return {"ok": False, "error": "NLP model not loaded"}
    if not text or len(text.strip()) < 10: return {"ok": True, "label": "LABEL_0", "score": 0.0, "note": "empty/short text"}
    try:
        res = nlp_pipeline(text[:2000])[0]
        return {"ok": True, "label": res.get("label"), "score": float(res.get("score", 0.0))}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---------------- SCORING & COMBINING ----------------
def compute_risk(report: dict, nlp_result: dict = None) -> dict:
    """Combine header heuristics and optional NLP result to produce a score and verdict."""
    score = 0
    reasons = []

    # SPF check
    spf = report.get("spf", {})
    if spf.get("ok") and spf.get("result"):
        res = spf["result"].lower()
        if res == "pass":
            score -= 2; reasons.append("SPF Passed (-2)")
        elif res in ["fail", "softfail"]:
            score += 2; reasons.append(f"SPF Failed: {res} (+2)")
        else: # neutral, none, etc.
            score += 1; reasons.append(f"SPF Neutral/None: {res} (+1)")
    else:
        score += 1; reasons.append("SPF Unavailable (+1)")

    # DKIM check
    dkim = report.get("dkim", {})
    if dkim.get("ok"):
        if dkim.get("verified"):
            score -= 2; reasons.append("DKIM Verified (-2)")
        else:
            score += 2; reasons.append("DKIM Signature Invalid (+2)")
    else:
        score += 1; reasons.append("DKIM Unavailable/Missing (+1)")

    # DMARC check
    dmarc = report.get("dmarc", {})
    if dmarc.get("ok") and dmarc.get("policy"):
        p = dmarc["policy"].get("p", "none")
        reasons.append(f"DMARC Policy: {p}")
        if p == "reject":
            score -= 2; reasons.append("DMARC Reject Policy (-2)")
        elif p == "quarantine":
            score -= 1; reasons.append("DMARC Quarantine Policy (-1)")
    else:
        score += 1; reasons.append("DMARC Missing/Unavailable (+1)")

    # Heuristics
    if report.get("display_spoof", {}).get("suspicious"):
        score += 3; reasons.append("Display Name Spoofing Likely (+3)")
    if report.get("attachments", {}).get("findings"):
        score += 3; reasons.append("Suspicious Attachments (+3)")
    if report.get("mismatches"):
        score += 2; reasons.append("Return-Path/From Mismatch (+2)")

    # NLP result integration
    if nlp_result and nlp_result.get("ok"):
        label, sc = nlp_result.get("label", ""), nlp_result.get("score", 0.0)
        if "1" in label: # Phishing/Spam
            score += int(sc * 3) + 1 # Weighted penalty up to +4
            reasons.append(f"NLP Risk: {sc:.2f} (+{int(sc*3)+1})")
        else: # Ham
            if sc > 0.95:
                score -= 2; reasons.append(f"NLP Safe: {sc:.2f} (-2)")
            elif sc > 0.8:
                score -= 1; reasons.append(f"NLP Safe: {sc:.2f} (-1)")
    else:
        reasons.append("NLP Unavailable")
        
    # Final verdict mapping
    if score <= 0: verdict = "SAFE"
    elif score <= 3: verdict = "MAYBE"
    else: verdict = "RISK"

    return {"score": score, "verdict": verdict, "reasons": reasons}

# ---------------- top-level analysis ----------------
def analyze(raw_bytes: bytes) -> dict:
    report = {"ok": True, "errors": []}
    try: msg = parse_eml_bytes(raw_bytes)
    except Exception as e: return {"ok": False, "error": f"Failed to parse message: {e}"}

    report["headers"] = dict(msg.items())
    report["from"], report["return_path"] = get_from_and_return_path(msg)
    report["received_ips"] = extract_received_ips(msg)

    ip = report["received_ips"][0] if report["received_ips"] else None
    mail_from = report["return_path"] or report["from"]
    
    report["spf"] = spf_check(ip, mail_from=mail_from) if ip else {"ok": False, "error": "No originating IP"}
    report["dkim"] = dkim_check(raw_bytes)

    domain = None
    if report["from"]:
        match = re.search(r"<([^>]+@[^>]+)>", report["from"])
        if match: domain = match.group(1).split("@")[-1]
        elif "@" in report["from"]: domain = report["from"].strip().split("@")[-1]
    
    report["dmarc"] = dmarc_lookup(domain) if domain else {"ok": False, "error": "No From domain"}

    report["display_spoof"] = detect_display_name_spoof(report["from"])
    report["attachments"] = detect_hidden_attachments(msg)
    
    report["mismatches"] = []
    try:
        from_domain = domain
        rp_domain = None
        if report["return_path"]:
            rp_match = re.search(r"@[^>]+", report["return_path"])
            if rp_match: rp_domain = rp_match.group(0).strip("@>")
        
        if from_domain and rp_domain and from_domain.lower() != rp_domain.lower():
            report["mismatches"].append(f"From domain ({from_domain}) != Return-Path domain ({rp_domain})")
    except Exception: pass

    report["subject"], report["body_snippet"] = extract_subject_and_body(msg)
    return report


# ---------------- STYLESHEET (MODERATE THEME) ----------------
APP_STYLESHEET = """
    QMainWindow, QDialog {
        background-color: #ECEFF4;
    }
    QTextEdit {
        background-color: #FFFFFF;
        color: #2E3440;
        border: 1px solid #D8DEE9;
        border-radius: 4px;
        font-size: 11pt;
    }
    QToolBar {
        background-color: #E5E9F0;
        border: none;
        padding: 4px;
    }
    QToolButton {
        color: #4C566A;
        background-color: #E5E9F0;
        border: 1px solid #D8DEE9;
        padding: 6px;
        border-radius: 4px;
    }
    QToolButton:hover {
        color: #FFFFFF;
        background-color: #81A1C1;
        border: 1px solid #5E81AC;
    }
    QToolButton:pressed {
        background-color: #88C0D0;
    }
    QLabel {
        color: #4C566A;
        font-size: 10pt;
    }
    QLabel#title {
        color: #2E3440;
        font-weight: bold;
        font-size: 11pt;
    }
    QGroupBox {
        color: #2E3440;
        font-weight: bold;
        background-color: #E5E9F0;
        border: 1px solid #D8DEE9;
        border-radius: 6px;
        margin-top: 6px;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 5px 0 5px;
    }
    QStatusBar {
        color: #4C566A;
    }
    QStatusBar::item {
        border: none;
    }
"""


# ---------------- Enhanced PyQt5 GUI ----------------
class ForensicsGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Email Forensics & Phishing Detector")
        self.setGeometry(100, 100, 1200, 800)
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_MessageBoxInformation))
        self.raw_bytes = None
        self.latest_report = None
        self.nlp_loaded = False
        self._create_actions()
        self._create_toolbar()
        self._create_central_widget()
        self._create_status_bar()
        self.try_load_nlp_model()

    def _create_actions(self):
        """Create the actions for the toolbar."""
        style = self.style()
        self.load_eml_action = QAction(QIcon.fromTheme("document-open", style.standardIcon(QStyle.SP_DirOpenIcon)), "&Load .eml", self)
        self.paste_action = QAction(QIcon.fromTheme("edit-paste", style.standardIcon(QStyle.SP_FileLinkIcon)), "&Paste Raw", self)
        self.pcap_action = QAction(QIcon.fromTheme("network-wired", style.standardIcon(QStyle.SP_DriveNetIcon)), "&Open PCAP", self)
        self.run_action = QAction(QIcon.fromTheme("system-run", style.standardIcon(QStyle.SP_MediaPlay)), "&Run Analysis", self)
        self.export_action = QAction(QIcon.fromTheme("document-save", style.standardIcon(QStyle.SP_DialogSaveButton)), "&Export PDF", self)
        
        self.load_eml_action.triggered.connect(self.load_eml)
        self.paste_action.triggered.connect(self.paste_raw)
        self.pcap_action.triggered.connect(self.open_pcap)
        self.run_action.triggered.connect(self.run_analysis)
        self.export_action.triggered.connect(self.export_report_pdf)

    def _create_toolbar(self):
        """Create and populate the main toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        actions = [self.load_eml_action, self.paste_action, self.pcap_action]
        tooltips = ["Load an .eml file", "Paste raw email content", "Extract email from a .pcap file"]
        for action, tip in zip(actions, tooltips):
            action.setToolTip(tip)
            toolbar.addAction(action)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(spacer)

        self.run_action.setToolTip("Run the analysis on the loaded data")
        self.export_action.setToolTip("Export the final report as a PDF")
        toolbar.addAction(self.run_action)
        toolbar.addAction(self.export_action)

    def _create_central_widget(self):
        """Setup the main layout and widgets."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        left_group = QGroupBox("Email Source")
        left_layout = QVBoxLayout(left_group)
        self.raw_box = QTextEdit()
        self.raw_box.setLineWrapMode(QTextEdit.NoWrap)
        self.raw_box.setPlaceholderText("Load or paste a raw email message here...")
        left_layout.addWidget(self.raw_box)
        main_layout.addWidget(left_group, 2)

        right_group = QGroupBox("Analysis & Verdict")
        right_layout = QVBoxLayout(right_group)
        right_layout.setSpacing(8)

        self.verdict_label = QLabel("NO DATA")
        self.verdict_label.setFont(QFont("Arial", 22, QFont.Bold))
        self.verdict_label.setAlignment(Qt.AlignCenter)
        self.verdict_label.setStyleSheet("padding: 10px; border-radius: 5px; background-color: #D8DEE9; color: #4C566A;")
        right_layout.addWidget(self.verdict_label)

        nlp_layout = QHBoxLayout()
        self.nlp_status_label = QLabel("NLP: Not loaded")
        self.model_accuracy_label = QLabel("Model Accuracy: 80.0%")
        self.model_accuracy_label.setAlignment(Qt.AlignRight)
        nlp_layout.addWidget(self.nlp_status_label)
        nlp_layout.addWidget(self.model_accuracy_label)
        right_layout.addLayout(nlp_layout)

        indicator_layout = QHBoxLayout()
        self.spf_indicator = self._create_indicator("SPF: ?")
        self.dkim_indicator = self._create_indicator("DKIM: ?")
        self.dmarc_indicator = self._create_indicator("DMARC: ?")
        indicator_layout.addWidget(self.spf_indicator)
        indicator_layout.addWidget(self.dkim_indicator)
        indicator_layout.addWidget(self.dmarc_indicator)
        right_layout.addLayout(indicator_layout)

        for text in ["Analysis Factors", "Recommendation"]:
            title = QLabel(text)
            title.setObjectName("title")
            right_layout.addWidget(title)
            if text == "Analysis Factors":
                self.out_box = QTextEdit()
                self.out_box.setReadOnly(True)
                right_layout.addWidget(self.out_box, 1)
            else:
                self.rec_text = QTextEdit()
                self.rec_text.setReadOnly(True)
                self.rec_text.setFixedHeight(70)
                right_layout.addWidget(self.rec_text)

        main_layout.addWidget(right_group, 1)

    def _create_indicator(self, text: str) -> QLabel:
        """Helper to create a styled status indicator label."""
        label = QLabel(text)
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet("font-weight: bold; padding: 5px; border-radius: 4px; background-color: #D8DEE9; color: #4C566A;")
        return label

    def _create_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready. Please load an email to begin analysis.")

    def try_load_nlp_model(self):
        if not HAVE_TRANSFORMERS:
            self.nlp_status_label.setText("NLP: 'transformers' not found")
            self.nlp_status_label.setStyleSheet("color: #BF616A;")
            return
        self.status_bar.showMessage("Loading NLP model (this may take a moment)...")
        QApplication.processEvents()
        _, msg = load_nlp_model()
        if nlp_pipeline:
            self.nlp_status_label.setText("NLP: Model Loaded"); self.nlp_status_label.setStyleSheet("color: #468747;")
            self.nlp_loaded = True
            self.status_bar.showMessage("NLP model loaded successfully. Ready.", 5000)
        else:
            self.nlp_status_label.setText("NLP: Load Failed"); self.nlp_status_label.setStyleSheet("color: #BF616A;")
            self.status_bar.showMessage(f"NLP model failed to load: {msg}", 10000)

    def set_verdict_banner(self, verdict: str):
        styles = {
            "SAFE": "background-color: #A3BE8C; color: #2E3440;",
            "MAYBE": "background-color: #EBCB8B; color: #3B4252;",
            "RISK": "background-color: #BF616A; color: #ECEFF4;"
        }
        self.verdict_label.setStyleSheet(f"padding: 10px; border-radius: 5px; {styles.get(verdict, '')}")
        self.verdict_label.setText(verdict)

    def update_indicator(self, indicator: QLabel, text: str, state: str):
        """Update indicator text and color."""
        styles = {
            "pass": "background-color: #A3BE8C; color: #2E3440;",
            "fail": "background-color: #BF616A; color: #ECEFF4;",
            "neutral": "background-color: #EBCB8B; color: #3B4252;",
            "unknown": "background-color: #D8DEE9; color: #4C566A;"
        }
        indicator.setText(text)
        indicator.setStyleSheet(f"font-weight: bold; padding: 5px; border-radius: 4px; {styles.get(state, 'unknown')}")

    def load_eml(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open .eml file", "", "EML files (*.eml);;All files (*.*)")
        if not path: return
        try:
            with open(path, "rb") as f: self.raw_bytes = f.read()
            self.raw_box.setPlainText(self.raw_bytes.decode("utf-8", "ignore"))
            self.status_bar.showMessage(f"Loaded {os.path.basename(path)}", 5000)
        except Exception as e: QMessageBox.critical(self, "Error", f"Failed to load file: {e}")

    def paste_raw(self):
        text, ok = QInputDialog.getMultiLineText(self, "Paste raw headers/message", "Paste content here:")
        if ok and text:
            self.raw_bytes = text.encode("utf-8", "ignore")
            self.raw_box.setPlainText(text)
            self.status_bar.showMessage("Raw message pasted from clipboard.", 5000)

    def open_pcap(self):
        if not HAVE_SCAPY:
            QMessageBox.warning(self, "scapy missing", "Please install scapy (`pip install scapy`)")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Open pcap", "", "pcap files (*.pcap *.pcapng);;All files (*.*)")
        if not path: return
        try:
            pkts = rdpcap(path)
            streams = {}
            for p in pkts:
                if "TCP" in p and "Raw" in p and "IP" in p:
                    if p["TCP"].sport in (25, 587, 465) or p["TCP"].dport in (25, 587, 465):
                        key = (p["IP"].src, p["IP"].dst, p["TCP"].sport, p["TCP"].dport)
                        streams.setdefault(key, b"")
                        streams[key] += bytes(p["Raw"].load)
            if not streams:
                QMessageBox.information(self, "No SMTP", "No SMTP-like traffic found in pcap")
                return
            
            cand = max(streams.values(), key=len)
            self.raw_bytes = cand
            self.raw_box.setPlainText(cand.decode("utf-8", "ignore"))
            self.status_bar.showMessage(f"Loaded largest TCP stream from {os.path.basename(path)}", 5000)
        except Exception as e: QMessageBox.critical(self, "pcap error", f"Failed to parse pcap: {e}")

    def run_analysis(self):
        if not self.raw_bytes:
            QMessageBox.warning(self, "No message", "Load or paste a raw message first")
            return
        self.status_bar.showMessage("Running analysis...")
        QApplication.processEvents()
        
        try: report = analyze(self.raw_bytes)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Analysis failed: {e}")
            self.status_bar.showMessage(f"Analysis failed", 5000)
            return

        self.latest_report = report
        nlp_res = nlp_classify(report.get("subject", "") + "\n" + report.get("body_snippet", "")) if self.nlp_loaded else None
        assessment = compute_risk(report, nlp_result=nlp_res)
        self.latest_report["assessment"] = assessment

        # Update indicators
        spf_res = report.get("spf", {})
        spf_state = "pass" if spf_res.get("result") == "pass" else "fail" if spf_res.get("result") in ["fail", "softfail"] else "neutral" if spf_res.get("ok") else "unknown"
        self.update_indicator(self.spf_indicator, f"SPF: {spf_res.get('result', 'N/A').upper()}", spf_state)
        
        dkim_res = report.get("dkim", {})
        dkim_state = "pass" if dkim_res.get("verified") else "fail" if dkim_res.get("ok") else "unknown"
        self.update_indicator(self.dkim_indicator, f"DKIM: {'PASS' if dkim_state=='pass' else 'FAIL' if dkim_state=='fail' else 'N/A'}", dkim_state)

        dmarc_res = report.get("dmarc", {})
        dmarc_policy = dmarc_res.get("policy", {}).get("p", "N/A")
        dmarc_state = "pass" if dmarc_policy == "reject" else "neutral" if dmarc_policy == "quarantine" else "fail" if dmarc_res.get("ok") else "unknown"
        self.update_indicator(self.dmarc_indicator, f"DMARC: {dmarc_policy.upper()}", dmarc_state)

        self.set_verdict_banner(assessment.get("verdict", "ERROR"))
        
        # Populate text boxes
        self.out_box.setPlainText("\n".join(assessment.get("reasons", [])))
        self.rec_text.setPlainText(self.generate_recommendation(assessment))
        self.status_bar.showMessage("Analysis complete.", 5000)

    def generate_recommendation(self, assessment: dict) -> str:
        verdict = assessment.get("verdict")
        if verdict == "SAFE": return "Message appears safe. Standard caution is still advised."
        if verdict == "MAYBE": return "Message shows anomalies. Verify sender independently before clicking links or opening attachments."
        return "High risk — likely phishing. Do NOT click links or open attachments. Report immediately."

    def export_report_pdf(self):
        if not self.latest_report:
            QMessageBox.warning(self, "No report", "Run analysis first")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save report", "Email_Forensics_Report.pdf", "PDF files (*.pdf)")
        if not path: return
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(0, 10, "Email Forensics Report", ln=True, align='C')
            pdf.ln(10)
            
            assessment = self.latest_report["assessment"]
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 8, f"Final Verdict: {assessment.get('verdict', 'N/A')}", ln=True)
            pdf.cell(0, 8, f"Risk Score: {assessment.get('score', 'N/A')}", ln=True)
            pdf.ln(5)

            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, "Analysis Factors", ln=True)
            pdf.set_font("Arial", size=10)
            report_text = self.out_box.toPlainText().encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 5, report_text)
            pdf.ln(10)

            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, "Recommendation", ln=True)
            pdf.set_font("Arial", size=10)
            rec_text = self.rec_text.toPlainText().encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 5, rec_text)

            pdf.output(path)
            self.status_bar.showMessage(f"Report saved to {path}", 5000)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save PDF: {e}")

# ---------------- main ----------------
def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(APP_STYLESHEET)
    gui = ForensicsGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()