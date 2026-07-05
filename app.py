import json
import os
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

try:
    from openai import OpenAI
except Exception:
    OpenAI = None

BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title="ATT&CK Profiler LLM Backend", version="0.4")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class AnalyzeRequest(BaseModel):
    description: str
    mode: str = "soc"

class EnrichRequest(BaseModel):
    type: str = "unknown"
    value: str
    consent: bool = False
    source_policy: str = "allowlisted_backend_only"

TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1566": {"name":"Phishing","tactic":"Initial Access","keywords":["phishing","email","mail","allegato","link malevolo","spear phishing","spearphishing"],"mitigations":["Email filtering","Sandbox allegati","SPF/DKIM/DMARC","Formazione anti-phishing"],"detections":["Analizzare header email, SPF/DKIM/DMARC e allegati.","Hunting su allegati Office e URL inviati alla stessa organizzazione."]},
    "T1204": {"name":"User Execution","tactic":"Execution","keywords":["utente ha aperto","cliccato","eseguito","abilita le macro","abilitato le macro","apre il file","aperto il file"],"mitigations":["EDR","Application control","Awareness","Bloccare contenuti attivi non attendibili"],"detections":["Processi figli anomali di Office/browser.","Esecuzione di file da download/temp/profile utente."]},
    "T1059": {"name":"Command and Scripting Interpreter","tactic":"Execution","keywords":["macro","powershell","script","cmd","shell","wscript","cscript","bash"],"mitigations":["Bloccare macro non firmate","Limitare PowerShell","Application allowlisting"],"detections":["PowerShell con download cradle o encoded command.","Office che avvia powershell/cmd/wscript/cscript."]},
    "T1547.001": {"name":"Registry Run Keys / Startup Folder","tactic":"Persistence","keywords":["registro","registry","run key","startup","persistenza","runonce","chiave run"],"mitigations":["Monitoraggio chiavi Run/RunOnce","Least privilege","EDR"],"detections":["Modifiche a HKCU/HKLM Software\\Microsoft\\Windows\\CurrentVersion\\Run.","Nuovi file in cartelle Startup."]},
    "T1071": {"name":"Application Layer Protocol","tactic":"Command and Control","keywords":["c2","command and control","dominio esterno","http","https","dns","beacon","server di comando"],"mitigations":["DNS monitoring","Proxy filtering","Network detection","Blocchi su IOC confermati"],"detections":["Beaconing periodico HTTP/HTTPS/DNS.","Connessioni verso domini nuovi o rari per l'organizzazione."]},
    "T1021.001": {"name":"Remote Desktop Protocol","tactic":"Lateral Movement","keywords":["rdp","desktop remoto","accesso remoto"],"mitigations":["MFA su RDP","VPN obbligatoria","Limitare esposizione RDP"],"detections":["Logon RDP anomali, eventi 4624 tipo 10.","Connessioni RDP laterali tra endpoint."]},
    "T1562": {"name":"Impair Defenses","tactic":"Defense Evasion","keywords":["disattivato antivirus","disabilitato edr","tampering","disattiva antivirus","disattivazione antivirus"],"mitigations":["Tamper protection","Hardening EDR","Privilege restriction"],"detections":["Eventi di stop service AV/EDR.","Modifiche policy Defender o esclusioni sospette."]},
    "T1486": {"name":"Data Encrypted for Impact","tactic":"Impact","keywords":["ransomware","cifratura","file cifrati","riscatto","cryptolocker"],"mitigations":["Backup offline","Segmentazione rete","EDR anti-ransomware"],"detections":["Creazione massiva di file cifrati/estensioni anomale.","Note di riscatto e picchi di rename/write."]},
    "T1560": {"name":"Archive Collected Data","tactic":"Collection","keywords":["archivio","zip","rar","compressione","compressi","7z","comprimere"],"mitigations":["DLP","Monitoraggio compressione","Controllo accessi"],"detections":["Uso anomalo di zip/rar/7z su grandi quantità di dati.","Archivi creati in temp, desktop o share sensibili."]},
    "T1567": {"name":"Exfiltration Over Web Service","tactic":"Exfiltration","keywords":["cloud storage","dropbox","google drive","mega","upload esterno","servizio cloud","cloud esterno","caricarli su un servizio cloud","caricati su cloud","upload su cloud"],"mitigations":["CASB","DLP","Proxy monitoring","Blocco servizi cloud non autorizzati"],"detections":["Upload verso cloud storage non approvati.","Volumi outbound anomali su HTTPS verso servizi web."]},
}
GROUPS = {"FIN7":["T1566","T1204","T1059","T1547.001","T1071"],"APT29":["T1566","T1204","T1059","T1071"],"TA505":["T1566","T1204","T1059","T1071","T1486"],"LockBit-like ransomware":["T1021.001","T1562","T1486"],"Generic Data Exfiltration Actor":["T1560","T1567","T1071"]}
IOC_PATTERNS = {"ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", "url": r"https?://[^\s\]\)>'\"]+", "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "hash": r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", "windows_path": r"[A-Za-z]:\\[^\s\n\r]+"}
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
NO_DOMAINS = {"microsoft.com", "windows.com"}

def ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def extract_iocs(text: str) -> Dict[str, List[str]]:
    iocs = {k: sorted(set(re.findall(p, text))) for k, p in IOC_PATTERNS.items()}
    domains = set(DOMAIN_RE.findall(text))
    domains -= set(iocs.get("email", []))
    for u in iocs.get("url", []):
        try:
            domains.discard(re.sub(r"^https?://", "", u).split("/")[0])
        except Exception:
            pass
    iocs["domain"] = sorted(d for d in domains if d.lower() not in NO_DOMAINS)
    return {k: v for k, v in iocs.items() if v}

def keyword_detect(text: str) -> List[Dict[str, Any]]:
    low = text.lower(); out = []
    for tid, data in TECHNIQUES.items():
        matched = [k for k in data["keywords"] if k.lower() in low]
        if matched:
            out.append({"id": tid, "name": data["name"], "tactic": data["tactic"], "confidence": min(0.95, 0.55 + 0.15 * len(matched)), "evidence": "; ".join(matched), "source": "keyword", "mitigations": data["mitigations"], "detections": data["detections"]})
    return out

def llm_detect(text: str) -> List[Dict[str, Any]]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or OpenAI is None: return []
    allowed = {tid: {"name": v["name"], "tactic": v["tactic"]} for tid, v in TECHNIQUES.items()}
    prompt = "Sei un analista CTI. Estrai solo tecniche MITRE ATT&CK tra quelle consentite. Rispondi solo JSON valido: {\"techniques\":[{\"id\":\"T1566\",\"confidence\":0.0,\"evidence\":\"frase testuale\",\"reason\":\"motivazione breve\"}],\"unknowns\":[\"dato mancante\"]}. Tecniche consentite: " + json.dumps(allowed, ensure_ascii=False) + "\nTesto: " + text
    try:
        client = OpenAI(api_key=api_key)
        resp = client.responses.create(model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"), input=prompt)
        parsed = json.loads(resp.output_text.strip())
    except Exception:
        return []
    out = []
    for item in parsed.get("techniques", []):
        tid = item.get("id")
        if tid in TECHNIQUES:
            d = TECHNIQUES[tid]
            out.append({"id": tid, "name": d["name"], "tactic": d["tactic"], "confidence": float(item.get("confidence", 0.7)), "evidence": str(item.get("evidence", "")), "reason": str(item.get("reason", "")), "source": "llm", "mitigations": d["mitigations"], "detections": d["detections"]})
    return out

def merge_techniques(*lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for item in [x for lst in lists for x in lst]:
        tid = item["id"]
        if tid not in merged:
            merged[tid] = item
        else:
            old = merged[tid]
            old["confidence"] = max(float(old.get("confidence", 0)), float(item.get("confidence", 0)))
            old["source"] = "keyword+llm" if old.get("source") != item.get("source") else old.get("source")
            if item.get("evidence") and item["evidence"] not in old.get("evidence", ""):
                old["evidence"] = (old.get("evidence", "") + "; " + item["evidence"]).strip("; ")
            if item.get("reason"):
                old["reason"] = item["reason"]
    return sorted(merged.values(), key=lambda x: x["id"])

def score_groups(techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ids = {t["id"] for t in techniques}; scored = []
    for group, tids in GROUPS.items():
        match = [tid for tid in tids if tid in ids]
        if match and ids:
            raw = len(match) / len(ids); penalty = 0.85 if len(ids) < 4 else 1; score = round(raw * penalty, 2)
            scored.append({"group": group, "score": score, "confidence": "media" if score >= .61 else "medio-bassa" if score >= .31 else "bassa", "matched_techniques": match, "missing_for_attribution": ["malware/famiglia", "IOC infrastrutturali", "vittimologia", "cronologia campagna"], "note": "Profilo TTP compatibile: non è attribuzione certa."})
    return sorted(scored, key=lambda x: x["score"], reverse=True)

def operational_actions(techniques: List[Dict[str, Any]], mode: str) -> List[str]:
    ids = {t["id"] for t in techniques}
    base = ["Preservare log e artefatti prima della bonifica.", "Documentare catena di custodia e timeline."]
    if mode == "ciso": base = ["Valutare impatto su processi critici, dati e continuità operativa.", "Definire priorità di containment, comunicazione e ripristino."]
    if mode == "investigator": base = ["Acquisire evidenze in modo ripetibile e documentato.", "Separare fatti osservati, inferenze e ipotesi di attribuzione."]
    if {"T1566", "T1204"} & ids: base.append("Analizzare email, allegati, header, URL e destinatari della campagna.")
    if "T1059" in ids: base.append("Controllare processi figli di Office, PowerShell, cmd e script engine.")
    if "T1071" in ids: base.append("Analizzare DNS/HTTP/HTTPS, beaconing e bloccare IOC confermati.")
    if "T1547.001" in ids: base.append("Verificare chiavi Run/RunOnce, cartelle Startup e persistenze correlate.")
    if "T1486" in ids: base.append("Isolare host cifrati/sospetti, verificare backup e blast radius.")
    if {"T1560", "T1567"} & ids: base.append("Analizzare archivi creati, compressioni massive e upload verso cloud esterni.")
    return base

def executive_summary(techniques, groups, iocs, mode):
    tactics = sorted({t["tactic"] for t in techniques})
    top = groups[0]["group"] if groups else "nessun profilo prevalente"
    return {"mode": mode, "technique_count": len(techniques), "tactics": tactics, "top_profile": top, "ioc_count": sum(len(v) for v in iocs.values()), "assessment": "Compatibilità TTP utile per prioritizzare risposta e hunting; non valida attribuzione senza ulteriori evidenze."}

# --- CTI enrichment backend ---
ENRICH_CACHE: Dict[str, Dict[str, Any]] = {}
RATE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = int(os.getenv("CACHE_TTL_MS", "1800000")) / 1000
SOURCE_TIMEOUT = float(os.getenv("SOURCE_TIMEOUT_MS", "6500")) / 1000

def infer_ioc_type(value: str) -> str:
    v = value.strip()
    if re.match(r"^CVE-\d{4}-\d{4,}$", v, re.I): return "cve"
    if re.match(r"^[a-f0-9]{32,64}$", v, re.I): return "hash"
    if re.match(r"^https?://", v, re.I): return "url"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v): return "ip"
    if "@" in v: return "email"
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", v, re.I): return "domain"
    return "unknown"

def rate_limit(request: Request):
    ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown").split(",")[0].strip()
    current = time.time(); item = RATE.get(ip, {"start": current, "count": 0})
    if current - item["start"] > 60:
        item = {"start": current, "count": 0}
    item["count"] += 1; RATE[ip] = item
    if item["count"] > 30:
        raise HTTPException(status_code=429, detail="Rate limit superato")

def get_json(url: str, data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None) -> Any:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "ATTACK-Profiler-PWA-CTI/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=SOURCE_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))

def post_form(url: str, payload: Dict[str, str]) -> Any:
    data = urllib.parse.urlencode(payload).encode()
    return get_json(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})

def post_json(url: str, payload: Dict[str, Any]) -> Any:
    return get_json(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})

def src(name: str, status: str, detail: str, reliability: str = "media", url: str = "", **extra):
    return {"name": name, "status": status, "detail": detail, "timestamp": ts(), "reliability": reliability, "url": url, **extra}

def safe_call(name: str, fn):
    try:
        return fn()
    except Exception as e:
        return src(name, "error", str(e))

def enrich_cve(cve: str) -> List[Dict[str, Any]]:
    out = []
    def kev():
        data = get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        hit = next((v for v in data.get("vulnerabilities", []) if str(v.get("cveID", "")).upper() == cve.upper()), None)
        return src("CISA KEV", "match" if hit else "no-match", f"{hit.get('vendorProject','')} {hit.get('product','')}: {hit.get('vulnerabilityName','Known exploited')}" if hit else "CVE non presente nel catalogo KEV", "alta", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", kev=bool(hit), dueDate=hit.get("dueDate") if hit else None)
    out.append(safe_call("CISA KEV", kev))
    def epss():
        data = get_json(f"https://api.first.org/data/v1/epss?cve={urllib.parse.quote(cve)}")
        row = (data.get("data") or [None])[0]
        return src("FIRST EPSS", "match" if row else "no-match", f"EPSS {float(row.get('epss',0))*100:.2f}%, percentile {float(row.get('percentile',0))*100:.2f}%" if row else "EPSS non disponibile", "alta", "https://www.first.org/epss/api", epss=row.get("epss") if row else None, percentile=row.get("percentile") if row else None)
    out.append(safe_call("FIRST EPSS", epss))
    def nvd():
        data = get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve)}")
        item = ((data.get("vulnerabilities") or [{}])[0]).get("cve")
        desc = "NVD record non trovato"
        cvss = None
        if item:
            desc = next((d.get("value") for d in item.get("descriptions", []) if d.get("lang") == "en"), desc)
            metrics = item.get("metrics", {})
            cvss = (((metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or [{}])[0]).get("cvssData") or {}).get("baseScore")
        return src("NVD/NIST", "match" if item else "no-match", desc[:240] + ("…" if len(desc) > 240 else ""), "alta", f"https://nvd.nist.gov/vuln/detail/{urllib.parse.quote(cve)}", cvss=cvss)
    out.append(safe_call("NVD/NIST", nvd))
    return out

def enrich_url(value: str) -> List[Dict[str, Any]]:
    out = []
    def urlhaus():
        data = post_form("https://urlhaus-api.abuse.ch/v1/url/", {"url": value})
        ok = data.get("query_status") == "ok"
        return src("URLhaus", "match" if ok else "no-match", f"Threat: {data.get('threat','n/d')} · status: {data.get('url_status','n/d')}" if ok else "URL non presente in URLhaus", "alta", "https://urlhaus.abuse.ch/")
    out.append(safe_call("URLhaus", urlhaus))
    def threatfox():
        data = post_json("https://threatfox-api.abuse.ch/api/v1/", {"query": "search_ioc", "search_term": value})
        ok = data.get("query_status") == "ok"
        return src("ThreatFox", "match" if ok else "no-match", f"{len(data.get('data') or [])} indicatori correlati" if ok else "Nessun match ThreatFox", "media", "https://threatfox.abuse.ch/")
    out.append(safe_call("ThreatFox", threatfox))
    return out

def enrich_domain(domain: str) -> List[Dict[str, Any]]:
    out = []
    def crtsh():
        data = get_json(f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json")
        names = set()
        if isinstance(data, list):
            for x in data:
                for n in str(x.get("name_value", "")).split("\n"):
                    if n: names.add(n)
        return src("crt.sh", "match" if names else "no-match", f"{len(names)} nomi/certificati pubblici correlati" if names else "Nessun certificato pubblico trovato", "media", f"https://crt.sh/?q={urllib.parse.quote(domain)}", count=len(names))
    out.append(safe_call("crt.sh", crtsh))
    out.extend(enrich_url(domain))
    return out

def enrich_hash(value: str) -> List[Dict[str, Any]]:
    out = []
    def mb():
        data = post_form("https://mb-api.abuse.ch/api/v1/", {"query": "get_info", "hash": value})
        ok = data.get("query_status") == "ok"
        item = (data.get("data") or [{}])[0]
        return src("MalwareBazaar", "match" if ok else "no-match", f"{item.get('signature','malware')} · {item.get('file_type','file')}" if ok else "Hash non presente in MalwareBazaar", "alta", "https://bazaar.abuse.ch/")
    out.append(safe_call("MalwareBazaar", mb))
    def tf():
        data = post_json("https://threatfox-api.abuse.ch/api/v1/", {"query": "search_hash", "hash": value})
        ok = data.get("query_status") == "ok"
        return src("ThreatFox", "match" if ok else "no-match", f"{len(data.get('data') or [])} IOC correlati all'hash" if ok else "Nessun match ThreatFox", "media", "https://threatfox.abuse.ch/")
    out.append(safe_call("ThreatFox", tf))
    return out

def enrich_ip(ip: str) -> List[Dict[str, Any]]:
    out = []
    def ripe():
        data = get_json(f"https://stat.ripe.net/data/whois/data.json?resource={urllib.parse.quote(ip)}")
        records = data.get("data", {}).get("records", [])
        text = json.dumps(records)
        m = re.search(r'org-name", "value": "([^"]+)', text) or re.search(r'descr", "value": "([^"]+)', text)
        return src("RIPEstat WHOIS", "match" if records else "no-match", m.group(1) if m else "WHOIS disponibile" if records else "Nessun record WHOIS", "alta", f"https://stat.ripe.net/{urllib.parse.quote(ip)}")
    out.append(safe_call("RIPEstat WHOIS", ripe))
    def tf():
        data = post_json("https://threatfox-api.abuse.ch/api/v1/", {"query": "search_ioc", "search_term": ip})
        ok = data.get("query_status") == "ok"
        return src("ThreatFox", "match" if ok else "no-match", f"{len(data.get('data') or [])} IOC correlati" if ok else "Nessun match ThreatFox", "media", "https://threatfox.abuse.ch/")
    out.append(safe_call("ThreatFox", tf))
    return out

def summarize_enrichment(ioc_type: str, value: str, sources: List[Dict[str, Any]]) -> Dict[str, Any]:
    matches = [s for s in sources if s.get("status") == "match"]
    high = any(s.get("reliability") == "alta" for s in matches)
    confidence = min(0.95, 0.45 + len(matches) * 0.15 + (0.15 if high else 0)) if matches else 0.25
    impact = "alto" if ioc_type == "cve" and any(s.get("name") == "CISA KEV" and s.get("kev") for s in sources) else "medio-alto" if len(matches) >= 2 else "medio" if matches else "basso"
    rec = "Validare con log interni, asset coinvolti e timeline prima di blocchi o escalation. Se impatto alto, avviare hunting mirato." if matches else "Nessun match forte nelle fonti integrate. Monitorare e verificare altre fonti se il contesto interno è sospetto."
    return {"confidence": round(confidence, 2), "impact": impact, "recommendation": rec, "summary": f"{len(matches)} fonte/i hanno restituito segnali per {ioc_type} {value}." if matches else f"Nessun match forte nelle fonti integrate per {ioc_type} {value}."}

@app.get("/")
def home(): return FileResponse(BASE_DIR / "index.html")

@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    if not req.description.strip(): raise HTTPException(status_code=400, detail="description vuota")
    mode = req.mode if req.mode in {"soc", "ciso", "investigator"} else "soc"
    kw = keyword_detect(req.description); llm = llm_detect(req.description)
    techniques = merge_techniques(kw, llm)
    iocs = extract_iocs(req.description)
    groups = score_groups(techniques)
    return {"mode": "llm+keyword" if llm else "keyword-only", "view_mode": mode, "executive_summary": executive_summary(techniques, groups, iocs, mode), "iocs": iocs, "detected_techniques": techniques, "probable_groups": groups, "operational_actions": operational_actions(techniques, mode), "warning": "I gruppi sono profili TTP compatibili, non attribuzioni certe. Confermare con IOC, malware, infrastruttura, vittimologia, cronologia e fonti CTI."}

@app.post("/api/enrich")
def enrich(req: EnrichRequest, request: Request):
    rate_limit(request)
    value = req.value.strip()
    if not req.consent: raise HTTPException(status_code=400, detail="Consenso esplicito richiesto")
    if not value or len(value) > 2048: raise HTTPException(status_code=400, detail="IOC mancante o troppo lungo")
    ioc_type = req.type if req.type in {"ip", "domain", "url", "hash", "cve", "email", "file", "unknown"} else infer_ioc_type(value)
    if ioc_type == "unknown": ioc_type = infer_ioc_type(value)
    if ioc_type in {"email", "file", "unknown"}:
        return {"ok": True, "type": ioc_type, "value": value, "timestamp": ts(), "mode": "backend aggregatore", "sources": [], "summary": "Tipo IOC non interrogato automaticamente per minimizzazione/privacy.", "recommendation": "Usare fonti manuali e log interni. Non inviare dati personali o file a terzi senza autorizzazione.", "confidence": 0.2, "impact": "da valutare"}
    key = f"{ioc_type}:{value.lower()}"; cached = ENRICH_CACHE.get(key)
    if cached and time.time() - cached["time"] < CACHE_TTL:
        data = dict(cached["data"]); data["cached"] = True; return data
    if ioc_type == "cve": sources = enrich_cve(value)
    elif ioc_type == "url": sources = enrich_url(value)
    elif ioc_type == "domain": sources = enrich_domain(value)
    elif ioc_type == "hash": sources = enrich_hash(value)
    elif ioc_type == "ip": sources = enrich_ip(value)
    else: sources = []
    meta = summarize_enrichment(ioc_type, value, sources)
    data = {"ok": True, "type": ioc_type, "value": value, "timestamp": ts(), "mode": "backend aggregatore", **meta, "sources": sources, "disclaimer": "Segnali OSINT da validare con telemetria interna. Non costituiscono attribuzione certa."}
    ENRICH_CACHE[key] = {"time": time.time(), "data": data}
    return data

@app.get("/api/health")
def api_health(): return {"ok": True, "llm_enabled": bool(os.getenv("OPENAI_API_KEY")), "version": "0.4", "enrich_enabled": True}

@app.get("/health")
def health(): return api_health()
