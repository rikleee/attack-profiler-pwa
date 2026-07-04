import json
import os
import re
from pathlib import Path
from typing import Dict, List, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

try:
    from openai import OpenAI
except Exception:
    OpenAI = None

BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title="ATT&CK Profiler LLM Backend", version="0.3")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class AnalyzeRequest(BaseModel):
    description: str
    mode: str = "soc"  # soc | ciso | investigator

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

IOC_PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "url": r"https?://[^\s\]\)>'\"]+",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "hash": r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b",
    "windows_path": r"[A-Za-z]:\\[^\s\n\r]+",
}
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
NO_DOMAINS = {"microsoft.com", "windows.com"}

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
    return {k:v for k,v in iocs.items() if v}

def keyword_detect(text: str) -> List[Dict[str, Any]]:
    low = text.lower(); out = []
    for tid, data in TECHNIQUES.items():
        matched = [k for k in data["keywords"] if k.lower() in low]
        if matched:
            out.append({"id":tid,"name":data["name"],"tactic":data["tactic"],"confidence":min(0.95,0.55+0.15*len(matched)),"evidence":"; ".join(matched),"source":"keyword","mitigations":data["mitigations"],"detections":data["detections"]})
    return out

def llm_detect(text: str) -> List[Dict[str, Any]]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or OpenAI is None: return []
    allowed = {tid:{"name":v["name"],"tactic":v["tactic"]} for tid,v in TECHNIQUES.items()}
    prompt = "Sei un analista CTI. Estrai solo tecniche MITRE ATT&CK tra quelle consentite. Rispondi solo JSON valido: {\"techniques\":[{\"id\":\"T1566\",\"confidence\":0.0,\"evidence\":\"frase testuale\",\"reason\":\"motivazione breve\"}],\"unknowns\":[\"dato mancante\"]}. Tecniche consentite: " + json.dumps(allowed, ensure_ascii=False) + "\nTesto: " + text
    try:
        client = OpenAI(api_key=api_key)
        resp = client.responses.create(model=os.getenv("OPENAI_MODEL","gpt-4.1-mini"), input=prompt)
        parsed = json.loads(resp.output_text.strip())
    except Exception:
        return []
    out=[]
    for item in parsed.get("techniques",[]):
        tid=item.get("id")
        if tid in TECHNIQUES:
            d=TECHNIQUES[tid]
            out.append({"id":tid,"name":d["name"],"tactic":d["tactic"],"confidence":float(item.get("confidence",0.7)),"evidence":str(item.get("evidence","")),"reason":str(item.get("reason","")),"source":"llm","mitigations":d["mitigations"],"detections":d["detections"]})
    return out

def merge_techniques(*lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for item in [x for lst in lists for x in lst]:
        tid=item["id"]
        if tid not in merged:
            merged[tid]=item
        else:
            old=merged[tid]
            old["confidence"] = max(float(old.get("confidence",0)), float(item.get("confidence",0)))
            old["source"] = "keyword+llm" if old.get("source") != item.get("source") else old.get("source")
            if item.get("evidence") and item["evidence"] not in old.get("evidence",""):
                old["evidence"] = (old.get("evidence","") + "; " + item["evidence"]).strip("; ")
            if item.get("reason"):
                old["reason"] = item["reason"]
    return sorted(merged.values(), key=lambda x: x["id"])

def score_groups(techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ids={t["id"] for t in techniques}; scored=[]
    for group,tids in GROUPS.items():
        match=[tid for tid in tids if tid in ids]
        if match and ids:
            raw=len(match)/len(ids)
            penalty=0.85 if len(ids)<4 else 1
            score=round(raw*penalty,2)
            scored.append({"group":group,"score":score,"confidence":"media" if score>=.61 else "medio-bassa" if score>=.31 else "bassa","matched_techniques":match,"missing_for_attribution":["malware/famiglia","IOC infrastrutturali","vittimologia","cronologia campagna"],"note":"Profilo TTP compatibile: non è attribuzione certa."})
    return sorted(scored,key=lambda x:x["score"],reverse=True)

def operational_actions(techniques: List[Dict[str, Any]], mode: str) -> List[str]:
    ids={t["id"] for t in techniques}
    base=["Preservare log e artefatti prima della bonifica.","Documentare catena di custodia e timeline."]
    if mode=="ciso": base=["Valutare impatto su processi critici, dati e continuità operativa.","Definire priorità di containment, comunicazione e ripristino."]
    if mode=="investigator": base=["Acquisire evidenze in modo ripetibile e documentato.","Separare fatti osservati, inferenze e ipotesi di attribuzione."]
    if {"T1566","T1204"}&ids: base.append("Analizzare email, allegati, header, URL e destinatari della campagna.")
    if "T1059" in ids: base.append("Controllare processi figli di Office, PowerShell, cmd e script engine.")
    if "T1071" in ids: base.append("Analizzare DNS/HTTP/HTTPS, beaconing e bloccare IOC confermati.")
    if "T1547.001" in ids: base.append("Verificare chiavi Run/RunOnce, cartelle Startup e persistenze correlate.")
    if "T1486" in ids: base.append("Isolare host cifrati/sospetti, verificare backup e blast radius.")
    if {"T1560","T1567"}&ids: base.append("Analizzare archivi creati, compressioni massive e upload verso cloud esterni.")
    return base

def executive_summary(techniques, groups, iocs, mode):
    tactics=sorted({t["tactic"] for t in techniques})
    top=groups[0]["group"] if groups else "nessun profilo prevalente"
    return {"mode":mode,"technique_count":len(techniques),"tactics":tactics,"top_profile":top,"ioc_count":sum(len(v) for v in iocs.values()),"assessment":"Compatibilità TTP utile per prioritizzare risposta e hunting; non valida attribuzione senza ulteriori evidenze."}

@app.get("/")
def home(): return FileResponse(BASE_DIR/"index.html")

@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    if not req.description.strip(): raise HTTPException(status_code=400, detail="description vuota")
    mode=req.mode if req.mode in {"soc","ciso","investigator"} else "soc"
    kw=keyword_detect(req.description); llm=llm_detect(req.description)
    techniques=merge_techniques(kw,llm)
    iocs=extract_iocs(req.description)
    groups=score_groups(techniques)
    return {"mode":"llm+keyword" if llm else "keyword-only","view_mode":mode,"executive_summary":executive_summary(techniques,groups,iocs,mode),"iocs":iocs,"detected_techniques":techniques,"probable_groups":groups,"operational_actions":operational_actions(techniques,mode),"warning":"I gruppi sono profili TTP compatibili, non attribuzioni certe. Confermare con IOC, malware, infrastruttura, vittimologia, cronologia e fonti CTI."}

@app.get("/health")
def health(): return {"ok":True,"llm_enabled":bool(os.getenv("OPENAI_API_KEY")),"version":"0.3"}
