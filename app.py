import json
import os
from pathlib import Path
from typing import Dict, List, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

try:
    from openai import OpenAI
except Exception:  # allows local keyword-only operation if SDK is missing
    OpenAI = None

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="ATT&CK Profiler LLM Backend", version="0.2")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    description: str

TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1566": {"name": "Phishing", "tactic": "Initial Access", "keywords": ["phishing", "email", "mail", "allegato", "link malevolo", "spear phishing"], "mitigations": ["Email filtering", "Sandbox allegati", "SPF/DKIM/DMARC"]},
    "T1204": {"name": "User Execution", "tactic": "Execution", "keywords": ["utente ha aperto", "cliccato", "eseguito", "abilita le macro", "abilitato le macro", "apre il file"], "mitigations": ["EDR", "Application control", "Awareness"]},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "keywords": ["macro", "powershell", "script", "cmd", "shell", "wscript", "cscript"], "mitigations": ["Bloccare macro non firmate", "Limitare PowerShell"]},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "Persistence", "keywords": ["registro", "registry", "run key", "startup", "persistenza", "runonce"], "mitigations": ["Monitoraggio chiavi Run/RunOnce", "Least privilege"]},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "keywords": ["c2", "command and control", "dominio esterno", "http", "https", "dns", "beacon"], "mitigations": ["DNS monitoring", "Proxy filtering"]},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement", "keywords": ["rdp", "desktop remoto", "accesso remoto"], "mitigations": ["MFA su RDP", "VPN obbligatoria"]},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion", "keywords": ["disattivato antivirus", "disabilitato edr", "tampering", "disattiva antivirus"], "mitigations": ["Tamper protection", "Hardening EDR"]},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "keywords": ["ransomware", "cifratura", "file cifrati", "riscatto", "cryptolocker"], "mitigations": ["Backup offline", "Segmentazione rete"]},
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection", "keywords": ["archivio", "zip", "rar", "compressione", "compressi", "7z"], "mitigations": ["DLP", "Monitoraggio compressione"]},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "keywords": ["cloud storage", "dropbox", "google drive", "mega", "upload esterno", "servizio cloud", "cloud esterno", "caricarli su un servizio cloud"], "mitigations": ["CASB", "DLP"]},
}

GROUPS: Dict[str, List[str]] = {
    "FIN7": ["T1566", "T1204", "T1059", "T1547.001", "T1071"],
    "APT29": ["T1566", "T1204", "T1059", "T1071"],
    "TA505": ["T1566", "T1204", "T1059", "T1071", "T1486"],
    "LockBit-like ransomware": ["T1021.001", "T1562", "T1486"],
    "Generic Data Exfiltration Actor": ["T1560", "T1567", "T1071"],
}

def keyword_detect(text: str) -> List[Dict[str, Any]]:
    low = text.lower()
    out = []
    for tid, data in TECHNIQUES.items():
        matched = [k for k in data["keywords"] if k.lower() in low]
        if matched:
            out.append({
                "id": tid,
                "name": data["name"],
                "tactic": data["tactic"],
                "confidence": min(0.95, 0.55 + 0.15 * len(matched)),
                "evidence": ", ".join(matched),
                "source": "keyword",
                "mitigations": data["mitigations"],
            })
    return out

def score_groups(techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ids = {t["id"] for t in techniques}
    scored = []
    for group, tids in GROUPS.items():
        match = [tid for tid in tids if tid in ids]
        if match and ids:
            score = len(match) / len(ids)
            scored.append({
                "group": group,
                "score": round(score, 2),
                "confidence": "alta" if score >= .81 else "media" if score >= .61 else "medio-bassa" if score >= .31 else "bassa",
                "matched_techniques": match,
                "note": "Profilo compatibile, non attribuzione certa.",
            })
    return sorted(scored, key=lambda x: x["score"], reverse=True)

def operational_actions(techniques: List[Dict[str, Any]]) -> List[str]:
    ids = {t["id"] for t in techniques}
    actions = ["Preservare log e artefatti prima della bonifica.", "Documentare la catena di custodia."]
    if {"T1566", "T1204"} & ids:
        actions.append("Analizzare email, allegati, header e URL.")
    if "T1059" in ids:
        actions.append("Controllare processi figli di Office, PowerShell, cmd e script engine.")
    if "T1071" in ids:
        actions.append("Analizzare DNS/HTTP/HTTPS e bloccare IOC confermati.")
    if "T1547.001" in ids:
        actions.append("Verificare chiavi Run/RunOnce e startup.")
    if "T1486" in ids:
        actions.append("Isolare host cifrati o sospetti e verificare backup.")
    if {"T1560", "T1567"} & ids:
        actions.append("Analizzare compressioni massive e upload verso cloud esterni.")
    return actions

def llm_detect(text: str) -> List[Dict[str, Any]]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or OpenAI is None:
        return []
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    allowed = {tid: {"name": v["name"], "tactic": v["tactic"]} for tid, v in TECHNIQUES.items()}
    client = OpenAI(api_key=api_key)
    prompt = (
        "Sei un analista CTI. Estrai dal testo solo tecniche MITRE ATT&CK tra quelle consentite. "
        "Rispondi SOLO JSON valido: {\"techniques\":[{\"id\":\"T1566\",\"confidence\":0.0-1.0,\"evidence\":\"frase dal testo\"}],\"unknowns\":[\"...\"]}. "
        f"Tecniche consentite: {json.dumps(allowed, ensure_ascii=False)}\n\nTesto: {text}"
    )
    try:
        resp = client.responses.create(model=model, input=prompt)
        raw = resp.output_text.strip()
        parsed = json.loads(raw)
    except Exception:
        return []
    result = []
    for item in parsed.get("techniques", []):
        tid = item.get("id")
        if tid in TECHNIQUES:
            d = TECHNIQUES[tid]
            result.append({
                "id": tid,
                "name": d["name"],
                "tactic": d["tactic"],
                "confidence": float(item.get("confidence", 0.7)),
                "evidence": str(item.get("evidence", "")),
                "source": "llm",
                "mitigations": d["mitigations"],
            })
    return result

def merge_techniques(a: List[Dict[str, Any]], b: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for item in a + b:
        tid = item["id"]
        if tid not in merged or item.get("confidence", 0) > merged[tid].get("confidence", 0):
            merged[tid] = item
        elif tid in merged:
            merged[tid]["source"] = "keyword+llm" if merged[tid].get("source") != item.get("source") else merged[tid].get("source")
    return list(merged.values())

@app.get("/")
def home():
    return FileResponse(BASE_DIR / "index.html")

@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    if not req.description.strip():
        raise HTTPException(status_code=400, detail="description vuota")
    kw = keyword_detect(req.description)
    llm = llm_detect(req.description)
    techniques = merge_techniques(kw, llm)
    return {
        "mode": "llm+keyword" if llm else "keyword-only",
        "detected_techniques": techniques,
        "probable_groups": score_groups(techniques),
        "operational_actions": operational_actions(techniques),
        "warning": "I gruppi sono profili compatibili, non attribuzioni certe. Confermare con IOC, malware, infrastruttura, vittimologia e fonti CTI.",
    }

@app.get("/health")
def health():
    return {"ok": True, "llm_enabled": bool(os.getenv("OPENAI_API_KEY"))}
