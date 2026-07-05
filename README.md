# ATT&CK Profiler PWA

**ATT&CK Profiler PWA** è una Progressive Web App difensiva per Cyber Threat Intelligence, triage incidenti, MITRE ATT&CK, IOC/IOA, detection, mitigazioni, ransomware watch e formazione CTI.

## Struttura attuale

La PWA è stata divisa in pagine per ridurre confusione:

- `index.html` — dashboard principale;
- `intelligence.html` — fonti aperte, Ransomfeed e catalogo enrichment;
- `training.html` — manuale CTI esteso;
- `analyze.html` — analisi incidente, IOC, MITRE, Triage CTI e report;
- `security.html` — checklist postura difensiva e garanzie sicurezza;
- `glossary.html` — glossario CTI.

## Backend

Il backend di analisi principale resta:

```text
https://attack-profiler-pwa.onrender.com/api/analyze
```

È stata aggiunta una predisposizione reale per l’arricchimento IOC:

```text
https://attack-profiler-pwa.onrender.com/api/enrich
```

Il frontend chiama `/api/enrich` solo su azione manuale dell’utente e solo dopo consenso nella UI. Se l’endpoint non è ancora distribuito sul backend Render, la PWA mostra un fallback sicuro con le fonti consigliate.

## Backend CTI enrichment

La cartella `backend/` contiene un server Node/Express pronto per Render con:

- `POST /api/enrich`;
- `GET /api/health`;
- validazione input;
- consenso obbligatorio;
- rate limit in memoria;
- cache TTL;
- timeout per fonte;
- CORS controllato;
- nessuna API key nel frontend;
- logging minimale.

Fonti integrate senza API key:

- CISA KEV;
- FIRST EPSS;
- NVD/NIST;
- URLhaus;
- ThreatFox;
- MalwareBazaar;
- crt.sh;
- RIPEstat.

Fonti come VirusTotal, GreyNoise, AbuseIPDB, HIBP e OTX devono essere integrate solo lato backend con credenziali, policy d’uso e avviso privacy/OPSEC.

## Deploy backend su Render

Per usare il nuovo backend:

```text
Root Directory: backend
Build Command: npm install
Start Command: npm start
```

Variabili consigliate:

```text
ALLOWED_ORIGINS=https://rikleee.github.io,http://localhost:8080
CACHE_TTL_MS=1800000
SOURCE_TIMEOUT_MS=6500
```

## Sicurezza e privacy

- Nessun invio automatico di IOC a fonti esterne.
- Nessun invio di log completi o file a fonti terze.
- Enrichment solo su click manuale.
- Ogni risultato è segnale da validare con telemetria interna.
- Le attribuzioni sono sempre ipotesi, non prova certa.
- CSP, Referrer Policy e Permissions Policy sono applicate alle pagine statiche.

## Focus difensivo

Il progetto è esclusivamente difensivo: SOC, CISO, investigatore, CTI, MITRE ATT&CK, IOC/IOA, detection, mitigazioni e incident response. Non contiene exploit, payload o istruzioni offensive.
