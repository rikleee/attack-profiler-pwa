# Backend CTI Enrichment

Questa cartella contiene un backend Node/Express difensivo per l'endpoint:

```text
POST /api/enrich
```

Serve a interrogare fonti pubbliche lato server e restituire alla PWA una scheda normalizzata di arricchimento IOC.

## Avvio locale

```bash
cd backend
npm install
npm start
```

Health check:

```bash
curl http://localhost:3000/api/health
```

Test arricchimento CVE:

```bash
curl -X POST http://localhost:3000/api/enrich \
  -H 'Content-Type: application/json' \
  -d '{"type":"cve","value":"CVE-2024-3400","consent":true}'
```

## Deploy Render

Se usi Render, crea o aggiorna un servizio Web Node impostando:

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

## Fonti integrate senza API key

- CISA KEV
- FIRST EPSS
- NVD/NIST
- URLhaus
- ThreatFox
- MalwareBazaar
- crt.sh
- RIPEstat

## Fonti non interrogate automaticamente

- VirusTotal
- Have I Been Pwned
- AbuseIPDB
- GreyNoise
- OTX con credenziali

Queste fonti possono registrare query o richiedere API key. Vanno integrate solo con policy esplicita e credenziali lato backend.

## Garanzie

- Solo IOC scelto dall'utente.
- Nessun log completo.
- Nessun file.
- Nessun dato personale se non strettamente autorizzato.
- Rate limit in memoria.
- Cache TTL.
- Timeout per fonte.
- Output con fonte, timestamp, affidabilità, confidence, impatto e raccomandazione.
