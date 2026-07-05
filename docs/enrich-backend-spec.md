# Specifica endpoint `/api/enrich`

Questa PWA chiama l'endpoint backend:

```text
POST https://attack-profiler-pwa.onrender.com/api/enrich
```

L'endpoint deve essere implementato lato backend, non nel frontend GitHub Pages, perché molte fonti CTI richiedono API key, CORS compatibile, rate limit, cache e controllo di policy.

## Obiettivo

Aggregare fonti CTI pubbliche o autorizzate per un singolo IOC scelto esplicitamente dall'utente, restituendo una scheda normalizzata. Non deve mai ricevere log completi, file, descrizioni di indagine o dati personali non necessari.

## Request

```json
{
  "type": "ip|domain|url|hash|cve|email|file|unknown",
  "value": "IOC scelto dall'utente",
  "consent": true,
  "source_policy": "allowlisted_backend_only"
}
```

## Response consigliata

```json
{
  "ok": true,
  "type": "domain",
  "value": "example.com",
  "timestamp": "2026-07-05T10:00:00.000Z",
  "mode": "backend aggregatore",
  "summary": "Sintesi difensiva del risultato.",
  "recommendation": "Monitorare, validare o bloccare in base a impatto e confidence.",
  "confidence": 0.72,
  "impact": "medio",
  "sources": [
    {
      "name": "URLhaus",
      "status": "match|no-match|error|skipped",
      "detail": "Risultato sintetico",
      "url": "link alla fonte",
      "timestamp": "2026-07-05T10:00:00.000Z",
      "reliability": "alta|media|bassa"
    }
  ]
}
```

## Fonti iniziali consigliate

### CVE
- CISA KEV
- FIRST EPSS
- NVD/NIST
- CERT-EU / CISA advisories

### URL e domini
- URLhaus
- ThreatFox
- crt.sh
- OTX se autorizzato
- VirusTotal solo con API key e policy esplicita

### Hash
- MalwareBazaar
- ThreatFox
- VirusTotal solo con API key e policy esplicita

### IP
- RIPEstat
- GreyNoise se autorizzato
- AbuseIPDB se autorizzato
- Spamhaus / Talos come consultazione o integrazione conforme

### Ransomware / contesto
- Ransomfeed
- Ransomware.live
- Webamon Intelligence se espone modalità compatibile o consultazione manuale
- CISA StopRansomware

## Garanzie obbligatorie

- Consent esplicito lato UI.
- Nessun arricchimento automatico.
- Allowlist di fonti.
- Rate limiting.
- Cache con TTL.
- Timeout per fonte.
- Logging minimale e privo di dati sensibili.
- Nessuna API key nel frontend.
- Sanitizzazione input.
- Limite dimensione request.
- Output con fonte, timestamp, affidabilità, confidence e link origine.
- Segnalazione chiara di risultati non conclusivi.

## Limiti

L'arricchimento non è attribuzione certa. Un match su fonte OSINT è un segnale da validare con telemetria interna, contesto asset, timeline, evidenze forensi e valutazione umana.
