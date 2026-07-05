# Roadmap miglioramenti interfaccia e funzionalità

Questa roadmap raccoglie le attività pianificate per evolvere ATT&CK Profiler PWA verso le prossime fasi.

## Priorità alta

- Rifinire animazioni, transizioni e toast per errori di rete, salvataggio ed export.
- Migliorare la strategia service worker con modello stale-while-revalidate.
- Aggiungere esportazione PDF lato client solo se il peso della libreria resta sostenibile.
- Ampliare la knowledge base MITRE locale con più tecniche, detection e mitigazioni.
- Migliorare la distinzione tra dato osservato, ipotesi investigativa e azione richiesta.

## Modalità didattica

- Ampliare il glossario con termini come MITRE D3FEND, Purple Teaming e threat hunting.
- Aggiungere un tour guidato alla prima installazione.
- Inserire link a fonti ufficiali affidabili in nuova scheda.

## Integrazione CTI e backend

- Implementare endpoint `/api/enrich/ioc` e `/api/enrich/cve` sul backend.
- Integrare NVD, CISA KEV, FIRST EPSS e feed open source compatibili.
- Applicare caching, rate limiting, timestamp, fonte e livello di affidabilità.
- Mostrare chiaramente nell’interfaccia la provenienza dei dati arricchiti.

## Detection engineering

- Generare modelli Sigma per tecniche rilevate.
- Fornire esempi YARA quando pertinenti.
- Esportare hunting query per SIEM come Elastic, Splunk e Microsoft Sentinel.

## Privacy e sicurezza

- Non inviare IOC a fonti esterne senza consenso esplicito.
- Non inserire API key nel frontend o nel repository.
- Non trasformare mai l’app in strumento offensivo.

## Fasi

1. PWA completa, dashboard, didattica e link MITRE.
2. Enrichment CVE/IOC manuale.
3. Backend CTI con cache e scoring fonti.
4. Integrazione opzionale MISP/OpenCTI per organizzazioni autorizzate.
