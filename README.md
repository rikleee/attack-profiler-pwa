# ATT&CK Profiler PWA

**ATT&CK Profiler PWA** è una Progressive Web App pensata per supportare **SOC, CISO e investigatori digitali** nel triage difensivo di incidenti cyber.

Prendendo come input la descrizione di un evento, l’app restituisce una scheda tecnica strutturata secondo il modello **MITRE ATT&CK**, mettendo in evidenza tecniche, tattiche, IOC, indicatori di comportamento (IOA), profili TTP compatibili, suggerimenti di detection e mitigazione. È uno strumento pensato per la fase di analisi e risposta, non per l’attacco: non contiene funzioni offensive né procedure di compromissione.

## Caratteristiche principali

### PWA moderna e installabile

- Manifest e service worker per la modalità offline: `index.html`, fogli di stile, script e icone vengono messi in cache così che l’app continui a funzionare anche senza connettività.
- Se il backend non risponde l’interfaccia passa automaticamente al motore euristico locale, evitando interruzioni.
- Installabile su Android e browser desktop: basta aprire l’app da un browser compatibile e selezionare “Aggiungi alla schermata Home”.
- Tema scuro/chiaro con design sobrio in stile cyber, tipografia chiara e componenti responsive.

### Dashboard e visualizzazione dei risultati

- Dashboard iniziale con quattro card: livello di rischio stimato, numero di tecniche MITRE rilevate, numero di IOC estratti e profilo TTP principale.
- Timeline visuale della kill chain: per ogni tattica MITRE rilevata viene mostrata la sequenza temporale 0–24h, 24–48h, 48–72h.
- Card tecniche compatte: ogni tecnica riporta ID, nome, tattica, confidence score, evidenza, detection, mitigazioni e link alla pagina ufficiale MITRE.
- Sezioni chiare per IOC, profili TTP, azioni consigliate, fonti e report completo.
- Export report in JSON e download/copia della versione `.txt` direttamente dal browser.

### Modalità operative e didattica

- Supporto a tre prospettive: **SOC**, **CISO** e **Investigatore**.
- Preset di scenario difensivi: phishing con macro e PowerShell, ransomware, esfiltrazione cloud, compromissione account cloud, attacco OT/ICS.
- Modalità didattica opzionale con pulsanti “?” accanto ai concetti principali.
- Pop-up in italiano su MITRE ATT&CK, tattica vs tecnica, IOC, IOA, TTP, confidence score, kill chain, detection, mitigazione, preservazione evidenze e rischio.
- Glossario rapido con ricerca locale per IOC, IOA, TTP, MITRE ATT&CK, Kill Chain, C2, phishing, ransomware, persistence, lateral movement, exfiltration, EDR, SIEM, Sigma, YARA, CVE, CVSS, CWE e CAPEC.

### Persistenza e storico locale

- Le ultime cinque analisi vengono salvate nel `localStorage` del browser.
- La sezione “Analisi recenti” permette di ricaricare un report precedente o cancellare la cronologia locale.
- Non vengono memorizzate chiavi API, token o informazioni di autenticazione.

## Backend e fallback

Il backend attuale rimane invariato:

```text
https://attack-profiler-pwa.onrender.com/api/analyze
```

Quando il backend è configurato con una chiave LLM valida restituisce analisi ragionate e contestuali. In assenza di chiave può utilizzare un motore a parole chiave. Se il backend non risponde entro il timeout, il frontend passa al **motore euristico locale** basato su regole difensive.

## Fonti aperte e privacy

Questa versione include collegamenti diretti alle pagine ufficiali **MITRE ATT&CK** per le tecniche valide. La roadmap prevede arricchimento manuale di IOC e CVE con:

- CISA Known Exploited Vulnerabilities;
- NVD/NIST per CVE, CVSS e CWE;
- FIRST EPSS;
- CISA advisories, CERT-EU, ENISA, CSIRT Italia/ACN;
- feed open source compatibili come CIRCL MISP e Abuse.ch.

Il frontend **non invia automaticamente IOC a servizi esterni**. L’enrichment è manuale, richiede consenso esplicito dell’utente e deve essere implementato lato backend con cache, rate limiting, timestamp, fonte e livello di affidabilità. Le chiavi API non devono mai essere inserite nel frontend o nel repository.

## Utilizzo

1. Apri l’app via GitHub Pages o servendo localmente i file statici.
2. Scrivi o incolla la descrizione di un incidente nell’area di input.
3. Seleziona modalità SOC, CISO o Investigatore, settore e criticità.
4. Avvia l’analisi.
5. Esplora dashboard, IOC, kill chain, tecniche MITRE, profili TTP e azioni.
6. Esporta il report in JSON o TXT.
7. Attiva la modalità didattica per visualizzare spiegazioni contestuali.

## Struttura progetto

```text
index.html
styles.css
app.js
manifest.json
manifest.webmanifest
service-worker.js
icon.svg
README.md
PROJECT_PRESENTATION.md
docs/
```

## Sicurezza e limiti

- Il progetto è esclusivamente difensivo.
- Non genera exploit, payload o procedure di compromissione.
- I profili TTP sono compatibilità comportamentali, non attribuzioni certe.
- Ogni valutazione deve essere validata con log, timeline, evidenze forensi, fonti CTI aggiornate e analisi umana.
- Non inserire chiavi API o informazioni sensibili nel frontend.

## Roadmap sintetica

- **Fase 1**: PWA installabile, interfaccia moderna, service worker, dashboard, timeline, storico locale, modalità didattica, glossario e link MITRE.
- **Fase 2**: arricchimento manuale di IOC e CVE con NVD, CISA KEV, EPSS e fonti aperte.
- **Fase 3**: backend CTI con cache, scoring fonti, report strutturato e query Sigma/YARA.
- **Fase 4**: integrazione opzionale MISP/OpenCTI per organizzazioni autorizzate.

## Disclaimer difensivo

ATT&CK Profiler PWA è uno strumento di supporto analitico, formazione e triage difensivo. Non sostituisce il giudizio dell’analista, le procedure di incident response, l’analisi forense o la threat intelligence aggiornata.
