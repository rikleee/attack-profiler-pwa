# ATT&CK Profiler PWA

**ATT&CK Profiler PWA** è una Progressive Web App pensata per supportare **SOC, CISO e investigatori digitali** nel triage difensivo di incidenti cyber.

Prendendo come input la descrizione di un evento, l’app restituisce una scheda tecnica strutturata secondo il modello **MITRE ATT&CK**, mettendo in evidenza tecniche, tattiche, IOC, indicatori di comportamento (IOA), profili TTP compatibili, suggerimenti di detection, mitigazione e una nuova sezione **Triage CTI** per trasformare gli indicatori in decisioni operative tracciabili. È uno strumento pensato per analisi e risposta, non per l’attacco: non contiene funzioni offensive né procedure di compromissione.

## Caratteristiche principali

### PWA moderna e installabile

- Manifest e service worker per la modalità offline: `index.html`, fogli di stile, script e icone vengono messi in cache così che l’app continui a funzionare anche senza connettività.
- Se il backend non risponde l’interfaccia passa automaticamente al motore euristico locale, evitando interruzioni.
- Installabile su Android e browser desktop: basta aprire l’app da un browser compatibile e selezionare “Aggiungi alla schermata Home”.
- Tema scuro/chiaro con design sobrio in stile cyber, tipografia chiara e componenti responsive.

### Dashboard e visualizzazione dei risultati

- Dashboard iniziale con quattro card: livello di rischio stimato, numero di tecniche MITRE rilevate, numero di IOC estratti e profilo TTP principale.
- Timeline visuale della kill chain per le tattiche MITRE rilevate.
- Card tecniche compatte: ogni tecnica riporta ID, nome, tattica, confidence score, evidenza, detection, mitigazioni e link alla pagina ufficiale MITRE.
- Sezioni chiare per sintesi, **Triage CTI**, IOC, profili TTP, azioni consigliate, fonti e report completo.
- Export report in JSON e download/copia della versione `.txt` direttamente dal browser.

### Triage CTI implementato nella UI

Dopo ogni analisi, la tab **Triage CTI** crea una card per ogni IOC estratto. Ogni card include:

- tipo e valore dell’IOC;
- provenienza del dato: osservato dall’utente, inferenza locale, backend o fonte esterna quando disponibile;
- timestamp dell’analisi;
- affidabilità della fonte;
- confidence;
- impatto stimato;
- stato operativo selezionabile: da contestualizzare, in monitoraggio, da validare, blocco consigliato, archiviato;
- decisione consigliata derivata da una matrice **impatto × fiducia**;
- motivazione della decisione;
- pulsante **Arricchisci IOC** solo manuale;
- avviso privacy/operational security prima di qualunque enrichment.

La logica resta difensiva: l’app non invia automaticamente IOC a servizi esterni, non effettua query silenziose e non contiene API key nel frontend.

### Modalità operative e didattica

- Supporto a tre prospettive: **SOC**, **CISO** e **Investigatore**.
- Preset di scenario difensivi: phishing con macro e PowerShell, ransomware, esfiltrazione cloud, compromissione account cloud, attacco OT/ICS.
- Modalità didattica opzionale con pulsanti “?” accanto ai concetti principali.
- Pop-up in italiano su MITRE ATT&CK, tattica vs tecnica, IOC, IOA, TTP, confidence score, kill chain, detection, mitigazione, preservazione evidenze, rischio e Triage CTI.
- Glossario rapido con ricerca locale per IOC, IOA, TTP, CTI, confidence, MITRE ATT&CK, Kill Chain, C2, phishing, ransomware, persistence, lateral movement, exfiltration, EDR, SIEM, Sigma, YARA, CVE, CVSS, CWE e CAPEC.

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

Questa versione include collegamenti diretti alle pagine ufficiali **MITRE ATT&CK** per le tecniche valide. Il pulsante **Arricchisci IOC** è intenzionalmente manuale e non trasmette indicatori dal frontend. Un eventuale backend CTI autorizzato dovrà gestire consenso esplicito, minimizzazione del dato, cache, rate limiting, audit log, timestamp, fonte e livello di affidabilità.

Le chiavi API non devono mai essere inserite nel frontend o nel repository.

## Utilizzo

1. Apri l’app via GitHub Pages o servendo localmente i file statici.
2. Scrivi o incolla la descrizione di un incidente nell’area di input.
3. Seleziona modalità SOC, CISO o Investigatore, settore e criticità.
4. Avvia l’analisi.
5. Esplora dashboard, Triage CTI, IOC, kill chain, tecniche MITRE, profili TTP e azioni.
6. Modifica lo stato operativo degli IOC quando l’analista valida nuove evidenze.
7. Esporta il report in JSON o TXT.
8. Attiva la modalità didattica per visualizzare spiegazioni contestuali.

## Struttura progetto

```text
index.html
styles.css
cti.css
app.js
cti.js
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
- Nessun IOC viene inviato automaticamente a fonti esterne.

## Roadmap sintetica

- **Fase 1**: PWA installabile, interfaccia moderna, service worker, dashboard, timeline, storico locale, modalità didattica, glossario e link MITRE.
- **Fase 2**: Triage CTI locale con matrice impatto × fiducia e stato operativo IOC selezionabile.
- **Fase 3**: arricchimento manuale di IOC e CVE con fonti aperte tramite backend autorizzato.
- **Fase 4**: backend CTI con cache, scoring fonti, report strutturato e query Sigma/YARA.
- **Fase 5**: integrazione opzionale MISP/OpenCTI per organizzazioni autorizzate.

## Disclaimer difensivo

ATT&CK Profiler PWA è uno strumento di supporto analitico, formazione e triage difensivo. Non sostituisce il giudizio dell’analista, le procedure di incident response, l’analisi forense o la threat intelligence aggiornata.
