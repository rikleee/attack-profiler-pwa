# Presentazione progetto: ATT&CK Profiler PWA

## Introduzione

Nella gestione di un incidente informatico è essenziale ricostruire rapidamente **cosa è accaduto**, **come l’attore si è mosso** e **quali decisioni difensive assumere**. Le informazioni arrivano spesso come descrizioni testuali, alert eterogenei o IOC isolati: l’analista deve trasformarle in una sequenza coerente di TTP, detection, mitigazioni e priorità operative.

## Obiettivo della soluzione

**ATT&CK Profiler PWA** è uno strumento **difensivo** che aiuta ad analizzare descrizioni di incidenti e a mappare rapidamente le evidenze sulle tecniche **MITRE ATT&CK**, evidenziando IOC, IOA, TTP compatibili, detection, mitigazioni, priorità e decisioni operative. La stessa analisi può essere letta secondo tre prospettive: SOC, CISO e Investigatore.

La nuova versione implementa realmente nella UI una sezione **Triage CTI**, ispirata ai concetti di threat hunting e threat intelligence platform: ogni IOC diventa una scheda decisionale con fonte, affidabilità, confidence, impatto, stato operativo, motivazione e avviso privacy/OPSEC.

## Architettura PWA

La soluzione è composta da tre livelli:

- **Frontend PWA**: realizzato in HTML, CSS e JavaScript vanilla. Registra un service worker che abilita la cache di `index.html`, manifest, script, fogli di stile e icone per l’uso offline.
- **Backend su Render**: endpoint `https://attack-profiler-pwa.onrender.com/api/analyze`. Se configurato con chiave LLM valida, elabora le descrizioni tramite modello di linguaggio. In assenza di chiave può usare un motore keyword.
- **Fallback locale**: se il backend non risponde, il frontend invoca un motore euristico locale che costruisce un report difensivo di base, inclusa la matrice di Triage CTI.

```text
Descrizione evento
       |
       v
Frontend PWA installabile
       |
       +--> Backend Render /api/analyze
       |
       +--> Fallback locale euristico
       |
       v
Dashboard, Triage CTI, kill chain, MITRE, IOC, TTP, azioni, report
```

## Funzionalità principali

- Dashboard con rischio, tecniche rilevate, IOC e profilo TTP principale.
- Tab **Triage CTI** visibile dopo ogni analisi.
- Timeline visuale della kill chain.
- Card MITRE con ID, nome, tattica, confidence score, evidenza, detection, mitigazioni e link ufficiale.
- Preset difensivi per phishing, ransomware, esfiltrazione cloud, compromissione account cloud e OT/ICS.
- Export JSON e TXT.
- Storico locale delle ultime cinque analisi tramite `localStorage`.
- Tema dark cyber con possibilità di tema chiaro.

## Triage CTI

Per ogni IOC estratto la UI crea una card contenente:

- tipo e valore;
- provenienza del dato: osservato dall’utente, inferenza locale, backend o fonte esterna quando disponibile;
- timestamp dell’analisi;
- affidabilità della fonte;
- confidence;
- impatto stimato;
- stato operativo selezionabile;
- decisione consigliata secondo matrice **impatto × fiducia**;
- motivazione della decisione;
- pulsante **Arricchisci IOC** solo manuale;
- avviso privacy/operational security.

Gli stati operativi disponibili sono: da contestualizzare, in monitoraggio, da validare, blocco consigliato e archiviato.

## Modalità SOC, CISO e Investigatore

- **SOC / Incident Response**: privilegia detection, hunting, contenimento e verifica degli asset coinvolti.
- **CISO / Decisioni**: evidenzia impatto, rischio, priorità, escalation e comunicazione verso stakeholder.
- **Investigatore / Evidenze**: orienta la lettura verso IOC, timeline, preservazione log e catena di custodia.

## Modalità didattica e glossario

Un interruttore permette di attivare la **modalità didattica**, aggiungendo icone di aiuto vicino a termini e sezioni. I pop-up spiegano in italiano MITRE ATT&CK, IOC, IOA, TTP, confidence score, kill chain, detection, mitigazione, preservazione evidenze, rischio e Triage CTI.

È incluso un glossario rapido con ricerca locale per termini come IOC, IOA, CTI, confidence, TTP, C2, phishing, ransomware, persistence, lateral movement, exfiltration, EDR, SIEM, Sigma, YARA, CVE, CVSS, CWE e CAPEC.

## Enrichment CTI e fonti aperte

L’app integra link ufficiali MITRE ATT&CK. L’arricchimento degli IOC resta manuale e non automatico. Prima dell’invio di un IOC a fonti esterne, l’utente deve essere autorizzato e valutare privacy, sensibilità del caso, minimizzazione del dato e policy interne. Le API key devono restare lato backend come variabili ambiente.

## Limiti e sicurezza

L’app non fornisce exploit, payload, procedure di compromissione o funzioni offensive. Le attribuzioni sono probabilistiche: un profilo TTP compatibile indica somiglianza comportamentale, non prova definitiva. Ogni risultato va validato con log, timeline, evidenze forensi e CTI aggiornata.

## Roadmap evolutiva

1. **Fase 1** – PWA completa, UI moderna, service worker, dashboard, timeline, modalità didattica, glossario, storico locale e link MITRE.
2. **Fase 2** – Triage CTI locale con matrice impatto × fiducia e stato operativo IOC selezionabile.
3. **Fase 3** – enrichment manuale IOC/CVE con fonti aperte tramite backend autorizzato.
4. **Fase 4** – backend CTI con cache, rate limiting, scoring delle fonti e report strutturato.
5. **Fase 5** – integrazione opzionale MISP/OpenCTI per organizzazioni autorizzate.

## Conclusione

ATT&CK Profiler PWA colma il divario tra descrizione narrativa dell’incidente e analisi strutturata difensiva. Con il Triage CTI, l’app distingue fatti osservati, ipotesi analitiche e decisioni operative sugli IOC, mantenendo il focus su SOC, CISO, investigatore e incident response.
