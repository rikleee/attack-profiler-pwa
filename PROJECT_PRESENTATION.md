# Presentazione progetto: ATT&CK Profiler PWA

## Introduzione

Nella gestione di un incidente informatico è essenziale ricostruire in tempi rapidi **cosa è accaduto**, **come l’attaccante si è mosso** e **quali azioni immediatamente intraprendere**. Spesso le informazioni arrivano come descrizioni testuali o alert eterogenei, e l’analista deve trasformarle in una sequenza coerente di TTP per orientarsi fra detection, contenimento e mitigazioni.

## Obiettivo della soluzione

**ATT&CK Profiler PWA** è uno strumento **difensivo** che aiuta ad analizzare descrizioni di incidenti e a mappare rapidamente le evidenze sulle tecniche **MITRE ATT&CK**, evidenziando IOC, IOA, TTP compatibili, detection, mitigazioni e priorità operative. La stessa analisi può essere letta secondo tre prospettive: SOC, CISO e Investigatore.

## Architettura PWA

La soluzione è composta da tre livelli:

- **Frontend PWA**: realizzato in HTML, CSS e JavaScript vanilla. Registra un service worker che abilita la cache di `index.html`, manifest, script, fogli di stile e icone per l’uso offline.
- **Backend su Render**: endpoint `https://attack-profiler-pwa.onrender.com/api/analyze`. Se configurato con chiave LLM valida, elabora le descrizioni tramite modello di linguaggio. In assenza di chiave può usare un motore keyword.
- **Fallback locale**: se il backend non risponde, il frontend invoca un motore euristico locale che costruisce un report difensivo di base.

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
Dashboard, kill chain, MITRE, IOC, TTP, azioni, report
```

## Funzionalità principali

- Dashboard con rischio, tecniche rilevate, IOC e profilo TTP principale.
- Timeline visuale della kill chain su finestre 0–24h, 24–48h, 48–72h.
- Card MITRE con ID, nome, tattica, confidence score, evidenza, detection, mitigazioni e link ufficiale.
- Preset difensivi per phishing, ransomware, esfiltrazione cloud, compromissione account cloud e OT/ICS.
- Export JSON e TXT.
- Storico locale delle ultime cinque analisi tramite `localStorage`.
- Tema dark cyber con possibilità di tema chiaro.

## Modalità SOC, CISO e Investigatore

- **SOC / Incident Response**: privilegia detection, hunting, contenimento e verifica degli asset coinvolti.
- **CISO / Decisioni**: evidenzia impatto, rischio, priorità, escalation e comunicazione verso stakeholder.
- **Investigatore / Evidenze**: orienta la lettura verso IOC, timeline, preservazione log e catena di custodia.

## Modalità didattica e glossario

Un interruttore permette di attivare la **modalità didattica**, aggiungendo icone di aiuto vicino a termini e sezioni. I pop-up spiegano in italiano:

- cos’è MITRE ATT&CK e la differenza fra tattica e tecnica;
- cosa sono IOC, IOA e TTP e perché sono importanti;
- come interpretare il confidence score;
- perché un profilo TTP compatibile non è attribuzione certa;
- la sequenza della kill chain e come leggerla;
- differenze operative tra detection, contenimento, eradicazione, ripristino e hardening;
- importanza della preservazione delle evidenze.

È incluso un glossario rapido con ricerca locale per termini come IOC, IOA, TTP, C2, phishing, ransomware, persistence, lateral movement, exfiltration, EDR, SIEM, Sigma, YARA, CVE, CVSS, CWE e CAPEC.

## Enrichment CTI e fonti aperte

L’app integra link ufficiali MITRE ATT&CK. Nelle fasi successive è prevista l’integrazione manuale e sicura di fonti aperte:

- MITRE ATT&CK;
- NVD/NIST per CVE, CVSS e CWE;
- CISA Known Exploited Vulnerabilities;
- FIRST EPSS;
- CISA, CERT-EU, ENISA, CSIRT Italia/ACN;
- CIRCL MISP e feed Abuse.ch quando compatibili con termini d’uso.

L’arricchimento sarà manuale, mai automatico. Prima dell’invio di un IOC a fonti esterne, l’utente dovrà confermare di essere autorizzato. Le API key resteranno lato backend come variabili ambiente.

## Limiti e sicurezza

L’app non fornisce exploit, payload, procedure di compromissione o funzioni offensive. Le attribuzioni sono probabilistiche: un profilo TTP compatibile indica somiglianza comportamentale, non prova definitiva. Ogni risultato va validato con log, timeline, evidenze forensi e CTI aggiornata.

## Roadmap evolutiva

1. **Fase 1** – PWA completa, UI moderna, service worker, dashboard, timeline, modalità didattica, glossario, storico locale e link MITRE.
2. **Fase 2** – enrichment manuale IOC/CVE con NVD, CISA KEV, EPSS e fonti aperte.
3. **Fase 3** – backend CTI con cache, rate limiting, scoring delle fonti e report strutturato.
4. **Fase 4** – integrazione opzionale MISP/OpenCTI per organizzazioni autorizzate.

## Conclusione

ATT&CK Profiler PWA colma il divario tra descrizione narrativa dell’incidente e analisi strutturata difensiva. È utilizzabile sia in contesti formativi sia in attività reali di triage, mantenendo sempre la distinzione tra fatti osservati, ipotesi analitiche e decisioni operative.
