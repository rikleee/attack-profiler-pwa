# ATT&CK Profiler PWA

![Status](https://img.shields.io/badge/status-prototype-blue) ![MITRE ATT%26CK](https://img.shields.io/badge/MITRE-ATT%26CK-red) ![PWA](https://img.shields.io/badge/PWA-ready-brightgreen)

**ATT&CK Profiler PWA** è una web app difensiva pensata per trasformare la descrizione di un incidente cyber in una prima lettura operativa basata su MITRE ATT&CK.

L'obiettivo è aiutare analisti SOC, CISO, investigatori e team di incident response a strutturare rapidamente le informazioni disponibili, evidenziando tecniche, tattiche, IOC, profili TTP compatibili e azioni di contenimento.

---

## Cosa fa

- Analizza una descrizione testuale di un attacco cyber.
- Estrae IOC come IP, domini, URL, email, hash e nomi file.
- Mappa le possibili tecniche MITRE ATT&CK.
- Suggerisce detection, mitigazioni e attività operative.
- Stima profili TTP compatibili, senza attribuzione certa.
- Genera un report testuale copiabile o scaricabile.
- Funziona con backend LLM quando disponibile e con fallback locale euristico se il backend non risponde.

---

## Modalità di analisi

### SOC / Incident Response
Vista tecnica orientata a detection, triage, contenimento e hunting.

### CISO / Decisioni
Vista sintetica per priorità, rischio, escalation, impatto e governance.

### Investigatore / Evidenze
Vista orientata a IOC, catena degli eventi, preservazione delle evidenze e ricostruzione della timeline.

---

## Flusso operativo

1. L'utente descrive l'evento osservato.
2. L'app invia la richiesta al backend LLM.
3. Se il backend non è raggiungibile, entra in funzione l'analisi locale.
4. Il risultato viene organizzato in sezioni navigabili.
5. Il report può essere copiato o scaricato per successive attività operative.

---

## Sezioni del risultato

- **Sintesi operativa**: quadro generale, rischio, tecniche, IOC e profilo principale.
- **IOC estratti**: indicatori tecnici separati per categoria.
- **Tecniche MITRE**: tecnica, tattica, confidenza, evidenza, detection e mitigazione.
- **Profili TTP compatibili**: cluster probabilistici basati sulle tecniche osservate.
- **Azioni consigliate**: contenimento, preservazione evidenze, escalation e detection engineering.
- **Report testuale**: output pronto per copia o download.

---

## Avvertenza importante

Questo progetto ha finalità **difensive, formative e di supporto al triage**.  
L'attribuzione a gruppi o cluster è solo probabilistica e deve essere sempre validata con log, evidenze forensi, fonti CTI aggiornate e analisi umana.

---

## Roadmap miglioramenti

- Aggiunta di una knowledge base MITRE ATT&CK più completa.
- Esportazione in PDF/JSON/STIX.
- Query Sigma e YARA generate automaticamente.
- Integrazione con MISP o piattaforme CTI.
- Timeline dell'attacco con kill chain visuale.
- Dashboard CISO con impatto, priorità e azioni entro 24/48/72 ore.
- Modalità offline PWA completa con service worker e manifest.

---

## Tecnologie

- Frontend: HTML, CSS, JavaScript vanilla.
- Backend: API LLM esterna.
- Deploy: GitHub Pages / Render.
- Modello concettuale: MITRE ATT&CK, IOC, TTP, detection engineering e incident response.

---

## Stato progetto

Prototipo funzionante in evoluzione. Ideale come base per un'applicazione più ampia di cyber threat intelligence operativa e supporto decisionale durante la gestione di incidenti cyber.
