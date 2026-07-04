# ATT&CK Profiler PWA

![Status](https://img.shields.io/badge/status-PWA%20defensive%20tool-blue) ![MITRE ATT%26CK](https://img.shields.io/badge/MITRE-ATT%26CK-red) ![PWA](https://img.shields.io/badge/PWA-installable-brightgreen)

**ATT&CK Profiler PWA** è una Progressive Web App difensiva per trasformare la descrizione di un incidente cyber in una prima lettura operativa basata su MITRE ATT&CK.

L'obiettivo è aiutare analisti SOC, CISO, investigatori digitali e team di incident response a strutturare rapidamente le informazioni disponibili, evidenziando tecniche, tattiche, IOC, profili TTP compatibili, detection, mitigazioni e azioni di contenimento.

---

## Novità della versione PWA

- Interfaccia più moderna, mobile-first e installabile.
- Manifest PWA dedicato (`manifest.webmanifest`).
- Service worker per cache dell'app shell e uso offline del frontend.
- Icona applicativa SVG (`icon.svg`).
- Stato online/offline visibile nell'interfaccia.
- Pulsante di installazione quando supportato dal browser.
- Preset difensivi per avviare rapidamente scenari di analisi.
- Timeline operativa 24/48/72 ore.
- Export report in `.txt` e `.json`.
- Salvataggio locale della bozza sul dispositivo.

---

## Cosa fa

- Analizza una descrizione testuale di un incidente cyber.
- Estrae IOC come IP, domini, URL, email, hash e nomi file.
- Mappa possibili tecniche MITRE ATT&CK.
- Suggerisce detection, mitigazioni e attività operative.
- Stima profili TTP compatibili, senza attribuzione certa.
- Genera un report testuale copiabile o scaricabile.
- Funziona con backend LLM quando disponibile e con fallback locale euristico se il backend non risponde.

---

## Backend e fallback

Il frontend mantiene il backend attuale:

```text
https://attack-profiler-pwa.onrender.com/api/analyze
```

Se il backend non risponde, l'app passa automaticamente a un'analisi locale euristica. Il fallback non sostituisce una piattaforma CTI o una validazione forense, ma consente di mantenere continuità operativa per triage iniziale, estrazione IOC e prime azioni difensive.

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
5. Il report può essere copiato, scaricato in testo o esportato in JSON.

---

## Sezioni del risultato

- **Sintesi operativa**: quadro generale, rischio, tecniche, IOC e profilo principale.
- **IOC estratti**: indicatori tecnici separati per categoria.
- **Tecniche MITRE**: tecnica, tattica, confidenza, evidenza, detection e mitigazione.
- **Profili TTP compatibili**: cluster probabilistici basati sulle tecniche osservate.
- **Azioni consigliate**: contenimento, preservazione evidenze, escalation e detection engineering.
- **Timeline 24/48/72 ore**: priorità operative per contenimento, hunting, validazione, remediation e governance.
- **Report testuale**: output pronto per copia o download.

---

## Avvertenza importante

Questo progetto ha finalità **difensive, formative e di supporto al triage**.  
L'attribuzione a gruppi o cluster è solo probabilistica e deve essere sempre validata con log, evidenze forensi, fonti CTI aggiornate e analisi umana.

---

## Tecnologie

- Frontend: HTML, CSS, JavaScript vanilla.
- PWA: Web App Manifest + Service Worker.
- Backend: API LLM esterna su Render.
- Deploy: GitHub Pages / Render.
- Modello concettuale: MITRE ATT&CK, IOC, TTP, detection engineering e incident response.

---

## Roadmap miglioramenti

- Knowledge base MITRE ATT&CK più completa.
- Esportazione PDF/STIX.
- Query Sigma/YARA/SIEM generate automaticamente.
- Integrazione con MISP o piattaforme CTI.
- Timeline visuale dell'incidente.
- Dashboard CISO con impatto, priorità e azioni entro 24/48/72 ore.
- Storico locale cifrato delle analisi.

---

## Stato progetto

PWA difensiva funzionante e installabile. Ideale come base per un'applicazione più ampia di cyber threat intelligence operativa e supporto decisionale durante la gestione di incidenti cyber.
