# Presentazione progetto: ATT&CK Profiler PWA

## Elevator pitch

**ATT&CK Profiler PWA** è una Progressive Web App per il triage difensivo di incidenti cyber. L'utente descrive un evento di attacco e l'app restituisce una lettura strutturata secondo MITRE ATT&CK, con IOC, tecniche, detection, mitigazioni, profili TTP compatibili e report operativo.

## Problema affrontato

Durante un incidente cyber le informazioni arrivano spesso in forma frammentata: email sospette, log, alert EDR, domini, hash, comandi PowerShell, segni di persistenza o esfiltrazione. Il rischio è perdere tempo nel trasformare queste informazioni in decisioni operative.

Il progetto nasce per ridurre questo gap: dalla descrizione narrativa dell'evento a una scheda tecnica ordinata, utilizzabile da SOC, CISO, investigatori e team di incident response.

## Utenti target

- Analisti SOC e incident responder.
- CISO e figure di governance cyber.
- Investigatori digitali.
- Studenti e professionisti in formazione su CTI e MITRE ATT&CK.
- Organizzazioni che vogliono una prima classificazione difensiva dell'evento.

## Valore aggiunto

- Trasforma un racconto tecnico in una matrice operativa.
- Aiuta a ragionare per tecniche, tattiche e TTP.
- Supporta una prima prioritizzazione del rischio.
- Produce azioni difensive immediate.
- Mantiene una chiara separazione tra compatibilità TTP e attribuzione certa.
- Include fallback locale quando il backend non è disponibile.

## Architettura logica

```text
Descrizione evento
       |
       v
Frontend PWA
       |
       +--> Backend LLM / API analyze
       |
       +--> Fallback locale euristico
       |
       v
Normalizzazione risultati
       |
       v
Dashboard: Sintesi, IOC, Tecniche, TTP, Azioni, Report
```

## Funzionalità principali

1. Input guidato dell'incidente.
2. Modalità di lettura: SOC, CISO, Investigatore.
3. Selezione del settore: PA, finanza, sanità, energia/OT, PMI.
4. Stima della criticità.
5. Mappatura MITRE ATT&CK.
6. Estrazione automatica degli IOC.
7. Profili TTP compatibili.
8. Azioni consigliate.
9. Report copiabile e scaricabile.
10. Analisi locale di emergenza se il backend non risponde.

## Limiti dichiarati

L'app non deve essere usata per attribuzioni certe. I profili TTP sono compatibilità basate sugli elementi osservati. Ogni risultato deve essere validato con evidenze tecniche, log, fonti CTI aggiornate e analisi umana.

## Evoluzione prevista

### Breve periodo

- Miglioramento grafico dell'interfaccia.
- Aggiunta card statistiche e dashboard più visuale.
- Migliore esperienza mobile.
- Preset di scenari: phishing, ransomware, esfiltrazione, OT, cloud.

### Medio periodo

- Esportazione JSON, PDF e STIX.
- Generazione query Sigma/YARA/SIEM.
- Timeline dell'attacco.
- Mapping ATT&CK più esteso.
- Salvataggio locale delle analisi.

### Lungo periodo

- Integrazione MISP/OpenCTI.
- Import di log e alert.
- Knowledge base CTI aggiornata.
- Dashboard direzionale per CISO.
- Workflow incident response 24/48/72 ore.

## Visione

Il progetto può evolvere in una piccola piattaforma di **Cyber Threat Intelligence operativa**, capace di collegare descrizione dell'incidente, detection engineering, governance del rischio e supporto alle decisioni durante la crisi cyber.
