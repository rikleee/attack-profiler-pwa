import express from 'express';
import cors from 'cors';
import helmet from 'helmet';

const app = express();
const PORT = process.env.PORT || 3000;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://rikleee.github.io,http://localhost:3000,http://localhost:8080').split(',').map(s => s.trim());
const CACHE_TTL_MS = Number(process.env.CACHE_TTL_MS || 30 * 60 * 1000);
const TIMEOUT_MS = Number(process.env.SOURCE_TIMEOUT_MS || 6500);
const MAX_VALUE_LENGTH = 2048;
const cache = new Map();
const rate = new Map();

app.disable('x-powered-by');
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: false
}));
app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.some(o => origin.startsWith(o))) return cb(null, true);
    return cb(new Error('Origin non autorizzata'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));
app.use(express.json({ limit: '16kb' }));

function now() { return new Date().toISOString(); }
function clean(s) { return String(s || '').trim(); }
function cacheKey(type, value) { return `${type}:${value.toLowerCase()}`; }
function inferType(value) {
  const v = clean(value);
  if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return 'cve';
  if (/^[a-f0-9]{32,64}$/i.test(v)) return 'hash';
  if (/^https?:\/\//i.test(v)) return 'url';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ip';
  if (/@/.test(v)) return 'email';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return 'domain';
  return 'unknown';
}
function validType(type) { return ['ip','domain','url','hash','cve','email','file','unknown'].includes(type); }
function rateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const t = Date.now();
  const windowMs = 60_000;
  const max = 30;
  const item = rate.get(ip) || { start: t, count: 0 };
  if (t - item.start > windowMs) { item.start = t; item.count = 0; }
  item.count++;
  rate.set(ip, item);
  if (item.count > max) return res.status(429).json({ ok: false, error: 'Rate limit superato', timestamp: now() });
  next();
}
async function fetchJson(url, options = {}) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(url, { ...options, signal: ac.signal, headers: { 'User-Agent': 'ATTACK-Profiler-PWA-CTI/1.0 defensive research', ...(options.headers || {}) } });
    const text = await r.text();
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return JSON.parse(text);
  } finally { clearTimeout(timer); }
}
async function postForm(url, body) {
  return fetchJson(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body).toString()
  });
}
async function postJson(url, body) {
  return fetchJson(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
}
function source(name, status, detail, extra = {}) {
  return { name, status, detail, timestamp: now(), reliability: extra.reliability || 'media', url: extra.url || '', ...extra };
}
async function enrichCve(cve) {
  const out = [];
  try {
    const kev = await fetchJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    const hit = (kev.vulnerabilities || []).find(v => String(v.cveID).toUpperCase() === cve.toUpperCase());
    out.push(source('CISA KEV', hit ? 'match' : 'no-match', hit ? `${hit.vendorProject || ''} ${hit.product || ''}: ${hit.vulnerabilityName || 'Known exploited vulnerability'}` : 'CVE non presente nel catalogo KEV CISA', { reliability: 'alta', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', kev: Boolean(hit), dueDate: hit?.dueDate }));
  } catch (e) { out.push(source('CISA KEV', 'error', e.message, { reliability: 'alta' })); }
  try {
    const epss = await fetchJson(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`);
    const row = epss.data?.[0];
    out.push(source('FIRST EPSS', row ? 'match' : 'no-match', row ? `EPSS ${(Number(row.epss) * 100).toFixed(2)}%, percentile ${(Number(row.percentile) * 100).toFixed(2)}%` : 'EPSS non disponibile', { reliability: 'alta', url: 'https://www.first.org/epss/api', epss: row?.epss, percentile: row?.percentile }));
  } catch (e) { out.push(source('FIRST EPSS', 'error', e.message, { reliability: 'alta' })); }
  try {
    const nvd = await fetchJson(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve)}`);
    const item = nvd.vulnerabilities?.[0]?.cve;
    const desc = item?.descriptions?.find(d => d.lang === 'en')?.value || 'NVD record non trovato';
    const cvss = item?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || item?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || item?.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore;
    out.push(source('NVD/NIST', item ? 'match' : 'no-match', item ? `${desc.slice(0, 220)}${desc.length > 220 ? '…' : ''}` : desc, { reliability: 'alta', url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`, cvss }));
  } catch (e) { out.push(source('NVD/NIST', 'error', e.message, { reliability: 'alta' })); }
  return out;
}
async function enrichUrl(value) {
  const out = [];
  try {
    const u = await postForm('https://urlhaus-api.abuse.ch/v1/url/', { url: value });
    out.push(source('URLhaus', u.query_status === 'ok' ? 'match' : 'no-match', u.query_status === 'ok' ? `Threat: ${u.threat || 'n/d'} · status: ${u.url_status || 'n/d'}` : 'URL non presente in URLhaus', { reliability: 'alta', url: 'https://urlhaus.abuse.ch/' }));
  } catch (e) { out.push(source('URLhaus', 'error', e.message, { reliability: 'alta' })); }
  try {
    const t = await postJson('https://threatfox-api.abuse.ch/api/v1/', { query: 'search_ioc', search_term: value });
    out.push(source('ThreatFox', t.query_status === 'ok' ? 'match' : 'no-match', t.query_status === 'ok' ? `${t.data?.length || 0} indicatori correlati` : 'Nessun match ThreatFox', { reliability: 'media', url: 'https://threatfox.abuse.ch/' }));
  } catch (e) { out.push(source('ThreatFox', 'error', e.message, { reliability: 'media' })); }
  return out;
}
async function enrichDomain(domain) {
  const out = [];
  try {
    const data = await fetchJson(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`);
    const unique = new Set((Array.isArray(data) ? data : []).flatMap(x => String(x.name_value || '').split('\n')).filter(Boolean));
    out.push(source('crt.sh', unique.size ? 'match' : 'no-match', unique.size ? `${unique.size} nomi/certificati pubblici correlati` : 'Nessun certificato pubblico trovato', { reliability: 'media', url: `https://crt.sh/?q=${encodeURIComponent(domain)}`, count: unique.size }));
  } catch (e) { out.push(source('crt.sh', 'error', e.message, { reliability: 'media' })); }
  out.push(...await enrichUrl(domain));
  return out;
}
async function enrichHash(hash) {
  const out = [];
  try {
    const mb = await postForm('https://mb-api.abuse.ch/api/v1/', { query: 'get_info', hash });
    out.push(source('MalwareBazaar', mb.query_status === 'ok' ? 'match' : 'no-match', mb.query_status === 'ok' ? `${mb.data?.[0]?.signature || 'malware'} · ${mb.data?.[0]?.file_type || 'file'}` : 'Hash non presente in MalwareBazaar', { reliability: 'alta', url: 'https://bazaar.abuse.ch/' }));
  } catch (e) { out.push(source('MalwareBazaar', 'error', e.message, { reliability: 'alta' })); }
  try {
    const t = await postJson('https://threatfox-api.abuse.ch/api/v1/', { query: 'search_hash', hash });
    out.push(source('ThreatFox', t.query_status === 'ok' ? 'match' : 'no-match', t.query_status === 'ok' ? `${t.data?.length || 0} IOC correlati all'hash` : 'Nessun match ThreatFox', { reliability: 'media', url: 'https://threatfox.abuse.ch/' }));
  } catch (e) { out.push(source('ThreatFox', 'error', e.message, { reliability: 'media' })); }
  return out;
}
async function enrichIp(ip) {
  const out = [];
  try {
    const ripe = await fetchJson(`https://stat.ripe.net/data/whois/data.json?resource=${encodeURIComponent(ip)}`);
    const records = ripe.data?.records || [];
    const org = JSON.stringify(records).match(/org-name","value":"([^"]+)/)?.[1] || JSON.stringify(records).match(/descr","value":"([^"]+)/)?.[1] || 'WHOIS disponibile';
    out.push(source('RIPEstat WHOIS', records.length ? 'match' : 'no-match', org, { reliability: 'alta', url: `https://stat.ripe.net/${encodeURIComponent(ip)}` }));
  } catch (e) { out.push(source('RIPEstat WHOIS', 'error', e.message, { reliability: 'alta' })); }
  try {
    const t = await postJson('https://threatfox-api.abuse.ch/api/v1/', { query: 'search_ioc', search_term: ip });
    out.push(source('ThreatFox', t.query_status === 'ok' ? 'match' : 'no-match', t.query_status === 'ok' ? `${t.data?.length || 0} IOC correlati` : 'Nessun match ThreatFox', { reliability: 'media', url: 'https://threatfox.abuse.ch/' }));
  } catch (e) { out.push(source('ThreatFox', 'error', e.message, { reliability: 'media' })); }
  return out;
}
function summarize(type, value, sources) {
  const matches = sources.filter(s => s.status === 'match');
  const highMatch = matches.some(s => s.reliability === 'alta');
  const confidence = matches.length ? Math.min(0.95, 0.45 + matches.length * 0.15 + (highMatch ? 0.15 : 0)) : 0.25;
  const impact = type === 'cve' && sources.some(s => s.name === 'CISA KEV' && s.kev) ? 'alto' : matches.length >= 2 ? 'medio-alto' : matches.length ? 'medio' : 'basso';
  const recommendation = matches.length ? 'Validare con log interni, asset coinvolti e timeline prima di blocchi o escalation. Se impatto alto, aprire hunting mirato.' : 'Nessun match rilevante nelle fonti integrate. Mantenere monitoraggio e verificare altre fonti se il contesto interno è sospetto.';
  return { confidence, impact, recommendation, summary: matches.length ? `${matches.length} fonte/i hanno restituito segnali per ${type} ${value}.` : `Nessun match forte nelle fonti integrate per ${type} ${value}.` };
}
app.get('/api/health', (req, res) => res.json({ ok: true, service: 'attack-profiler-cti-backend', timestamp: now() }));
app.post('/api/enrich', rateLimit, async (req, res) => {
  const value = clean(req.body?.value);
  const type = validType(req.body?.type) ? req.body.type : inferType(value);
  if (!req.body?.consent) return res.status(400).json({ ok: false, error: 'Consenso esplicito richiesto', timestamp: now() });
  if (!value || value.length > MAX_VALUE_LENGTH) return res.status(400).json({ ok: false, error: 'IOC mancante o troppo lungo', timestamp: now() });
  if (type === 'email' || type === 'file' || type === 'unknown') {
    return res.json({ ok: true, type, value, timestamp: now(), mode: 'backend aggregatore', sources: [], summary: 'Tipo IOC non interrogato automaticamente per minimizzazione/privacy. Usare fonti manuali e log interni.', recommendation: 'Non inviare email, file o dati personali a fonti esterne senza autorizzazione.', confidence: 0.2, impact: 'da valutare' });
  }
  const key = cacheKey(type, value);
  const cached = cache.get(key);
  if (cached && Date.now() - cached.t < CACHE_TTL_MS) return res.json({ ...cached.data, cached: true });
  let sources = [];
  if (type === 'cve') sources = await enrichCve(value);
  else if (type === 'url') sources = await enrichUrl(value);
  else if (type === 'domain') sources = await enrichDomain(value);
  else if (type === 'hash') sources = await enrichHash(value);
  else if (type === 'ip') sources = await enrichIp(value);
  const meta = summarize(type, value, sources);
  const data = { ok: true, type, value, timestamp: now(), mode: 'backend aggregatore', ...meta, sources, disclaimer: 'Segnali OSINT da validare con telemetria interna. Non costituiscono attribuzione certa.' };
  cache.set(key, { t: Date.now(), data });
  return res.json(data);
});
app.use((err, req, res, next) => res.status(500).json({ ok: false, error: 'Errore backend CTI', detail: err.message, timestamp: now() }));
app.listen(PORT, () => console.log(`CTI backend listening on ${PORT}`));
