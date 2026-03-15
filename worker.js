// CF Bot Guard — Advanced Bot Detection + Analytics + Dashboard
// https://github.com/yourusername/cf-bot-guard

// ─── ISP CLASSIFICATION (heuristic, inspired by TheGreatAzizi) ────
const HOSTING_PATTERN = /(Hosting|Cloud|Datacenter|VPN|Proxy|Infrastructure|Amazon|Google|Microsoft|DigitalOcean|Hetzner|OVH|Vultr|Oracle|Akamai|Fastly|Linode|Scaleway|Contabo|ColoCross|M247|GreenCloud|Tencent|Alibaba|LeaseWeb|Zscaler|Cloudflare|NordVPN|ExpressVPN|Surfshark|Mullvad|Private Internet|CyberGhost|TorGuard|IPVanish|HideMyAss|ProtonVPN|Windscribe)/i;
const MOBILE_PATTERN = /(Mobile|LTE|Cellular|Wireless|4G|5G|Telecommunication|Vodafone|Verizon|Orange|T-Mobile|EE|Three|O2|Sprint|Cricket|Boost|Metro|Visible)/i;
const EDUCATION_PATTERN = /(University|College|Education|School|Research|Academy|JANET|GÉANT|Internet2)/i;
const CORPORATE_PATTERN = /(Business|Enterprise|Corporation|Inc\.|Limited|Ltd\.|PLC|GmbH)/i;

function classifyISP(ispName) {
  if (HOSTING_PATTERN.test(ispName)) return 'hosting';
  if (MOBILE_PATTERN.test(ispName)) return 'mobile';
  if (EDUCATION_PATTERN.test(ispName)) return 'education';
  if (CORPORATE_PATTERN.test(ispName)) return 'corporate';
  return 'residential';
}

// ─── DATACENTER ASNs (fallback for ISPs that don't match patterns) ─
const DATACENTER_ASNS = new Set([
  14061, 16509, 14618, 15169, 8075,
  13335, 20473, 63949, 24940, 16276,
  51167, 197540, 9009, 46606,
  36352, 55286, 62567,
  398101, 206264, 142002,
  45102, 132203, 59930,
  210644, 41378,
]);

// ─── BOT FINGERPRINTING ───────────────────────────────────────────
function fingerprintRequest(request) {
  const cf = request.cf || {};
  const ispName = cf.asOrganization || 'unknown';
  return {
    tlsVersion: cf.tlsVersion || 'unknown',
    tlsCipher: cf.tlsCipher || 'unknown',
    httpProtocol: cf.httpProtocol || 'unknown',
    asn: cf.asn || 0,
    asOrganization: ispName,
    ispType: classifyISP(ispName),
    country: cf.country || 'unknown',
    city: cf.city || 'unknown',
    region: cf.region || 'unknown',
    postalCode: cf.postalCode || 'unknown',
    latitude: cf.latitude || 'unknown',
    longitude: cf.longitude || 'unknown',
    timezone: cf.timezone || 'unknown',
    colo: cf.colo || 'unknown',
    headerCount: [...request.headers.keys()].length,
    headerKeys: [...request.headers.keys()].join(','),
    hasAcceptLanguage: request.headers.has('accept-language'),
    hasAcceptEncoding: request.headers.has('accept-encoding'),
    hasSecFetchSite: request.headers.has('sec-fetch-site'),
    hasSecFetchMode: request.headers.has('sec-fetch-mode'),
    hasSecFetchDest: request.headers.has('sec-fetch-dest'),
    hasSecChUa: request.headers.has('sec-ch-ua'),
    hasSecChUaPlatform: request.headers.has('sec-ch-ua-platform'),
    hasSecChUaMobile: request.headers.has('sec-ch-ua-mobile'),
    hasDnt: request.headers.has('dnt'),
    hasUpgradeInsecure: request.headers.has('upgrade-insecure-requests'),
    hasCacheControl: request.headers.has('cache-control'),
    hasReferer: request.headers.has('referer'),
    acceptLanguage: request.headers.get('accept-language') || '',
  };
}

function calculateBotScore(fingerprint, userAgent) {
  let score = 0;
  const reasons = [];

  if (fingerprint.tlsVersion === 'TLSv1.1' || fingerprint.tlsVersion === 'TLSv1') {
    score += 30; reasons.push('old-tls');
  }
  if (fingerprint.httpProtocol === 'HTTP/1.0') {
    score += 20; reasons.push('http1.0');
  }
  if (!userAgent || userAgent.length === 0) {
    score += 40; reasons.push('no-ua');
  } else if (userAgent.length < 20) {
    score += 15; reasons.push('short-ua');
  }
  if (userAgent && /Mozilla|Chrome|Safari|Firefox/.test(userAgent)) {
    if (!fingerprint.hasSecChUa && !fingerprint.hasSecFetchMode) {
      score += 20; reasons.push('fake-browser-ua');
    }
  }
  if (!fingerprint.hasAcceptLanguage) { score += 15; reasons.push('no-accept-lang'); }
  if (!fingerprint.hasAcceptEncoding) { score += 10; reasons.push('no-accept-enc'); }
  if (!fingerprint.hasSecFetchSite) { score += 5; reasons.push('no-sec-fetch-site'); }
  if (!fingerprint.hasSecFetchMode) { score += 5; reasons.push('no-sec-fetch-mode'); }
  if (!fingerprint.hasSecFetchDest) { score += 5; reasons.push('no-sec-fetch-dest'); }
  if (!fingerprint.hasSecChUa) { score += 5; reasons.push('no-sec-ch-ua'); }
  if (!fingerprint.hasSecChUaPlatform) { score += 3; reasons.push('no-sec-ch-ua-platform'); }
  if (!fingerprint.hasSecChUaMobile) { score += 3; reasons.push('no-sec-ch-ua-mobile'); }
  if (fingerprint.headerCount < 5) { score += 20; reasons.push('few-headers'); }
  else if (fingerprint.headerCount < 8) { score += 10; reasons.push('low-headers'); }

  if (fingerprint.ispType === 'hosting') {
    score += 25; reasons.push('hosting-isp');
  } else if (fingerprint.ispType === 'mobile') {
    score -= 5;
  } else if (fingerprint.ispType === 'residential') {
    score -= 10;
  } else if (fingerprint.ispType === 'education') {
    score -= 5;
  }
  if (fingerprint.ispType !== 'hosting' && DATACENTER_ASNS.has(fingerprint.asn)) {
    score += 20; reasons.push('datacenter-asn');
  }
  if (fingerprint.hasAcceptLanguage) {
    const al = fingerprint.acceptLanguage;
    if (al && !al.includes(',') && !al.includes(';')) {
      score += 8; reasons.push('simple-accept-lang');
    }
  }

  return { score: Math.max(0, Math.min(score, 100)), reasons };
}

// ─── ANALYTICS (optimised: 2 KV writes per page view) ────────────
async function logPageView(env, request, fingerprint, botResult, domain) {
  const url = new URL(request.url);
  const path = url.pathname;
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';

  if (/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|xml|json|txt)$/i.test(path)) return;
  if (path === '/dashboard') return;

  const now = new Date();
  const dateKey = now.toISOString().slice(0, 10);
  const hour = String(now.getUTCHours()).padStart(2, '0');

  // ── Read both keys in parallel (2 reads) ──
  const [dailyRaw, ipRaw] = await Promise.all([
    env.ANALYTICS.get(`daily:${dateKey}`),
    env.ANALYTICS.get(`ip:${dateKey}:${ip}`),
  ]);

  // ── Write 1: Consolidated daily blob (everything in one JSON object) ──
  const d = JSON.parse(dailyRaw || '{}');
  d.pv = (d.pv || 0) + 1;
  if (botResult.score > 50) { d.bots = (d.bots || 0) + 1; } else { d.humans = (d.humans || 0) + 1; }

  if (!d.paths) d.paths = {};     d.paths[path] = (d.paths[path] || 0) + 1;
  if (!d.countries) d.countries = {}; d.countries[fingerprint.country] = (d.countries[fingerprint.country] || 0) + 1;
  if (!d.cities) d.cities = {};   const ck = `${fingerprint.country}-${fingerprint.city}`; d.cities[ck] = (d.cities[ck] || 0) + 1;
  if (!d.hourly) d.hourly = {};   d.hourly[hour] = (d.hourly[hour] || 0) + 1;

  const ua = request.headers.get('user-agent') || '';
  const device = /Mobile|Android|iPhone|iPad/.test(ua) ? 'mobile' : 'desktop';
  if (!d.devices) d.devices = {};  d.devices[device] = (d.devices[device] || 0) + 1;

  const referer = request.headers.get('referer') || '';
  if (referer && !referer.includes(domain)) {
    try {
      const refHost = new URL(referer).hostname;
      if (!d.referrers) d.referrers = {}; d.referrers[refHost] = (d.referrers[refHost] || 0) + 1;
    } catch { /* invalid referer URL */ }
  }

  const ak = `${fingerprint.asn}:${fingerprint.asOrganization}`;
  if (!d.asns) d.asns = {};       d.asns[ak] = (d.asns[ak] || 0) + 1;

  // Meta counters (signals, ISP types, scores, bot geo, infra)
  if (!d.signals) d.signals = {};
  for (const sig of botResult.reasons) { d.signals[sig] = (d.signals[sig] || 0) + 1; }
  if (!d.ispTypes) d.ispTypes = {};   d.ispTypes[fingerprint.ispType] = (d.ispTypes[fingerprint.ispType] || 0) + 1;
  if (!d.scoreBuckets) d.scoreBuckets = {};
  const bucket = botResult.score <= 20 ? '0-20' : botResult.score <= 40 ? '21-40' : botResult.score <= 60 ? '41-60' : botResult.score <= 80 ? '61-80' : '81-100';
  d.scoreBuckets[bucket] = (d.scoreBuckets[bucket] || 0) + 1;
  if (botResult.score > 50) {
    if (!d.botCountries) d.botCountries = {}; d.botCountries[fingerprint.country] = (d.botCountries[fingerprint.country] || 0) + 1;
    if (!d.botPaths) d.botPaths = {};         d.botPaths[path] = (d.botPaths[path] || 0) + 1;
  }
  if (!d.tls) d.tls = {};           d.tls[fingerprint.tlsVersion] = (d.tls[fingerprint.tlsVersion] || 0) + 1;
  if (!d.protocols) d.protocols = {}; d.protocols[fingerprint.httpProtocol] = (d.protocols[fingerprint.httpProtocol] || 0) + 1;
  if (!d.colos) d.colos = {};       d.colos[fingerprint.colo] = (d.colos[fingerprint.colo] || 0) + 1;

  // ── Write 2: IP reputation (separate key for 7-day TTL + list support) ──
  const ipData = JSON.parse(ipRaw || '{"hits":0,"totalScore":0}');
  ipData.hits += 1;
  ipData.totalScore += botResult.score;
  ipData.avgScore = Math.round(ipData.totalScore / ipData.hits);
  ipData.lastSeen = now.toISOString();

  // ── 2 parallel writes (down from ~12) ──
  await Promise.all([
    env.ANALYTICS.put(`daily:${dateKey}`, JSON.stringify(d), { expirationTtl: 90 * 86400 }),
    env.ANALYTICS.put(`ip:${dateKey}:${ip}`, JSON.stringify(ipData), { expirationTtl: 7 * 86400 }),
  ]);
}

// ═══════════════════════════════════════════════════════════════════
// ─── DASHBOARD ────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════

function countryFlag(code) {
  if (!code || code === 'unknown' || code.length !== 2) return '\u{1F310}';
  return String.fromCodePoint(...code.toUpperCase().split('').map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

function truncateIP(ip) {
  if (ip.includes(':')) {
    const parts = ip.split(':');
    return parts.slice(0, 2).join(':') + ':x:x';
  }
  const parts = ip.split('.');
  return parts.slice(0, 2).join('.') + '.x.x';
}

function addDays(dateStr, days) {
  const d = new Date(dateStr + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

function formatDateLong(dateStr) {
  const d = new Date(dateStr + 'T00:00:00Z');
  return d.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
}

function sortObj(obj) {
  return Object.entries(obj || {}).sort((a, b) => b[1] - a[1]);
}

async function getDashboardData(env, dateStr) {
  // Fetch all 7 daily blobs + IP list in parallel (8 reads total)
  const trendDays = Array.from({ length: 7 }, (_, i) => addDays(dateStr, i - 6));
  const [ipList, ...dailyBlobsRaw] = await Promise.all([
    env.ANALYTICS.list({ prefix: `ip:${dateStr}:`, limit: 200 }),
    ...trendDays.map(ds => env.ANALYTICS.get(`daily:${ds}`)),
  ]);

  const dailyBlobs = dailyBlobsRaw.map(raw => JSON.parse(raw || '{}'));
  const todayIdx = trendDays.indexOf(dateStr);
  const daily = dailyBlobs[todayIdx];

  const total = daily.pv || 0;
  const humanCount = daily.humans || 0;
  const botCount = daily.bots || 0;
  const mobile = (daily.devices || {}).mobile || 0;
  const desktop = (daily.devices || {}).desktop || 0;

  // Hourly — extract from daily blob
  const hourly = Array.from({ length: 24 }, (_, h) =>
    (daily.hourly || {})[String(h).padStart(2, '0')] || 0
  );

  // Trend — extract from each day's blob
  const trend = trendDays.map((ds, i) => {
    const blob = dailyBlobs[i];
    return {
      date: ds,
      day: new Date(ds + 'T00:00:00Z').toLocaleDateString('en-US', { weekday: 'short', timeZone: 'UTC' }),
      total: blob.pv || 0,
      humans: blob.humans || 0,
      bots: blob.bots || 0,
    };
  });

  // Convert daily blob objects to sorted arrays
  const paths = sortObj(daily.paths).map(([name, count]) => ({ name, count }));
  const countries = sortObj(daily.countries).map(([name, count]) => ({ name, count }));
  const cities = sortObj(daily.cities).map(([name, count]) => ({ name, count }));
  const referrers = sortObj(daily.referrers).map(([name, count]) => ({ name, count }));
  const asns = sortObj(daily.asns).map(([name, count]) => ({ name, count }));

  // IPs — still separate keys (7-day TTL, need list)
  const ips = (await Promise.all(ipList.keys.map(async k => {
    const data = JSON.parse(await env.ANALYTICS.get(k.name) || '{}');
    return { ip: k.name.slice(`ip:${dateStr}:`.length), hits: data.hits || 0, avgScore: data.avgScore || 0, lastSeen: data.lastSeen || '' };
  }))).sort((a, b) => b.avgScore - a.avgScore);

  // Meta is now embedded in the daily blob
  const meta = {
    signals: daily.signals || {},
    ispTypes: daily.ispTypes || {},
    scoreBuckets: daily.scoreBuckets || {},
    botCountries: daily.botCountries || {},
    tls: daily.tls || {},
    protocols: daily.protocols || {},
    colos: daily.colos || {},
    botPaths: daily.botPaths || {},
  };

  // Compute top threat ASN (hosting type with most hits)
  const topThreatASN = asns
    .filter(a => { const org = a.name.split(':').slice(1).join(':') || ''; return classifyISP(org) === 'hosting'; })
    .slice(0, 1)[0] || null;

  // Datacenter ASN activity
  const dcActivity = asns.filter(a => {
    const asnNum = parseInt(a.name.split(':')[0]);
    return DATACENTER_ASNS.has(asnNum);
  }).map(a => {
    const parts = a.name.split(':');
    return { asn: parts[0], org: parts.slice(1).join(':') || parts[0], count: a.count };
  });

  return { total, humanCount, botCount, mobile, desktop, meta, hourly, trend, paths, countries, cities, referrers, asns, ips, uniqueIPs: ips.length, topThreatASN, dcActivity };
}

function renderDashboard(data, dateStr) {
  const { total, humanCount, botCount, mobile, desktop, meta, hourly, trend, paths, countries, cities, referrers, asns, ips, uniqueIPs, topThreatASN, dcActivity } = data;
  const botRate = total > 0 ? Math.round(botCount / total * 100) : 0;
  const rateColor = botRate < 20 ? '#10b981' : botRate < 50 ? '#f59e0b' : '#ef4444';
  const maxHourly = Math.max(...hourly, 1);
  const maxTrend = Math.max(...trend.map(t => t.total), 1);
  const signals = sortObj(meta.signals);
  const maxSignal = signals.length > 0 ? signals[0][1] : 1;
  const scoreBuckets = meta.scoreBuckets || {};
  const totalScored = Object.values(scoreBuckets).reduce((a, b) => a + b, 0) || 1;
  const ispTypes = sortObj(meta.ispTypes);
  const totalISP = ispTypes.reduce((a, b) => a + b[1], 0) || 1;
  const botCountries = sortObj(meta.botCountries);
  const tlsVersions = sortObj(meta.tls);
  const protocols = sortObj(meta.protocols);
  const colos = sortObj(meta.colos);
  const botPaths = sortObj(meta.botPaths);
  const suspiciousIPs = ips.filter(ip => ip.avgScore > 50).slice(0, 15);
  const maxPath = paths.length > 0 ? paths[0].count : 1;
  const maxCountry = countries.length > 0 ? countries[0].count : 1;

  const ispColors = { residential: '#10b981', hosting: '#ef4444', mobile: '#3b82f6', education: '#8b5cf6', corporate: '#f59e0b' };
  const bucketColors = { '0-20': '#10b981', '21-40': '#22d3ee', '41-60': '#f59e0b', '61-80': '#f97316', '81-100': '#ef4444' };
  const bucketLabels = { '0-20': 'Human', '21-40': 'Likely Human', '41-60': 'Suspicious', '61-80': 'Likely Bot', '81-100': 'Bot' };

  // Build donut gradient
  let donutGrad = '';
  let pctCursor = 0;
  for (const [type, count] of ispTypes) {
    const pct = count / totalISP * 100;
    const color = ispColors[type] || '#64748b';
    donutGrad += `${color} ${pctCursor}% ${pctCursor + pct}%,`;
    pctCursor += pct;
  }
  donutGrad = donutGrad.slice(0, -1) || '#1e293b 0% 100%';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CF Bot Guard — Dashboard</title>
<style>
:root{--bg:#0a0e17;--card:#141b2d;--border:#1e293b;--text:#e2e8f0;--muted:#64748b;--dim:#475569;--green:#10b981;--red:#ef4444;--blue:#3b82f6;--purple:#8b5cf6;--amber:#f59e0b;--cyan:#06b6d4;--orange:#f97316}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;min-height:100vh}
.wrap{max-width:1400px;margin:0 auto;padding:20px}
.hdr{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px 24px;display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.hdr-t{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:700}
.hdr-nav{display:flex;align-items:center;gap:8px}
.hdr-nav a{color:var(--muted);text-decoration:none;padding:6px 14px;border-radius:8px;border:1px solid var(--border);font-size:13px;transition:all .2s}
.hdr-nav a:hover{color:var(--text);border-color:var(--blue);background:rgba(59,130,246,.08)}
.hdr-date{font-size:14px;color:var(--muted)}
.mg{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-bottom:24px}
.mc{background:var(--card);border-radius:12px;padding:18px 16px;text-align:center;border:1px solid var(--border);border-top:3px solid var(--blue);transition:transform .2s}
.mc:hover{transform:translateY(-2px)}
.mc-i{font-size:22px;margin-bottom:6px}
.mc-v{font-size:26px;font-weight:800;letter-spacing:-1px}
.mc-l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-top:3px}
.g2{display:grid;grid-template-columns:repeat(2,1fr);gap:20px;margin-bottom:24px}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-bottom:24px}
.cd{background:var(--card);border-radius:12px;padding:22px;border:1px solid var(--border)}
.cd-t{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.br{display:flex;align-items:center;gap:10px;margin-bottom:7px}
.br-l{width:130px;font-size:12px;color:var(--muted);text-align:right;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.br-t{flex:1;height:22px;background:rgba(255,255,255,.03);border-radius:4px;overflow:hidden}
.br-f{height:100%;border-radius:4px;min-width:2px;transition:width .4s}
.br-v{width:44px;font-size:12px;font-weight:600;text-align:right;flex-shrink:0}
.donut-w{display:flex;align-items:center;gap:24px;flex-wrap:wrap;justify-content:center}
.donut{width:150px;height:150px;border-radius:50%;position:relative;flex-shrink:0}
.donut-h{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:96px;height:96px;border-radius:50%;background:var(--card);display:flex;flex-direction:column;align-items:center;justify-content:center}
.donut-n{font-size:22px;font-weight:800}
.donut-l{font-size:10px;color:var(--muted)}
.lgd{display:flex;flex-direction:column;gap:6px}
.lgd-i{display:flex;align-items:center;gap:8px;font-size:12px}
.lgd-d{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.lgd-c{color:var(--muted);margin-left:auto;font-weight:600;min-width:28px;text-align:right}
.cv{display:flex;align-items:flex-end;gap:3px;height:120px;padding-top:16px}
.cv-b{flex:1;border-radius:3px 3px 0 0;min-height:2px;position:relative;cursor:default;transition:opacity .2s}
.cv-b:hover{opacity:.75}
.cv-b .tip{position:absolute;top:-22px;left:50%;transform:translateX(-50%);font-size:10px;color:var(--dim);opacity:0;transition:opacity .2s;white-space:nowrap}
.cv-b:hover .tip{opacity:1}
.cv-l{display:flex;gap:3px;margin-top:6px}
.cv-l span{flex:1;text-align:center;font-size:9px;color:var(--dim)}
.tb{width:100%}
.tr{display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.tr:last-child{border-bottom:none}
.t-r{width:20px;font-size:11px;color:var(--dim);text-align:center}
.t-n{flex:1;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.t-c{font-size:12px;font-weight:600;min-width:36px;text-align:right}
.t-b{width:70px;height:5px;background:rgba(255,255,255,.03);border-radius:3px;overflow:hidden}
.t-bf{height:100%;border-radius:3px}
.badge{display:inline-block;padding:1px 7px;border-radius:8px;font-size:10px;font-weight:600}
.b-g{background:rgba(16,185,129,.12);color:var(--green)}
.b-r{background:rgba(239,68,68,.12);color:var(--red)}
.b-b{background:rgba(59,130,246,.12);color:var(--blue)}
.b-p{background:rgba(139,92,246,.12);color:var(--purple)}
.b-a{background:rgba(245,158,11,.12);color:var(--amber)}
.sc{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px}
.fw{grid-column:1/-1}
.ft{text-align:center;padding:24px;font-size:11px;color:var(--dim);margin-top:16px}
.ft a{color:var(--blue);text-decoration:none}
.empty{text-align:center;padding:24px;color:var(--dim);font-size:13px}
.trend-bar{display:flex;flex-direction:column;align-items:center;gap:2px;flex:1}
.trend-seg{width:100%;border-radius:2px}
.trend-lbl{font-size:10px;color:var(--dim);margin-top:4px}
.trend-val{font-size:10px;color:var(--muted);font-weight:600}
.pill-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.pill{background:rgba(255,255,255,.04);border-radius:8px;padding:8px 14px;font-size:12px;display:flex;flex-direction:column;align-items:center;gap:2px;min-width:70px}
.pill-v{font-weight:700;font-size:16px}
.pill-l{color:var(--muted);font-size:10px}
.ip-tbl{font-size:12px;width:100%;border-collapse:collapse}
.ip-tbl th{text-align:left;color:var(--muted);font-weight:600;padding:6px 8px;border-bottom:1px solid var(--border);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.ip-tbl td{padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.03)}
.ip-tbl tr:last-child td{border-bottom:none}
@media(max-width:1024px){.mg{grid-template-columns:repeat(3,1fr)}.g3{grid-template-columns:1fr}}
@media(max-width:768px){.mg{grid-template-columns:repeat(2,1fr)}.g2{grid-template-columns:1fr}.hdr{flex-direction:column;text-align:center}}
</style>
</head>
<body>
<div class="wrap">

<!-- HEADER -->
<div class="hdr">
  <div class="hdr-t">\u{1F6E1}\uFE0F CF Bot Guard</div>
  <div class="hdr-nav">
    <a href="/dashboard?date=${addDays(dateStr, -1)}">\u25C0 Prev</a>
    <span class="hdr-date">${formatDateLong(dateStr)}</span>
    <a href="/dashboard?date=${addDays(dateStr, 1)}">Next \u25B6</a>
    <a href="/dashboard">Today</a>
  </div>
</div>

<!-- OVERVIEW METRICS -->
<div class="mg">
  <div class="mc" style="border-top-color:var(--blue)">
    <div class="mc-i">\u{1F4CA}</div>
    <div class="mc-v" style="color:var(--blue)">${total.toLocaleString()}</div>
    <div class="mc-l">Total Visitors</div>
  </div>
  <div class="mc" style="border-top-color:var(--green)">
    <div class="mc-i">\u{1F9D1}</div>
    <div class="mc-v" style="color:var(--green)">${humanCount.toLocaleString()}</div>
    <div class="mc-l">Humans</div>
  </div>
  <div class="mc" style="border-top-color:var(--red)">
    <div class="mc-i">\u{1F916}</div>
    <div class="mc-v" style="color:var(--red)">${botCount.toLocaleString()}</div>
    <div class="mc-l">Bots</div>
  </div>
  <div class="mc" style="border-top-color:${rateColor}">
    <div class="mc-i">\u{1F3AF}</div>
    <div class="mc-v" style="color:${rateColor}">${botRate}%</div>
    <div class="mc-l">Bot Rate</div>
  </div>
  <div class="mc" style="border-top-color:var(--purple)">
    <div class="mc-i">\u{1F310}</div>
    <div class="mc-v" style="color:var(--purple)">${uniqueIPs.toLocaleString()}</div>
    <div class="mc-l">Unique IPs</div>
  </div>
  <div class="mc" style="border-top-color:var(--orange)">
    <div class="mc-i">\u{1F525}</div>
    <div class="mc-v" style="color:var(--orange);font-size:${topThreatASN && topThreatASN.name ? '14px' : '26px'}">${topThreatASN ? (topThreatASN.name.split(':').slice(1).join(':') || 'unknown').slice(0, 16) : 'None'}</div>
    <div class="mc-l">Top Threat ASN (${topThreatASN ? topThreatASN.count : 0} hits)</div>
  </div>
</div>

<!-- BOT VS HUMAN -->
<div class="g2" style="margin-bottom:24px">
  <div class="cd">
    <div class="cd-t">\u{1F916} Bot vs Human</div>
    <div class="donut-w">
      <div class="donut" style="background:conic-gradient(var(--green) 0% ${total > 0 ? humanCount / total * 100 : 50}%, var(--red) ${total > 0 ? humanCount / total * 100 : 50}% 100%)">
        <div class="donut-h">
          <div class="donut-n">${total}</div>
          <div class="donut-l">total</div>
        </div>
      </div>
      <div class="lgd">
        <div class="lgd-i">
          <div class="lgd-d" style="background:var(--green)"></div>
          <span>Humans</span>
          <span class="lgd-c">${humanCount} (${total > 0 ? Math.round(humanCount / total * 100) : 0}%)</span>
        </div>
        <div class="lgd-i">
          <div class="lgd-d" style="background:var(--red)"></div>
          <span>Bots</span>
          <span class="lgd-c">${botCount} (${botRate}%)</span>
        </div>
        <div class="lgd-i" style="margin-top:8px">
          <div class="lgd-d" style="background:var(--blue)"></div>
          <span>Desktop</span>
          <span class="lgd-c">${desktop}</span>
        </div>
        <div class="lgd-i">
          <div class="lgd-d" style="background:var(--purple)"></div>
          <span>Mobile</span>
          <span class="lgd-c">${mobile}</span>
        </div>
      </div>
    </div>
  </div>
  <div class="cd">
    <div class="cd-t">\u{1F5A5}\uFE0F Datacenter ASN Activity</div>
    ${dcActivity.length === 0 ? '<div class="empty">No known datacenter ASNs detected today \u2705</div>' :
      '<div class="tb">' + dcActivity.slice(0, 12).map((d, i) => {
        const maxDC = dcActivity[0].count;
        const pct = d.count / maxDC * 100;
        return '<div class="tr"><span class="t-r">' + (i + 1) + '</span><span class="t-n"><span style="color:var(--dim);font-family:monospace;font-size:11px">AS' + d.asn + '</span> ' + d.org + '</span><div class="t-b"><div class="t-bf" style="width:' + pct + '%;background:var(--red)"></div></div><span class="t-c" style="color:var(--red)">' + d.count + '</span></div>';
      }).join('') + '</div>'}
  </div>
</div>

<!-- BOT SCORE + ISP CLASSIFICATION -->
<div class="g2">
  <div class="cd">
    <div class="cd-t">\u{1F4CA} Bot Score Distribution</div>
    ${['0-20', '21-40', '41-60', '61-80', '81-100'].map(b => {
      const v = scoreBuckets[b] || 0;
      const pct = v / totalScored * 100;
      return `<div class="br">
        <span class="br-l"><span class="sc" style="background:${bucketColors[b]}"></span>${b} ${bucketLabels[b]}</span>
        <div class="br-t"><div class="br-f" style="width:${pct}%;background:${bucketColors[b]}"></div></div>
        <span class="br-v">${v}</span>
      </div>`;
    }).join('')}
  </div>
  <div class="cd">
    <div class="cd-t">\u{1F3E2} ISP Classification</div>
    <div class="donut-w">
      <div class="donut" style="background:conic-gradient(${donutGrad})">
        <div class="donut-h">
          <div class="donut-n">${totalISP}</div>
          <div class="donut-l">visitors</div>
        </div>
      </div>
      <div class="lgd">
        ${ispTypes.map(([type, count]) => `<div class="lgd-i">
          <div class="lgd-d" style="background:${ispColors[type] || '#64748b'}"></div>
          <span>${type}</span>
          <span class="lgd-c">${count}</span>
        </div>`).join('')}
      </div>
    </div>
  </div>
</div>

<!-- BOT SIGNALS + BOT ORIGINS -->
<div class="g2">
  <div class="cd">
    <div class="cd-t">\u26A1 Top Bot Signals</div>
    ${signals.length === 0 ? '<div class="empty">No signal data yet</div>' :
      signals.slice(0, 12).map(([sig, count]) => `<div class="br">
        <span class="br-l">${sig}</span>
        <div class="br-t"><div class="br-f" style="width:${count / maxSignal * 100}%;background:linear-gradient(90deg,var(--orange),var(--red))"></div></div>
        <span class="br-v">${count}</span>
      </div>`).join('')}
  </div>
  <div class="cd">
    <div class="cd-t">\u{1F30D} Bot Origins</div>
    ${botCountries.length === 0 ? '<div class="empty">No bot traffic recorded</div>' :
      `<div class="tb">${botCountries.slice(0, 10).map(([code, count], i) => `<div class="tr">
        <span class="t-r">${i + 1}</span>
        <span class="t-n">${countryFlag(code)} ${code}</span>
        <span class="t-c">${count}</span>
      </div>`).join('')}</div>`}
  </div>
</div>

<!-- HOURLY TRAFFIC -->
<div class="cd" style="margin-bottom:24px">
  <div class="cd-t">\u{1F4C8} Hourly Traffic</div>
  <div class="cv">
    ${hourly.map((v, h) => `<div class="cv-b" style="height:${Math.max(v / maxHourly * 100, 2)}%;background:${v === Math.max(...hourly) ? 'var(--blue)' : 'rgba(59,130,246,.5)'}"><span class="tip">${v}</span></div>`).join('')}
  </div>
  <div class="cv-l">
    ${Array.from({ length: 24 }, (_, h) => `<span>${String(h).padStart(2, '0')}</span>`).join('')}
  </div>
</div>

<!-- 7-DAY TREND -->
<div class="cd" style="margin-bottom:24px">
  <div class="cd-t">\u{1F4C5} 7-Day Trend</div>
  <div style="display:flex;align-items:flex-end;gap:8px;height:120px">
    ${trend.map(t => {
      const h = t.total / maxTrend * 100;
      const humanH = t.total > 0 ? t.humans / t.total * h : 0;
      const botH = h - humanH;
      const isToday = t.date === dateStr;
      return `<div class="trend-bar">
        <div class="trend-val">${t.total}</div>
        <div style="width:100%;height:${Math.max(h, 2)}%;display:flex;flex-direction:column;border-radius:3px;overflow:hidden">
          <div class="trend-seg" style="flex:${botH};background:var(--red)"></div>
          <div class="trend-seg" style="flex:${humanH};background:var(--green)"></div>
        </div>
        <div class="trend-lbl" style="${isToday ? 'color:var(--blue);font-weight:700' : ''}">${t.day}</div>
      </div>`;
    }).join('')}
  </div>
  <div style="display:flex;gap:16px;justify-content:center;margin-top:12px;font-size:11px;color:var(--muted)">
    <span><span class="sc" style="background:var(--green)"></span>Humans</span>
    <span><span class="sc" style="background:var(--red)"></span>Bots</span>
  </div>
</div>

<!-- TOP PAGES + COUNTRIES + DEVICES -->
<div class="g3">
  <div class="cd">
    <div class="cd-t">\u{1F4C4} Top Pages</div>
    ${paths.length === 0 ? '<div class="empty">No page data yet</div>' :
      `<div class="tb">${paths.slice(0, 10).map((p, i) => `<div class="tr">
        <span class="t-r">${i + 1}</span>
        <span class="t-n" title="${p.name}">${p.name}</span>
        <div class="t-b"><div class="t-bf" style="width:${p.count / maxPath * 100}%;background:var(--blue)"></div></div>
        <span class="t-c">${p.count}</span>
      </div>`).join('')}</div>`}
  </div>
  <div class="cd">
    <div class="cd-t">\u{1F30D} Top Countries</div>
    ${countries.length === 0 ? '<div class="empty">No country data yet</div>' :
      `<div class="tb">${countries.slice(0, 10).map((c, i) => `<div class="tr">
        <span class="t-r">${i + 1}</span>
        <span class="t-n">${countryFlag(c.name)} ${c.name}</span>
        <div class="t-b"><div class="t-bf" style="width:${c.count / maxCountry * 100}%;background:var(--cyan)"></div></div>
        <span class="t-c">${c.count}</span>
      </div>`).join('')}</div>`}
  </div>
  <div class="cd">
    <div class="cd-t">\u{1F4F1} Device Split</div>
    <div style="display:flex;height:28px;border-radius:6px;overflow:hidden;margin-bottom:12px">
      <div style="width:${total > 0 ? desktop / total * 100 : 50}%;background:var(--blue);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;min-width:30px">${desktop}</div>
      <div style="width:${total > 0 ? mobile / total * 100 : 50}%;background:var(--purple);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;min-width:30px">${mobile}</div>
    </div>
    <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--muted)">
      <span><span class="sc" style="background:var(--blue)"></span>Desktop ${total > 0 ? Math.round(desktop / total * 100) : 0}%</span>
      <span><span class="sc" style="background:var(--purple)"></span>Mobile ${total > 0 ? Math.round(mobile / total * 100) : 0}%</span>
    </div>
    <div class="cd-t" style="margin-top:20px">\u{1F3E2} Top Cities</div>
    ${cities.length === 0 ? '<div class="empty">No city data</div>' :
      `<div class="tb">${cities.slice(0, 6).map((c, i) => `<div class="tr">
        <span class="t-r">${i + 1}</span>
        <span class="t-n">${c.name}</span>
        <span class="t-c">${c.count}</span>
      </div>`).join('')}</div>`}
  </div>
</div>

<!-- REFERRERS + ASNs -->
<div class="g2">
  <div class="cd">
    <div class="cd-t">\u{1F517} Top Referrers</div>
    ${referrers.length === 0 ? '<div class="empty">No referrer data yet</div>' :
      `<div class="tb">${referrers.slice(0, 10).map((r, i) => `<div class="tr">
        <span class="t-r">${i + 1}</span>
        <span class="t-n">${r.name}</span>
        <span class="t-c">${r.count}</span>
      </div>`).join('')}</div>`}
  </div>
  <div class="cd">
    <div class="cd-t">\u{1F3E2} Top ASNs / ISPs</div>
    ${asns.length === 0 ? '<div class="empty">No ASN data yet</div>' :
      `<div class="tb">${asns.slice(0, 10).map((a, i) => {
        const parts = a.name.split(':');
        const asnNum = parts[0];
        const org = parts.slice(1).join(':') || asnNum;
        const ispType = classifyISP(org);
        const badgeClass = ispType === 'hosting' ? 'b-r' : ispType === 'mobile' ? 'b-b' : ispType === 'education' ? 'b-p' : ispType === 'corporate' ? 'b-a' : 'b-g';
        return `<div class="tr">
          <span class="t-r">${i + 1}</span>
          <span class="t-n">${org} <span class="badge ${badgeClass}">${ispType}</span></span>
          <span class="t-c">${a.count}</span>
        </div>`;
      }).join('')}</div>`}
  </div>
</div>

<!-- TLS + PROTOCOLS + EDGE LOCATIONS -->
<div class="g3">
  <div class="cd">
    <div class="cd-t">\u{1F512} TLS Versions</div>
    ${tlsVersions.length === 0 ? '<div class="empty">No data</div>' :
      `<div class="pill-row">${tlsVersions.map(([v, c]) => `<div class="pill">
        <span class="pill-v">${c}</span>
        <span class="pill-l">${v}</span>
      </div>`).join('')}</div>`}
  </div>
  <div class="cd">
    <div class="cd-t">\u{1F310} HTTP Protocols</div>
    ${protocols.length === 0 ? '<div class="empty">No data</div>' :
      `<div class="pill-row">${protocols.map(([v, c]) => `<div class="pill">
        <span class="pill-v">${c}</span>
        <span class="pill-l">${v}</span>
      </div>`).join('')}</div>`}
  </div>
  <div class="cd">
    <div class="cd-t">\u{1F4E1} Edge Locations</div>
    ${colos.length === 0 ? '<div class="empty">No data</div>' :
      `<div class="pill-row">${colos.slice(0, 8).map(([v, c]) => `<div class="pill">
        <span class="pill-v">${c}</span>
        <span class="pill-l">${v}</span>
      </div>`).join('')}</div>`}
  </div>
</div>

<!-- BOT TARGETED PAGES + SUSPICIOUS IPs -->
<div class="g2">
  <div class="cd">
    <div class="cd-t">\u{1F3AF} Bot Targeted Pages</div>
    ${botPaths.length === 0 ? '<div class="empty">No bot-targeted pages recorded</div>' :
      `<div class="tb">${botPaths.slice(0, 10).map(([path, count], i) => `<div class="tr">
        <span class="t-r">${i + 1}</span>
        <span class="t-n">${path}</span>
        <span class="t-c" style="color:var(--red)">${count}</span>
      </div>`).join('')}</div>`}
  </div>
  <div class="cd">
    <div class="cd-t">\u26A0\uFE0F Suspicious IPs <span style="font-size:10px;font-weight:400;color:var(--dim)">(score &gt; 50)</span></div>
    ${suspiciousIPs.length === 0 ? '<div class="empty">No suspicious IPs today \u2705</div>' :
      `<table class="ip-tbl">
        <tr><th>IP</th><th>Score</th><th>Hits</th><th>Last Seen</th></tr>
        ${suspiciousIPs.map(ip => {
          const scoreColor = ip.avgScore > 80 ? 'var(--red)' : ip.avgScore > 60 ? 'var(--orange)' : 'var(--amber)';
          return `<tr>
            <td style="font-family:monospace">${truncateIP(ip.ip)}</td>
            <td style="color:${scoreColor};font-weight:700">${ip.avgScore}</td>
            <td>${ip.hits}</td>
            <td style="color:var(--dim)">${ip.lastSeen ? ip.lastSeen.slice(11, 19) : '-'}</td>
          </tr>`;
        }).join('')}
      </table>`}
  </div>
</div>

<!-- ALL VISITORS IP TABLE -->
<div class="cd" style="margin-bottom:24px">
  <div class="cd-t">\u{1F465} All Visitor IPs <span style="font-size:10px;font-weight:400;color:var(--dim)">(${ips.length} unique today)</span></div>
  ${ips.length === 0 ? '<div class="empty">No visitor data yet</div>' :
    `<table class="ip-tbl">
      <tr><th>IP (truncated)</th><th>Avg Score</th><th>Hits</th><th>Verdict</th><th>Last Seen</th></tr>
      ${ips.slice(0, 30).map(ip => {
        const sc = ip.avgScore;
        const scoreColor = sc > 80 ? 'var(--red)' : sc > 60 ? 'var(--orange)' : sc > 40 ? 'var(--amber)' : sc > 20 ? 'var(--cyan)' : 'var(--green)';
        const verdict = sc > 80 ? 'Bot' : sc > 60 ? 'Likely Bot' : sc > 40 ? 'Suspicious' : sc > 20 ? 'Likely Human' : 'Human';
        const badgeClass = sc > 60 ? 'b-r' : sc > 40 ? 'b-a' : sc > 20 ? 'b-b' : 'b-g';
        return `<tr>
          <td style="font-family:monospace">${truncateIP(ip.ip)}</td>
          <td style="color:${scoreColor};font-weight:700">${sc}</td>
          <td>${ip.hits}</td>
          <td><span class="badge ${badgeClass}">${verdict}</span></td>
          <td style="color:var(--dim)">${ip.lastSeen ? ip.lastSeen.slice(11, 19) : '-'}</td>
        </tr>`;
      }).join('')}
    </table>`}
</div>

<!-- FOOTER -->
<div class="ft">
  Powered by <a href="https://github.com/yourusername/cf-bot-guard" target="_blank">CF Bot Guard</a> &middot; Running on Cloudflare Workers
</div>

</div>
</body>
</html>`;
}

// ─── MAIN HANDLER ─────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Dashboard route
    if (url.pathname === '/dashboard') {
      const dateStr = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        return new Response('Invalid date format', { status: 400 });
      }
      const data = await getDashboardData(env, dateStr);
      return new Response(renderDashboard(data, dateStr), {
        headers: { 'content-type': 'text/html;charset=UTF-8', 'cache-control': 'no-store' },
      });
    }

    // Normal bot detection + proxy flow
    const ua = request.headers.get('user-agent') || '';
    const fingerprint = fingerprintRequest(request);
    const botResult = calculateBotScore(fingerprint, ua);

    const domain = env.BLOG_DOMAIN || url.hostname;
    const analyticsPromise = logPageView(env, request, fingerprint, botResult, domain);

    const response = await fetch(request);
    const newResponse = new Response(response.body, response);
    newResponse.headers.set('x-bot-score', String(botResult.score));
    newResponse.headers.set('x-bot-signals', botResult.reasons.join(',') || 'clean');
    newResponse.headers.set('x-isp-type', fingerprint.ispType);

    await analyticsPromise;
    return newResponse;
  },
};
