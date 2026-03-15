<div align="center">

# 🛡️ CF Bot Guard

**Advanced Bot Detection & Privacy-Respecting Analytics for Cloudflare Workers**

A single-file Cloudflare Worker that scores every visitor on a 0–100 bot scale using **16 detection signals**, classifies ISPs by type, and logs **10-dimension analytics** to KV — all at the edge, with zero client-side code.

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Free Tier](https://img.shields.io/badge/Tier-Free-brightgreen)]()

**No cookies · No JavaScript · No third-party scripts · No PII stored**

</div>

---

## ✨ What It Does

```
Visitor → Cloudflare Edge → [ CF Bot Guard ] → Your Origin
                                   │
                                   ├── Fingerprint (TLS version, headers, protocol)
                                   ├── Classify ISP (hosting / mobile / residential / edu / corp)
                                   ├── Score bot likelihood (0–100)
                                   ├── Log analytics to KV (10 dimensions)
                                   └── Add headers: x-bot-score, x-bot-signals, x-isp-type
```

The Worker is a **transparent proxy** — it never blocks requests. It adds intelligence headers and logs analytics, then passes the original response through untouched.

---

## 🔍 Bot Detection — 16 Signals

### Positive Signals (increases bot score)

| Signal | Weight | Description |
|:-------|:------:|:------------|
| `no-ua` | **+40** | No User-Agent header at all |
| `old-tls` | **+30** | TLS 1.0 or 1.1 (deprecated, only bots use these) |
| `hosting-isp` | **+25** | ISP name matches cloud/VPN/datacenter pattern |
| `fake-browser-ua` | **+20** | Claims Chrome/Firefox but missing browser-only headers |
| `http1.0` | **+20** | HTTP/1.0 protocol (no modern browser does this) |
| `datacenter-asn` | **+20** | Known datacenter ASN (30+ networks, fallback check) |
| `few-headers` | **+20** | Fewer than 5 headers total |
| `no-accept-lang` | **+15** | Missing `Accept-Language` (browsers always send this) |
| `short-ua` | **+15** | User-Agent shorter than 20 characters |
| `low-headers` | **+10** | 5–7 headers (still suspiciously few) |
| `no-accept-enc` | **+10** | Missing `Accept-Encoding` |
| `simple-accept-lang` | **+8** | `Accept-Language` without quality values (e.g. just `en`) |
| `no-sec-fetch-*` | **+5 ea** | Missing `Sec-Fetch-Site`, `Mode`, or `Dest` |
| `no-sec-ch-ua` | **+5** | Missing `Sec-CH-UA` client hint |
| `no-sec-ch-ua-platform` | **+3** | Missing `Sec-CH-UA-Platform` |
| `no-sec-ch-ua-mobile` | **+3** | Missing `Sec-CH-UA-Mobile` |

### Negative Signals (reduces bot score)

| ISP Type | Adjustment | Reason |
|:---------|:----------:|:-------|
| Residential | **−10** | Home ISP — most likely a real person |
| Mobile | **−5** | Cellular carrier — likely human on phone |
| Education | **−5** | University/research network |

### Score Interpretation

| Score | Meaning |
|:-----:|:--------|
| 0–20 | ✅ Almost certainly human |
| 21–40 | ✅ Likely human, minor anomalies |
| 41–60 | ⚠️ Suspicious — could be either |
| 61–80 | 🤖 Likely bot or automated tool |
| 81–100 | 🤖 Almost certainly a bot |

---

## 🏢 ISP Classification

Regex-based heuristic that classifies the visitor's ISP into 5 categories:

| Type | Examples | Bot Score Impact |
|:-----|:---------|:----------------:|
| **hosting** | AWS, Google Cloud, DigitalOcean, Hetzner, NordVPN, Cloudflare | +25 |
| **mobile** | Vodafone, T-Mobile, EE, Verizon, O2 | −5 |
| **education** | JANET, GÉANT, Internet2, universities | −5 |
| **corporate** | Business/Enterprise ISPs (Inc., Ltd., GmbH) | neutral |
| **residential** | Everything else (default) | −10 |

Plus a fallback set of **25 known datacenter ASNs** for hosting providers whose names don't match the patterns.

---

## 📊 Privacy-Respecting Analytics

All data stored in Cloudflare KV with **automatic expiration**. Static assets and the `/dashboard` path are excluded automatically.

The Worker uses just **2 KV writes per page view** by aggregating 10 dimensions into a single daily JSON blob:

| Key | Contents | TTL |
|:----|:---------|:---:|
| `daily:2026-03-15` | Page views, paths, countries, cities, hourly traffic, bot/human counts, devices, referrers, ASNs, ISP types, bot signals, score buckets, TLS versions, protocols, edge colos, bot-targeted paths | 90d |
| `ip:2026-03-15:x.x.x.x` | Hit count, total score, average score, last seen timestamp | 7d |

---

## 🚀 Setup

> **Requirements:** Cloudflare account (free tier works) + a domain proxied through Cloudflare (orange cloud) + [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)

### Step 1 — Create a KV namespace

```bash
npx wrangler kv namespace create ANALYTICS
```

Save the `id` from the output.

### Step 2 — Create `wrangler.toml`

```toml
name = "cf-bot-guard"
main = "worker.js"
compatibility_date = "2024-09-23"

[vars]
BLOG_DOMAIN = "yourdomain.com"        # Used to filter self-referrals

[[kv_namespaces]]
binding = "ANALYTICS"
id = "paste-your-kv-namespace-id"     # From step 1

[[routes]]
pattern = "yourdomain.com/*"
zone_name = "yourdomain.com"
```

### Step 3 — Deploy

```bash
npx wrangler deploy
```

### Step 4 — Verify

```bash
curl -sI https://yourdomain.com/ | grep -i "x-bot\|x-isp"
```

Expected output:
```
x-bot-score: 12
x-bot-signals: no-sec-ch-ua-platform,no-sec-ch-ua-mobile
x-isp-type: residential
```

---

## 📡 Response Headers

Every proxied response gets 3 headers added:

| Header | Example Value | Description |
|:-------|:-------------|:------------|
| `x-bot-score` | `15` | Bot likelihood (0 = human, 100 = bot) |
| `x-bot-signals` | `no-accept-lang,hosting-isp` | Which signals fired |
| `x-isp-type` | `residential` | ISP classification |

---

## � Built-in Dashboard

Access your analytics at `https://yourdomain.com/dashboard` — a fully rendered HTML dashboard with a dark theme, built entirely at the edge with **zero JavaScript dependencies**.

### Dashboard Sections (22 panels)

| Section | Description |
|:--------|:------------|
| **Overview Cards** | Total visitors, humans, bots, bot rate, unique IPs, top threat ASN |
| **Bot vs Human** | Donut chart with desktop/mobile breakdown |
| **Datacenter ASN Activity** | Known datacenter ASNs hitting your site |
| **Bot Score Distribution** | Horizontal bar chart across 5 score buckets |
| **ISP Classification** | Donut chart (residential/hosting/mobile/edu/corporate) |
| **Top Bot Signals** | Which detection signals fire most often |
| **Bot Origins** | Countries generating bot traffic |
| **Hourly Traffic** | 24-hour bar chart for the selected day |
| **7-Day Trend** | Stacked human/bot bars over the past week |
| **Top Pages** | Most visited paths |
| **Top Countries** | Visitor countries with flag emojis |
| **Device Split** | Desktop vs mobile ratio |
| **Top Cities** | Visitor cities |
| **Top Referrers** | External referral sources |
| **Top ASNs** | ISPs with type badges |
| **TLS / HTTP / Edge** | Protocol versions and Cloudflare edge locations |
| **Bot Targeted Pages** | Pages most hit by bots |
| **Suspicious IPs** | IPs with avg score > 50 (truncated for privacy) |
| **All Visitor IPs** | Every unique IP with verdict badge (truncated) |

> **Privacy:** All IPs are truncated (e.g. `192.168.x.x`) — no full IPs ever displayed. The dashboard itself is excluded from analytics tracking.

Navigate between dates with **Prev / Next** buttons or jump to **Today**.

---

## �💡 Use Cases

- **Observability** — See bot vs human traffic without any client-side code
- **WAF Rules** — Block or challenge based on `x-bot-score` thresholds
- **Analytics** — Privacy-first alternative to Google Analytics
- **Threat Intel** — Track which datacenter ASNs are scanning your site
- **AI Crawler Detection** — Identify scrapers by their network fingerprint

---

## 💰 Free Tier Compatible

Runs entirely on Cloudflare's free plan:

| Resource | Free Limit | 
|:---------|:-----------|
| Workers requests | 100,000/day |
| KV reads | 100,000/day |
| KV writes | 1,000/day |
| `request.cf` fields (geo, ASN, TLS) | ✅ All free |

---

##  License

[MIT](LICENSE)
