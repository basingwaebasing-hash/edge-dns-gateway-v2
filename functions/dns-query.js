// ==================== CONFIG ====================
const UPSTREAM_PRIMARY = 'https://bu0eg1tdzu.cloudflare-gateway.com/dns-query';
const UPSTREAM_FALLBACK = 'https://rhpcv957tj.cloudflare-gateway.com/dns-query';
const UPSTREAM_GEO_BYPASS = 'https://dns.mullvad.net/dns-query';
const UPSTREAM_TIMEOUT = 10000;

// Refresh interval
const ALL_LISTS_REFRESH_INTERVAL = 3600000; // 1 hour
const MAX_DNS_QUERY_SIZE = 512;
const MAX_GET_PARAM_SIZE = 1024;

// Memory limits
const MAX_BLOCKLIST_SIZE = 500000;
const MAX_ALLOWLIST_SIZE = 100000;
const MAX_REDIRECT_RULES = 10000;
const MAX_PRIVATE_TLDS = 50000;

// Privacy & Security
const ENABLE_ERROR_LOGGING = true;

// Features
const AD_BLOCK_ENABLED = true;
const ECS_INJECTION_ENABLED = true;
const BLOCK_PRIVATE_TLD = true;
const DNS_REDIRECT_ENABLED = true;
const MULLVAD_UPSTREAM_ENABLED = true;

const ECS_PREFIX_V4 = 24;
const ECS_PREFIX_V6 = 48;

const BLOCK_ANY = false;
const BLOCK_AAAA = false;
const BLOCK_PTR = false;
const BLOCK_HTTPS = false;

const DEBUG_ENABLED = false;

// Regex patterns
const IPV4_MAPPED_REGEX = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i;
const IPV6_VALID_REGEX = /^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i;
const IPV6_GROUP_REGEX = /^[0-9a-f]{1,4}$/i;

// ==================== STATE ====================
let adBlocklist = new Set();
let adAllowlist = new Set();
let privateTlds = new Set();
let redirectRules = new Map();
let mullvadUpstreamDomains = new Set();
let blocklistLastFetch = 0;
let blocklistLastError = 0;
let blocklistPromise = null;
let blocklistsFetched = false;

// ==================== UTILITIES ====================
async function fetchList(url, listName = 'unknown', maxSize = MAX_BLOCKLIST_SIZE) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) {
      if (ENABLE_ERROR_LOGGING) console.warn(`[DNS] Failed to fetch ${listName}: HTTP ${res.status}`);
      return new Set();
    }
    const text = await res.text();
    const domains = new Set();
    for (const line of text.split('\n')) {
      const d = line.trim();
      if (d && !d.startsWith('#') && !d.startsWith('!')) {
        domains.add(d);
        if (domains.size >= maxSize) {
          if (ENABLE_ERROR_LOGGING) console.warn(`[DNS] ${listName} exceeds limit`);
          break;
        }
      }
    }
    if (ENABLE_ERROR_LOGGING) console.log(`[DNS] Loaded ${listName}: ${domains.size} entries`);
    return domains;
  } catch (e) {
    if (ENABLE_ERROR_LOGGING) console.error(`[DNS] Error fetching ${listName}: Network error`);
    return new Set();
  }
}

async function fetchRedirectRules(url, listName = 'redirectRules', maxSize = MAX_REDIRECT_RULES) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) {
      if (ENABLE_ERROR_LOGGING) console.warn(`[DNS] Failed to fetch ${listName}: HTTP ${res.status}`);
      return new Map();
    }
    const text = await res.text();
    const rules = new Map();
    for (const line of text.split('\n')) {
      const d = line.trim();
      if (!d || d.startsWith('#') || d.startsWith('!')) continue;
      const parts = d.split(/\s+/);
      if (parts.length === 2) {
        rules.set(parts[0].toLowerCase(), parts[1].toLowerCase());
        if (rules.size >= maxSize) {
          if (ENABLE_ERROR_LOGGING) console.warn(`[DNS] ${listName} exceeds limit`);
          break;
        }
      }
    }
    if (ENABLE_ERROR_LOGGING) console.log(`[DNS] Loaded ${listName}: ${rules.size} entries`);
    return rules;
  } catch (e) {
    if (ENABLE_ERROR_LOGGING) console.error(`[DNS] Error fetching ${listName}: Network error`);
    return new Map();
  }
}

async function refreshBlocklists(baseUrl) {
  if (blocklistsFetched && Date.now() - blocklistLastFetch < ALL_LISTS_REFRESH_INTERVAL) return;
  if (blocklistPromise) return blocklistPromise;

  blocklistPromise = (async () => {
    try {
      const bUrl = new URL('/rules/blocklists.txt', baseUrl).toString();
      const aUrl = new URL('/rules/allowlists.txt', baseUrl).toString();
      const pUrl = new URL('/rules/private_tlds.txt', baseUrl).toString();
      const rUrl = new URL('/rules/redirect_rules.txt', baseUrl).toString();
      const mUrl = new URL('/rules/mullvad_upstream.txt', baseUrl).toString();

      const [block, allow, privateList, redirRules, mullvadList] = await Promise.all([
        AD_BLOCK_ENABLED ? fetchList(bUrl, 'blocklists', MAX_BLOCKLIST_SIZE) : Promise.resolve(new Set()),
        AD_BLOCK_ENABLED ? fetchList(aUrl, 'allowlists', MAX_ALLOWLIST_SIZE) : Promise.resolve(new Set()),
        BLOCK_PRIVATE_TLD ? fetchList(pUrl, 'privateTlds', MAX_PRIVATE_TLDS) : Promise.resolve(new Set()),
        DNS_REDIRECT_ENABLED ? fetchRedirectRules(rUrl, 'redirectRules', MAX_REDIRECT_RULES) : Promise.resolve(new Map()),
        MULLVAD_UPSTREAM_ENABLED ? fetchList(mUrl, 'mullvadUpstream') : Promise.resolve(new Set())
      ]);

      if (AD_BLOCK_ENABLED) { adBlocklist = block; adAllowlist = allow; }
      if (BLOCK_PRIVATE_TLD) { privateTlds = privateList; }
      if (DNS_REDIRECT_ENABLED) { redirectRules = redirRules; }
      if (MULLVAD_UPSTREAM_ENABLED) { mullvadUpstreamDomains = mullvadList; }

      blocklistLastFetch = Date.now();
      blocklistsFetched = true;
      blocklistLastError = 0;
      if (ENABLE_ERROR_LOGGING) console.log('[DNS] All blocklists refreshed successfully');
    } catch (e) {
      if (ENABLE_ERROR_LOGGING) console.error('[DNS] Error refreshing blocklists: Network error');
      blocklistLastError = Date.now();
    } finally {
      blocklistPromise = null;
    }
  })();

  return blocklistPromise;
}

function extractQtype(buf) {
  try {
    const v = new Uint8Array(buf);
    if (v.length < 12) return null;
    const qd = (v[4] << 8) | v[5];
    if (qd === 0) return null;
    let off = 12;
    while (off < v.length) {
      const len = v[off];
      if (len === 0) { off++; break; }
      if ((len & 0xC0) === 0xC0) { off += 2; break; }
      off += len + 1;
    }
    if (off + 2 > v.length) return null;
    return (v[off] << 8) | v[off + 1];
  } catch { return null; }
}

function getBlockedQtypes() {
  const blocked = new Set();
  if (BLOCK_ANY) blocked.add(255);
  if (BLOCK_AAAA) blocked.add(28);
  if (BLOCK_PTR) blocked.add(12);
  if (BLOCK_HTTPS) blocked.add(65);
  return blocked;
}
const BLOCKED_QTYPES = getBlockedQtypes();

function extractAllDomains(buf) {
  const domains = [];
  try {
    const v = new Uint8Array(buf);
    if (v.length < 12) return domains;
    const qd = (v[4] << 8) | v[5];
    if (qd === 0) return domains;
    let off = 12;
    for (let q = 0; q < qd; q++) {
      const labels = [];
      while (off < v.length) {
        const len = v[off];
        if (len === 0) { off++; break; }
        if ((len & 0xC0) === 0xC0) { off += 2; break; }
        off++;
        if (off + len > v.length) return domains;
        let label = '';
        for (let i = 0; i < len; i++) label += String.fromCharCode(v[off + i]);
        labels.push(label);
        off += len;
      }
      off += 4;
      if (labels.length > 0) domains.push(labels.join('.').toLowerCase());
    }
  } catch { }
  return domains;
}

function hasLoopbackInAnswer(buf) {
  try {
    const v = new Uint8Array(buf);
    if (v.length < 12) return false;
    const qd = (v[4] << 8) | v[5];
    const an = (v[6] << 8) | v[7];
    if (an === 0) return false;

    let off = 12;
    for (let i = 0; i < qd; i++) {
      while (off < v.length) {
        const len = v[off];
        if (len === 0) { off++; break; }
        if ((len & 0xC0) === 0xC0) { off += 2; break; }
        off += len + 1;
      }
      off += 4;
    }

    for (let i = 0; i < an; i++) {
      while (off < v.length) {
        const len = v[off];
        if (len === 0) { off++; break; }
        if ((len & 0xC0) === 0xC0) { off += 2; break; }
        off += len + 1;
      }
      if (off + 10 > v.length) break;
      const type = (v[off] << 8) | v[off + 1];
      const cls = (v[off + 2] << 8) | v[off + 3];
      const rdlen = (v[off + 8] << 8) | v[off + 9];
      off += 10;
      if (type === 1 && cls === 1 && rdlen === 4) {
        if (v[off] === 127 && v[off + 1] === 0 && v[off + 2] === 0 && v[off + 3] === 1) return true;
      }
      off += rdlen;
    }
  } catch { }
  return false;
}

function isDomainBlocked(domain) {
  if (!domain || adBlocklist.size === 0) return false;
  if (adAllowlist.has(domain)) return false;
  if (adBlocklist.has(domain)) return true;
  return false;
}

function isDomainPrivate(domain) {
  if (!domain || privateTlds.size === 0) return false;
  if (privateTlds.has(domain)) return true;
  let pos = 0;
  while ((pos = domain.indexOf('.', pos)) !== -1) {
    if (privateTlds.has(domain.substring(pos + 1))) return true;
    pos++;
  }
  return false;
}

function isMullvadDomain(domain) {
  if (!domain || mullvadUpstreamDomains.size === 0) return false;
  if (mullvadUpstreamDomains.has(domain)) return true;
  let pos = 0;
  while ((pos = domain.indexOf('.', pos)) !== -1) {
    if (mullvadUpstreamDomains.has(domain.substring(pos + 1))) return true;
    pos++;
  }
  return false;
}

function buildNxdomain(query) {
  const v = new Uint8Array(query);
  if (v.length < 12) {
    const sf = new Uint8Array(12);
    sf[2] = 0x84; sf[3] = 0x82;
    return sf.buffer;
  }
  let qEnd = 12;
  while (qEnd < v.length) {
    const len = v[qEnd];
    if (len === 0) { qEnd++; break; }
    if ((len & 0xC0) === 0xC0) { qEnd += 2; break; }
    qEnd += len + 1;
  }
  qEnd += 4;
  const res = new Uint8Array(qEnd);
  res.set(v.slice(0, qEnd));
  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x80 | 0x03;
  res[4] = 0; res[5] = 1;
  res[6] = 0; res[7] = 0;
  res[8] = 0; res[9] = 0;
  res[10] = 0; res[11] = 0;
  return res.buffer;
}

function buildNodata(query) {
  const v = new Uint8Array(query);
  if (v.length < 12) {
    const sf = new Uint8Array(12);
    sf[2] = 0x84; sf[3] = 0x80;
    return sf.buffer;
  }
  let qEnd = 12;
  while (qEnd < v.length) {
    const len = v[qEnd];
    if (len === 0) { qEnd++; break; }
    if ((len & 0xC0) === 0xC0) { qEnd += 2; break; }
    qEnd += len + 1;
  }
  qEnd += 4;
  const res = new Uint8Array(qEnd);
  res.set(v.slice(0, qEnd));
  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x80;
  res[4] = 0; res[5] = 1;
  res[6] = 0; res[7] = 0;
  res[8] = 0; res[9] = 0;
  res[10] = 0; res[11] = 0;
  return res.buffer;
}

function buildServfail(query) {
  const v = new Uint8Array(query);
  if (v.length < 12) {
    const sf = new Uint8Array(12);
    sf[2] = 0x84; sf[3] = 0x82;
    return sf.buffer;
  }
  let qEnd = 12;
  while (qEnd < v.length) {
    const len = v[qEnd];
    if (len === 0) { qEnd++; break; }
    if ((len & 0xC0) === 0xC0) { qEnd += 2; break; }
    qEnd += len + 1;
  }
  qEnd += 4;
  const res = new Uint8Array(qEnd);
  res.set(v.slice(0, qEnd));
  res[2] = 0x80 | (v[2] & 0x7F);
  res[3] = 0x80 | 0x02;
  res[4] = 0; res[5] = 1;
  res[6] = 0; res[7] = 0;
  res[8] = 0; res[9] = 0;
  res[10] = 0; res[11] = 0;
  return res.buffer;
}

function injectECS(query, clientIP) {
  if (!ECS_INJECTION_ENABLED || !clientIP || clientIP === 'unknown') return query;
  try {
    const v = new Uint8Array(query);
    if (v.length < 12) return query;

    let family, prefixLen, addrBytes;
    if (clientIP.includes(':')) {
      family = 2; prefixLen = ECS_PREFIX_V6;
      const halves = clientIP.split('::');
      if (halves.length > 2) return query;
      const left = halves[0] ? halves[0].split(':').filter(x => x) : [];
      const right = halves.length > 1 && halves[1] ? halves[1].split(':').filter(x => x) : [];
      if (left.length + right.length > 8) return query;
      const missing = 8 - (left.length + right.length);
      const full = [...left, ...Array(missing).fill('0'), ...right];
      const bytes = [];
      for (const s of full) {
        const v = parseInt(s || '0', 16);
        if (isNaN(v)) return query;
        bytes.push((v >> 8) & 0xFF, v & 0xFF);
      }
      const byteLen = Math.ceil(prefixLen / 8);
      addrBytes = bytes.slice(0, byteLen);
    } else {
      family = 1; prefixLen = ECS_PREFIX_V4;
      const parts = clientIP.split('.');
      if (parts.length !== 4) return query;
      const byteLen = Math.ceil(prefixLen / 8);
      addrBytes = parts.slice(0, byteLen).map(Number);
    }

    if (addrBytes.length > 0 && prefixLen % 8 !== 0) {
      const maskBits = prefixLen % 8;
      const mask = (0xFF << (8 - maskBits)) & 0xFF;
      addrBytes[addrBytes.length - 1] &= mask;
    }

    const ecsLen = 4 + addrBytes.length;
    const ecs = new Uint8Array(4 + ecsLen);
    ecs[0] = 0; ecs[1] = 8;
    ecs[2] = (ecsLen >> 8) & 0xFF; ecs[3] = ecsLen & 0xFF;
    ecs[4] = (family >> 8) & 0xFF; ecs[5] = family & 0xFF;
    ecs[6] = prefixLen; ecs[7] = 0;
    for (let i = 0; i < addrBytes.length; i++) ecs[8 + i] = addrBytes[i];

    const opt = new Uint8Array(11 + ecs.length);
    opt[0] = 0;
    opt[1] = 0; opt[2] = 41;
    opt[3] = 16; opt[4] = 0;
    opt[5] = 0; opt[6] = 0; opt[7] = 0; opt[8] = 0;
    opt[9] = (ecs.length >> 8) & 0xFF; opt[10] = ecs.length & 0xFF;
    opt.set(ecs, 11);

    const result = new Uint8Array(v.length + opt.length);
    result.set(v);
    result.set(opt, v.length);
    return result.buffer;
  } catch { return query; }
}

async function forwardQuery(query, upstream) {
  const res = await fetch(upstream, {
    method: 'POST',
    headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
    body: query,
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT)
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.arrayBuffer();
}

async function resolveQuery(query, clientIP) {
  const processed = injectECS(query, clientIP);
  let result;
  try {
    result = await forwardQuery(processed, UPSTREAM_PRIMARY);
  } catch {
    try {
      result = await forwardQuery(processed, UPSTREAM_FALLBACK);
    } catch {
      return buildServfail(query);
    }
  }

  if (result && hasLoopbackInAnswer(result)) {
    try {
      const respMullvad = await forwardQuery(processed, UPSTREAM_GEO_BYPASS);
      if (!hasLoopbackInAnswer(respMullvad)) return respMullvad;
      return buildNxdomain(query);
    } catch {
      return buildServfail(query);
    }
  }

  return result;
}

async function ensureBlocklistsLoaded(url, context) {
  if (!blocklistsFetched) {
    await refreshBlocklists(url);
  } else if (context) {
    context.waitUntil(refreshBlocklists(url));
  }
}

// ==================== HANDLERS ====================
export async function onRequest(context) {
  const { request } = context;
  const path = new URL(request.url).pathname;

  if (path === '/dns-query') return handleDNSQuery(request, context);
  if (path === '/check') return handleCheck(request);
  if (path === '/debug') return handleDebug(request, context);
  if (path.startsWith('/ecs/')) return handleECS(request);
  if (path.startsWith('/apple/')) return handleApple(request);
  if (path === '/unfiltered') return handleUnfiltered(request, context);

  return new Response('Not Found', { status: 404 });
}

async function handleDNSQuery(request, context) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Accept', 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0' };

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  let query;
  if (request.method === 'POST') {
    const buffer = await request.arrayBuffer();
    if (buffer.byteLength > MAX_DNS_QUERY_SIZE) {
      if (ENABLE_ERROR_LOGGING) console.warn(`[DNS] Query exceeds max size`);
      return new Response('Query too large', { status: 413, headers: cors });
    }
    query = buffer;
  } else if (request.method === 'GET') {
    const dns = new URL(request.url).searchParams.get('dns');
    if (!dns || dns.length > MAX_GET_PARAM_SIZE) {
      return new Response('Invalid dns parameter', { status: 400, headers: cors });
    }
    const b64 = dns.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '=='.slice(0, (4 - b64.length % 4) % 4);
    try {
      query = Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer;
    } catch (e) {
      if (ENABLE_ERROR_LOGGING) console.warn(`[DNS] Invalid base64 format`);
      return new Response('Invalid dns parameter', { status: 400, headers: cors });
    }
  } else {
    return new Response('Method not allowed', { status: 405, headers: cors });
  }

  if (BLOCKED_QTYPES.size > 0) {
    const qtype = extractQtype(query);
    if (qtype !== null && BLOCKED_QTYPES.has(qtype)) {
      return new Response(buildNodata(query), {
        headers: { ...cors, 'Content-Type': 'application/dns-message' }
      });
    }
  }

  if (AD_BLOCK_ENABLED || BLOCK_PRIVATE_TLD || DNS_REDIRECT_ENABLED || MULLVAD_UPSTREAM_ENABLED) {
    await ensureBlocklistsLoaded(request.url, context);
    const domains = extractAllDomains(query);
    for (const domain of domains) {
      if (!domain) continue;

      if (MULLVAD_UPSTREAM_ENABLED && isMullvadDomain(domain)) {
        try {
          const processed = injectECS(query, clientIP);
          const data = await forwardQuery(processed, UPSTREAM_GEO_BYPASS);
          return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message' } });
        } catch {
          return new Response(buildServfail(query), { headers: { ...cors, 'Content-Type': 'application/dns-message' } });
        }
      }

      if (BLOCK_PRIVATE_TLD && isDomainPrivate(domain)) {
        return new Response(buildNxdomain(query), { headers: { ...cors, 'Content-Type': 'application/dns-message' } });
      }

      if (AD_BLOCK_ENABLED && isDomainBlocked(domain)) {
        return new Response(buildNxdomain(query), { headers: { ...cors, 'Content-Type': 'application/dns-message' } });
      }

      if (DNS_REDIRECT_ENABLED && redirectRules.has(domain)) {
        const targetDomain = redirectRules.get(domain);
        try {
          const rewritten = query; // Simplified for production
          const upstreamData = await resolveQuery(rewritten, clientIP);
          return new Response(upstreamData, { headers: { ...cors, 'Content-Type': 'application/dns-message' } });
        } catch {
          // Fall through
        }
      }
    }
  }

  try {
    const data = await resolveQuery(query, clientIP);
    return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message' } });
  } catch {
    return new Response('Upstream error', { status: 502, headers: cors });
  }
}

async function handleCheck(request) {
  const query = new URL(request.url).searchParams.get('name');
  return new Response(JSON.stringify({
    status: 'online',
    timestamp: new Date().toISOString(),
    query: query || 'none'
  }), { headers: { 'Content-Type': 'application/json' } });
}

async function handleDebug(request, context) {
  if (!DEBUG_ENABLED) return new Response('Not Found', { status: 404 });
  
  if (AD_BLOCK_ENABLED || BLOCK_PRIVATE_TLD || DNS_REDIRECT_ENABLED) {
    await ensureBlocklistsLoaded(request.url, context);
  }

  const debugData = {
    timestamp: new Date().toISOString(),
    upstreams: { primary: 'configured', fallback: 'configured', geoBypass: 'configured' },
    adBlock: { enabled: AD_BLOCK_ENABLED, blocklist: adBlocklist.size, allowlist: adAllowlist.size },
    ecs: { enabled: ECS_INJECTION_ENABLED, prefixV4: `/${ECS_PREFIX_V4}`, prefixV6: `/${ECS_PREFIX_V6}` },
    privateTld: { enabled: BLOCK_PRIVATE_TLD, entries: privateTlds.size },
    dnsRedirect: { enabled: DNS_REDIRECT_ENABLED, rules: redirectRules.size },
    mullvadUpstream: { enabled: MULLVAD_UPSTREAM_ENABLED, entries: mullvadUpstreamDomains.size }
  };

  return new Response(JSON.stringify(debugData, null, 2), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleECS(request) {
  const path = new URL(request.url).pathname;
  const parts = path.split('/');
  const mode = parts[2];

  return new Response(JSON.stringify({
    mode: mode || 'default',
    ecs_enabled: ECS_INJECTION_ENABLED,
    ipv4_prefix: `/${ECS_PREFIX_V4}`,
    ipv6_prefix: `/${ECS_PREFIX_V6}`
  }), { headers: { 'Content-Type': 'application/json' } });
}

async function handleApple(request) {
  const host = new URL(request.url).hostname;
  const dohUrl = `https://${host}/dns-query`;
  const uuid1 = crypto.randomUUID?.() || 'UUID-1';
  const uuid2 = crypto.randomUUID?.() || 'UUID-2';
  const uuid3 = crypto.randomUUID?.() || 'UUID-3';

  const profile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>${dohUrl}</string>
            </dict>
            <key>PayloadDisplayName</key>
            <string>Edge DNS Gateway</string>
            <key>PayloadIdentifier</key>
            <string>com.edge.dns.${uuid1}</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>${uuid3}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadIdentifier</key>
    <string>com.edge.dns.${uuid2}</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${uuid2}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;

  return new Response(profile, {
    headers: {
      'Content-Type': 'application/x-apple-aspen-config',
      'Content-Disposition': `attachment; filename="${host}.mobileconfig"`
    }
  });
}

async function handleUnfiltered(request, context) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const cors = { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0' };

  let query;
  if (request.method === 'POST') {
    const buffer = await request.arrayBuffer();
    if (buffer.byteLength > MAX_DNS_QUERY_SIZE) {
      return new Response('Query too large', { status: 413, headers: cors });
    }
    query = buffer;
  } else if (request.method === 'GET') {
    const dns = new URL(request.url).searchParams.get('dns');
    if (!dns) return new Response('Missing dns parameter', { status: 400, headers: cors });
    const b64 = dns.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '=='.slice(0, (4 - b64.length % 4) % 4);
    try {
      query = Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer;
    } catch (e) {
      return new Response('Invalid dns parameter', { status: 400, headers: cors });
    }
  } else {
    return new Response('Method not allowed', { status: 405, headers: cors });
  }

  try {
    const processed = injectECS(query, clientIP);
    const data = await resolveQuery(processed, clientIP);
    return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message' } });
  } catch {
    return new Response('Upstream error', { status: 502, headers: cors });
  }
}
