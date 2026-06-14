/**
 * DNS Query Processing Order:
 * 1. QTYPE Block (ANY, AAAA, etc.) - Save upstream requests early (NODATA).
 * 2. Mullvad Upstream - Direct bypass to Mullvad for specific domains.
 * 3. Private TLDs - Block internal/router domains with NXDOMAIN.
 * 4. Ad/Tracker Block - Allowlist checked first, then Blocklist (NXDOMAIN).
 * 5. DNS Redirect - CNAME rewrite for local domain overrides.
 * 6. Primary/Fallback Upstream - Final resolution with ECS injection.
 */

// CONFIG_START
const UPSTREAM_PRIMARY = 'https://bu0eg1tdzu.cloudflare-gateway.com/dns-query';
const UPSTREAM_FALLBACK = 'https://rhpcv957tj.cloudflare-gateway.com/dns-query';
const UPSTREAM_GEO_BYPASS = 'https://dns.mullvad.net/dns-query'; // Re-resolve when geo-block returns loopback
const UPSTREAM_TIMEOUT = 5000;

// Refresh interval for ALL lists (blocklist, allowlists, private TLDs, redirect rules)
const ALL_LISTS_REFRESH_INTERVAL = 3600000; // 1 hour

const AD_BLOCK_ENABLED = true;
// List URLs: relative paths served from the same Cloudflare Pages deployment
const BLOCKLIST_URL = '/rules/blocklists.txt';
const ALLOWLIST_URL = '/rules/allowlists.txt';

const ECS_INJECTION_ENABLED = true;
const ECS_PREFIX_V4 = 24;
const ECS_PREFIX_V6 = 48;

// Block query types early to save Cloudflare Pages requests
const BLOCK_ANY = false;    // TYPE 255 — ANY queries
const BLOCK_AAAA = false;   // TYPE 28  — IPv6 queries
const BLOCK_PTR = false;    // TYPE 12  — Reverse DNS
const BLOCK_HTTPS = false;  // TYPE 65  — HTTPS record queries

// Block private/internal TLDs and router domains
const BLOCK_PRIVATE_TLD = true;
const PRIVATE_TLD_URL = '/rules/private_tlds.txt';

// DNS redirect/rewrite (local CNAME overrides)
const DNS_REDIRECT_ENABLED = true;
const REDIRECT_RULES_URL = '/rules/redirect_rules.txt';

// Dedicated Mullvad Upstream Domains
const MULLVAD_UPSTREAM_ENABLED = true;
const MULLVAD_UPSTREAM_URL = '/rules/mullvad_upstream.txt';

// CONFIG_END

// ==================== ECS COUNTRY MAP ====================
// Representative IP per country/ISP — just needs to belong to the correct ASN/range.
// A /24 prefix is sufficient. Update IPs to accurate values as needed.
const CC_TO_ECS_IP = {
    // ── Vietnam — by ISP & region ──────────────────────────────────────────────
    'vn-vnpt-hcm':      '113.173.60.0',     // VNPT Ho Chi Minh City
    'vn-vnpt-hn':       '14.160.0.0',       // VNPT Hanoi
    'vn-vnpt-dn':       '123.25.100.0',     // VNPT Da Nang
    'vn-fpt-hcm':       '1.52.0.0',         // FPT Ho Chi Minh City
    'vn-fpt-hn':        '42.116.101.0',     // FPT Hanoi
    'vn-fpt-dn':        '1.52.225.0',       // FPT Da Nang
    'vn-viettel-hcm':   '27.64.0.0',        // Viettel Ho Chi Minh City
    'vn-viettel-hn':    '103.1.208.0',      // Viettel Hanoi
    'vn-viettel-dn':    '210.211.127.0',    // Viettel Da Nang
    'vn-mb-hcm':        '103.199.79.0',     // MobiFone Ho Chi Minh City
    'vn-mb-hn':         '45.121.24.0',      // MobiFone Hanoi
    'vn-sctv':          '27.2.0.0',         // SCTV
    'vn-cmc':           '42.96.63.255',     // CMC Telecom
    'vn-netnam':        '101.53.0.0',       // NetNam

    // ── Southeast Asia ──────────────────────────────────────────────────────────
    'sg':               '212.165.2.0',      // Singapore
    'th':               '3.2.88.0',         // Thailand
    'my':               '1.9.0.0',          // Malaysia
    'id':               '1.178.19.0',       // Indonesia
    'ph':               '1.37.0.0',         // Philippines
    'mm':               '5.62.63.36',       // Myanmar
    'kh':               '1.32.252.0',       // Cambodia
    'la':               '5.62.16.0',        // Laos
    'bn':               '5.62.60.49',       // Brunei
    'tl':               '43.243.176.0',     // Timor-Leste

    // ── East Asia ───────────────────────────────────────────────────────────────
    'jp':               '1.32.226.0',       // Japan
    'kr':               '1.11.0.0',         // South Korea
    'tw':               '1.32.208.0',       // Taiwan
    'hk':               '2.20.40.0',        // Hong Kong
    'cn':               '1.0.1.0',          // China
    'mo':               '5.62.60.241',      // Macau
    'mn':               '5.62.63.20',       // Mongolia

    // ── South Asia ──────────────────────────────────────────────────────────────
    'in':               '1.6.0.0',          // India
    'pk':               '5.62.35.8',        // Pakistan
    'bd':               '5.62.60.25',       // Bangladesh
    'lk':               '5.62.63.132',      // Sri Lanka
    'np':               '5.62.63.44',       // Nepal
    'mv':               '5.62.62.248',      // Maldives

    // ── Middle East ─────────────────────────────────────────────────────────────
    'ae':               '1.178.20.0',       // UAE
    'sa':               '2.59.52.0',        // Saudi Arabia
    'qa':               '2.23.168.0',       // Qatar
    'kw':               '5.62.60.201',      // Kuwait
    'bh':               '1.178.16.0',       // Bahrain
    'om':               '2.56.253.0',       // Oman
    'il':               '1.178.25.0',       // Israel
    'tr':               '2.16.150.0',       // Turkey
    'ir':               '2.57.3.0',         // Iran
    'iq':               '2.56.36.0',        // Iraq
    'jo':               '2.17.24.0',        // Jordan
    'lb':               '5.8.128.0',        // Lebanon

    // ── Europe ──────────────────────────────────────────────────────────────────
    'gb':               '1.178.94.0',       // United Kingdom
    'de':               '1.178.10.0',       // Germany
    'fr':               '1.178.90.0',       // France
    'nl':               '1.118.32.0',       // Netherlands
    'se':               '1.178.93.0',       // Sweden
    'no':               '13.104.170.0',     // Norway
    'dk':               '2.16.63.0',        // Denmark
    'fi':               '2.16.171.0',       // Finland
    'ch':               '1.178.21.0',       // Switzerland
    'at':               '2.16.16.0',        // Austria
    'be':               '2.17.107.0',       // Belgium
    'es':               '1.178.22.0',       // Spain
    'pt':               '2.16.65.0',        // Portugal
    'it':               '1.178.17.0',       // Italy
    'pl':               '2.16.172.0',       // Poland
    'cz':               '2.16.2.0',         // Czech Republic
    'sk':               '2.57.64.0',        // Slovakia
    'hu':               '2.59.196.0',       // Hungary
    'ro':               '2.17.116.0',       // Romania
    'bg':               '2.20.45.0',        // Bulgaria
    'gr':               '2.16.19.0',        // Greece
    'ua':               '2.21.89.0',        // Ukraine
    'ru':               '2.16.20.0',        // Russia
    'ie':               '1.178.7.0',        // Ireland
    'is':               '2.56.174.0',       // Iceland
    'lt':               '130.41.215.0',     // Lithuania
    'lv':               '104.252.132.0',    // Latvia
    'ee':               '138.124.4.0',      // Estonia
    'hr':               '2.56.175.0',       // Croatia
    'si':               '109.202.120.0',    // Slovenia
    'rs':               '2.56.172.0',       // Serbia
    'ba':               '5.43.64.0',        // Bosnia
    'al':               '5.62.63.236',      // Albania
    'mk':               '5.32.176.0',       // North Macedonia
    'me':               '5.62.63.24',       // Montenegro
    'by':               '5.44.44.0',        // Belarus
    'md':               '5.10.208.0',       // Moldova
    'cy':               '5.42.205.0',       // Cyprus
    'mt':               '2.59.131.0',       // Malta
    'lu':               '2.18.250.0',       // Luxembourg

    // ── North America ───────────────────────────────────────────────────────────
    'us':               '1.32.239.0',       // United States
    'ca':               '1.178.26.0',       // Canada
    'mx':               '1.178.29.0',       // Mexico

    // ── South America & Caribbean ───────────────────────────────────────────────
    'br':               '1.178.32.0',       // Brazil
    'ar':               '1.178.48.0',       // Argentina
    'cl':               '2.18.21.0',        // Chile
    'co':               '2.19.32.0',        // Colombia
    'pe':               '2.23.232.0',       // Peru
    've':               '143.255.84.0',     // Venezuela
    'ec':               '2.57.225.28',      // Ecuador
    'bo':               '5.62.56.40',       // Bolivia
    'py':               '5.62.56.176',      // Paraguay
    'uy':               '5.62.56.244',      // Uruguay
    'cu':               '5.62.56.72',       // Cuba

    // ── Africa ──────────────────────────────────────────────────────────────────
    'za':               '1.178.18.0',       // South Africa
    'ng':               '3.175.217.0',      // Nigeria
    'ke':               '2.17.161.0',       // Kenya
    'eg':               '2.21.128.0',       // Egypt
    'gh':               '2.16.77.0',        // Ghana
    'et':               '5.62.60.129',      // Ethiopia
    'tz':               '2.17.250.0',       // Tanzania
    'ug':               '2.17.248.0',       // Uganda
    'ma':               '5.62.63.28',       // Morocco
    'dz':               '5.62.63.240',      // Algeria
    'tn':               '5.62.63.164',      // Tunisia
    'sd':               '5.62.63.136',      // Sudan
    'ao':               '5.62.60.9',        // Angola
    'zw':               '5.62.63.212',      // Zimbabwe
    'mz':               '5.62.63.32',       // Mozambique
    'cm':               '2.16.134.0',       // Cameroon
    'ci':               '5.62.60.105',      // Cote d'Ivoire
    'sn':               '5.62.63.108',      // Senegal

    // ── Oceania ─────────────────────────────────────────────────────────────────
    'au':               '1.0.0.0',          // Australia
    'nz':               '1.178.27.0',       // New Zealand
    'pg':               '5.62.56.172',      // Papua New Guinea
    'fj':               '5.62.56.96',       // Fiji
};

// Pre-compiled regex patterns for performance
const IPV4_MAPPED_REGEX = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i;
const IPV6_VALID_REGEX = /^[0-9a-f:]+$/i;
const IPV6_GROUP_REGEX = /^[0-9a-f]+$/i;
const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_FULL_REGEX = /^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$/;

// ==================== CF ASN → ECS IP MAP (Vietnam ISPs) ====================
// Maps Cloudflare ASN numbers to representative IPs for finer-grained ECS.
// Covers major Vietnamese ISPs; other countries use CC_TO_ECS_IP.
const ASN_TO_ECS_IP = {
    // Vietnam — VNPT
    45899: '14.160.0.0',     // VNPT Vietnam
    // Vietnam — Viettel
    7552:  '27.64.0.0',      // Viettel Group
    45903: '103.1.208.0',    // Viettel Hanoi
    // Vietnam — FPT Telecom
    18403: '42.116.101.0',   // FPT Telecom
    // Vietnam — MobiFone
    38731: '103.199.79.0',   // MobiFone
    // Vietnam — SCTV
    131432: '27.2.0.0',
    // Vietnam — CMC Telecom
    38325: '42.96.63.255',
    // Vietnam — NetNam
    10220: '101.53.0.0',
};

function isValidIP(ip) {
    return IPV4_REGEX.test(ip) || IPV6_FULL_REGEX.test(ip);
}

function ipToReverseDomain(ip) {
    if (ip.includes(':')) {
        // IPv6
        let expanded = ip;
        if (ip.includes('::')) {
            const [head, tail] = ip.split('::');
            const headParts = head ? head.split(':') : [];
            const tailParts = tail ? tail.split(':') : [];
            const missing = 8 - (headParts.length + tailParts.length);
            expanded = headParts.concat(Array(missing).fill('0')).concat(tailParts).join(':');
        } else {
            const parts = ip.split(':');
            if (parts.length < 8) {
                expanded = parts.concat(Array(8 - parts.length).fill('0')).join(':');
            }
        }
        const parts = expanded.split(':').map(p => p.padStart(4, '0'));
        return parts.join('').split('').reverse().join('.') + '.ip6.arpa';
    } else {
        // IPv4
        return ip.split('.').reverse().join('.') + '.in-addr.arpa';
    }
}

// ==================== STATE ====================
let adBlocklist = new Set();
let adAllowlist = new Set();
let privateTlds = new Set();
let redirectRules = new Map(); // domain → target domain
let mullvadUpstreamDomains = new Set();
let blocklistLastFetch = 0;
let blocklistPromise = null;
let blocklistsFetched = false; // Track if lists have been fetched at least once

// ==================== AD BLOCK ====================
async function fetchList(url) {
    try {
        const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
        if (!res.ok) return new Set();
        const text = await res.text();
        const domains = new Set();
        for (const line of text.split('\n')) {
            const d = line.trim();
            if (d && !d.startsWith('#') && !d.startsWith('!')) domains.add(d);
        }
        return domains;
    } catch { return new Set(); }
}

async function fetchRedirectRules(url) {
    try {
        const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
        if (!res.ok) return new Map();
        const text = await res.text();
        const rules = new Map();
        for (const line of text.split('\n')) {
            const d = line.trim();
            if (!d || d.startsWith('#') || d.startsWith('!')) continue;
            const parts = d.split(/\s+/);
            if (parts.length === 2) rules.set(parts[0].toLowerCase(), parts[1].toLowerCase());
        }
        return rules;
    } catch { return new Map(); }
}

async function refreshBlocklists(baseUrl) {
    if (blocklistsFetched && Date.now() - blocklistLastFetch < ALL_LISTS_REFRESH_INTERVAL) return;
    if (blocklistPromise) return blocklistPromise;

    blocklistPromise = (async () => {
        try {
            // Support both relative paths (e.g. '/rules/blocklists.txt') and absolute URLs
            const resolveUrl = (path) => path.startsWith('http') ? path : new URL(path, baseUrl).toString();
            const bUrl = resolveUrl(BLOCKLIST_URL);
            const aUrl = resolveUrl(ALLOWLIST_URL);
            const pUrl = resolveUrl(PRIVATE_TLD_URL);
            const rUrl = resolveUrl(REDIRECT_RULES_URL);
            const mUrl = resolveUrl(MULLVAD_UPSTREAM_URL);

            const [block, allow, privateList, redirRules, mullvadList] = await Promise.all([
                AD_BLOCK_ENABLED ? fetchList(bUrl) : Promise.resolve(new Set()),
                AD_BLOCK_ENABLED ? fetchList(aUrl) : Promise.resolve(new Set()),
                BLOCK_PRIVATE_TLD ? fetchList(pUrl) : Promise.resolve(new Set()),
                DNS_REDIRECT_ENABLED ? fetchRedirectRules(rUrl) : Promise.resolve(new Map()),
                MULLVAD_UPSTREAM_ENABLED ? fetchList(mUrl) : Promise.resolve(new Set())
            ]);

            if (AD_BLOCK_ENABLED) { adBlocklist = block; adAllowlist = allow; }
            if (BLOCK_PRIVATE_TLD) { privateTlds = privateList; }
            if (DNS_REDIRECT_ENABLED) { redirectRules = redirRules; }
            if (MULLVAD_UPSTREAM_ENABLED) { mullvadUpstreamDomains = mullvadList; }

            blocklistLastFetch = Date.now();
            blocklistsFetched = true;
            console.log(`[DNS] Lists refreshed — block:${adBlocklist.size} allow:${adAllowlist.size} tlds:${privateTlds.size} redir:${redirectRules.size} mullvad:${mullvadUpstreamDomains.size}`);
        } catch(e) {
            console.error('[DNS] Failed to refresh blocklists:', e.message);
        } finally { blocklistPromise = null; }
    })();

    return blocklistPromise;
}

// Extract QTYPE from first question section
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

// Build set of blocked query types from config
function getBlockedQtypes() {
    const blocked = new Set();
    if (BLOCK_ANY) blocked.add(255);
    if (BLOCK_AAAA) blocked.add(28);
    if (BLOCK_PTR) blocked.add(12);
    if (BLOCK_HTTPS) blocked.add(65);
    return blocked;
}
const BLOCKED_QTYPES = getBlockedQtypes();

// Parse all question domains
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
            off += 4; // QTYPE + QCLASS
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
    // Allowlist takes priority — exact match only
    if (adAllowlist.has(domain)) return false;
    // Blocklist: check exact domain match
    if (adBlocklist.has(domain)) return true;
    // Subdomain check: if parent domain is blocked, block subdomain too
    let pos = 0;
    while ((pos = domain.indexOf('.', pos)) !== -1) {
        if (adBlocklist.has(domain.substring(pos + 1)) && !adAllowlist.has(domain.substring(pos + 1))) return true;
        pos++;
    }
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

// Convert binary DNS response to JSON format with support for common record types
function dnsResponseToJson(buffer) {
    const v = new Uint8Array(buffer);
    if (v.length < 12) return { Status: 2, Comment: "Invalid response" };
    const res = {
        Status: v[3] & 0x0F,
        TC: !!(v[2] & 0x02),
        RD: !!(v[2] & 0x01),
        RA: !!(v[3] & 0x80),
        AD: !!(v[3] & 0x20),
        CD: !!(v[3] & 0x10),
        Question: [],
        Answer: [],
        Authority: [],
        Additional: []
    };
    let off = 12;

    const parseName = () => {
        let labels = [];
        let curr = off;
        let jumped = false;
        let depth = 0;

        while (depth < 20 && curr < v.length) {
            const b = v[curr];
            if (b === 0) {
                if (!jumped) off = curr + 1;
                curr++;
                break;
            }
            if ((b & 0xC0) === 0xC0) {
                if (curr + 1 >= v.length) break;
                const ptr = ((b & 0x3F) << 8) | v[curr + 1];
                if (!jumped) off = curr + 2;
                jumped = true;
                curr = ptr;
                depth++;
            } else {
                const l = v[curr++];
                if (curr + l > v.length) break;
                let label = "";
                for (let i = 0; i < l; i++) label += String.fromCharCode(v[curr++]);
                labels.push(label);
            }
        }
        if (!jumped && off < curr) off = curr;
        return labels.length === 0 ? "." : labels.join('.');
    };

    // Helper: add trailing dot — only if name is not root "."
    const fqdn = (name) => name === '.' ? name : name + '.';

    // Helper: bytes slice → uppercase hex string
    const toHex = (from, to) =>
        Array.from(v.slice(from, to)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    // Helper: bytes slice → base64 string
    const toB64 = (from, to) => btoa(String.fromCharCode(...v.slice(from, to)));

    // Helper: Compress IPv6 address (replace longest run of zeros with ::)
    const compressIPv6 = (ip) => {
        const segments = ip.split(':');
        let maxStart = -1, maxLen = 0, currStart = -1, currLen = 0;
        for (let i = 0; i < segments.length; i++) {
            if (segments[i] === '0') {
                if (currStart === -1) currStart = i;
                currLen++;
                if (currLen > maxLen) { maxStart = currStart; maxLen = currLen; }
            } else { currStart = -1; currLen = 0; }
        }
        if (maxLen > 1) {
            const left = segments.slice(0, maxStart).join(':');
            const right = segments.slice(maxStart + maxLen).join(':');
            return `${left}::${right}`;
        }
        return ip;
    };

    const TYPE_NAMES = {
        1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 13:'HINFO', 15:'MX', 16:'TXT', 17:'RP', 18:'AFSDB',
        24:'SIG', 25:'KEY', 28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 37:'CERT', 39:'DNAME', 43:'DS',
        44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC', 48:'DNSKEY', 52:'TLSA', 59:'CDS', 60:'CDNSKEY',
        64:'SVCB', 65:'HTTPS', 99:'SPF', 256:'URI', 257:'CAA'
    };

    const parseRdata = (type, len) => {
        const start = off;
        let d = "";
        try {
            if (type === 1 && len === 4) { // A
                d = `${v[off]}.${v[off+1]}.${v[off+2]}.${v[off+3]}`;

            } else if (type === 28 && len === 16) { // AAAA
                const p = []; for (let j=0; j<8; j++) p.push(((v[off+j*2]<<8)|v[off+j*2+1]).toString(16));
                d = compressIPv6(p.join(":"));

            } else if (type === 5 || type === 2 || type === 12 || type === 39) { // CNAME, NS, PTR, DNAME
                d = fqdn(parseName());

            } else if (type === 17) { // RP
                const mbox = parseName(); const txt = parseName();
                d = `${fqdn(mbox)} ${fqdn(txt)}`;

            } else if (type === 13) { // HINFO
                let hOff = off; const cpuLen = v[hOff++]; let cpu = ""; for (let j=0; j<cpuLen; j++) cpu += String.fromCharCode(v[hOff++]);
                const osLen = v[hOff++]; let os = ""; for (let j=0; j<osLen; j++) os += String.fromCharCode(v[hOff++]);
                d = `"${cpu}" "${os}"`;

            } else if (type === 15) { // MX
                const pref = (v[off] << 8) | v[off+1];
                off += 2;
                d = `${pref} ${fqdn(parseName())}`;

            } else if (type === 33) { // SRV
                const prio = (v[off] << 8) | v[off+1]; const weight = (v[off+2] << 8) | v[off+3]; const port = (v[off+4] << 8) | v[off+5];
                off += 6;
                d = `${prio} ${weight} ${port} ${fqdn(parseName())}`;

            } else if (type === 16 || type === 99) { // TXT, SPF
                let txt = "", tOff = off;
                while (tOff < start + len) { const l = v[tOff++]; for (let j=0; j<l; j++) txt += String.fromCharCode(v[tOff++]); }
                d = txt;

            } else if (type === 6) { // SOA
                const mname = parseName(); const rname = parseName();
                const serial = ((v[off]<<24|v[off+1]<<16|v[off+2]<<8|v[off+3])>>>0); off += 4;
                const refresh = ((v[off]<<24|v[off+1]<<16|v[off+2]<<8|v[off+3])>>>0); off += 4;
                const retry = ((v[off]<<24|v[off+1]<<16|v[off+2]<<8|v[off+3])>>>0); off += 4;
                const expire = ((v[off]<<24|v[off+1]<<16|v[off+2]<<8|v[off+3])>>>0); off += 4;
                const min = ((v[off]<<24|v[off+1]<<16|v[off+2]<<8|v[off+3])>>>0);
                d = `${fqdn(mname)} ${fqdn(rname)} ${serial} ${refresh} ${retry} ${expire} ${min}`;

            } else if (type === 35) { // NAPTR
                const order = (v[off]<<8)|v[off+1]; const pref = (v[off+2]<<8)|v[off+3]; let nOff = off+4;
                const fLen = v[nOff++]; let f = ""; for(let j=0; j<fLen; j++) f += String.fromCharCode(v[nOff++]);
                const sLen = v[nOff++]; let s = ""; for(let j=0; j<sLen; j++) s += String.fromCharCode(v[nOff++]);
                const rLen = v[nOff++]; let re = ""; for(let j=0; j<rLen; j++) re += String.fromCharCode(v[nOff++]);
                off = nOff;
                d = `${order} ${pref} "${f}" "${s}" "${re}" ${fqdn(parseName())}`;

            } else if (type === 44) { // SSHFP
                d = `${v[off]} ${v[off+1]} ${toHex(off+2, start+len)}`;

            } else if (type === 43 || type === 59) { // DS, CDS
                const kt = (v[off]<<8)|v[off+1]; d = `${kt} ${v[off+2]} ${v[off+3]} ${toHex(off+4, start+len)}`;

            } else if (type === 48 || type === 60 || type === 25) { // DNSKEY, CDNSKEY, KEY
                const f = (v[off]<<8)|v[off+1]; d = `${f} ${v[off+2]} ${v[off+3]} ${toB64(off+4, start+len)}`;

            } else if (type === 52) { // TLSA
                d = `${v[off]} ${v[off+1]} ${v[off+2]} ${toHex(off+3, start+len)}`;

            } else if (type === 37) { // CERT
                const ct = (v[off]<<8)|v[off+1]; const kt = (v[off+2]<<8)|v[off+3]; d = `${ct} ${kt} ${v[off+4]} ${toB64(off+5, start+len)}`;

            } else if (type === 46 || type === 24) { // RRSIG, SIG
                const tc = (v[off]<<8)|v[off+1]; const al = v[off+2]; const lb = v[off+3];
                const ottl = ((v[off+4]<<24|v[off+5]<<16|v[off+6]<<8|v[off+7])>>>0);
                const exp = ((v[off+8]<<24|v[off+9]<<16|v[off+10]<<8|v[off+11])>>>0);
                const inc = ((v[off+12]<<24|v[off+13]<<16|v[off+14]<<8|v[off+15])>>>0);
                const kt = (v[off+16]<<8)|v[off+17]; off += 18;
                const sgn = parseName(); const sig = toB64(off, start+len);
                d = `${tc} ${al} ${lb} ${ottl} ${exp} ${inc} ${kt} ${fqdn(sgn)} ${sig}`;

            } else if (type === 47) { // NSEC
                let name = parseName();
                if (name.includes('\u0000')) name = name.replace(/\u0000/g, '\\000');
                const ts = [];
                while (off < start + len) {
                    const wb = v[off++]; const bl = v[off++];
                    for (let i=0; i<bl && off<start+len; i++) {
                        const b = v[off++];
                        for (let bt=0; bt<8; bt++) {
                            if (b & (0x80 >> bt)) {
                                const tID = wb * 256 + i * 8 + bt;
                                ts.push(TYPE_NAMES[tID] || `TYPE${tID}`);
                            }
                        }
                    }
                }
                d = `${fqdn(name)} ${ts.join(' ')}`;

            } else if (type === 11) { // WKS
                const addr = `${v[off]}.${v[off+1]}.${v[off+2]}.${v[off+3]}`; const prot = v[off+4]; const pts = [];
                for (let i=0; i<len-5; i++) { const b = v[off+5+i]; for (let bt=0; bt<8; bt++) if (b & (0x80 >> bt)) pts.push(i * 8 + bt); }
                d = `${addr} ${prot}${pts.length ? ' ' + pts.join(' ') : ''}`;

            } else if (type === 45) { // IPSECKEY
                const prec = v[off]; const gt = v[off+1]; const al = v[off+2]; let iOff = off+3, gw = "";
                if (gt === 0) gw = "."; else if (gt === 1) { gw = `${v[iOff]}.${v[iOff+1]}.${v[iOff+2]}.${v[iOff+3]}`; iOff += 4; }
                else if (gt === 2) { const p = []; for (let j=0; j<8; j++) p.push(((v[iOff+j*2]<<8)|v[iOff+j*2+1]).toString(16)); gw = compressIPv6(p.join(':')); iOff += 16; }
                else if (gt === 3) { off = iOff; gw = fqdn(parseName()); iOff = off; }
                d = `${prec} ${gt} ${al} ${gw} ${toB64(iOff, start+len)}`;

            } else if (type === 257) { // CAA
                const f = v[off]; const tl = v[off+1]; let t = ""; for (let j=0; j<tl; j++) t += String.fromCharCode(v[off+2+j]);
                let vl = ""; for (let j=tl+2; j<len; j++) vl += String.fromCharCode(v[off+j]); d = `${f} ${t} "${vl}"`;

            } else if (type === 64 || type === 65) { // SVCB, HTTPS
                const prio = (v[off]<<8)|v[off+1]; off += 2; const tgt = parseName(); let ps = "";
                while (off < start + len) {
                    const k = (v[off]<<8)|v[off+1]; const pl = (v[off+2]<<8)|v[off+3]; off += 4;
                    if (k === 1) {
                        let alpn = [], aOff = off; while (aOff < off + pl) { const l = v[aOff++]; alpn.push(String.fromCharCode(...v.slice(aOff, aOff + l))); aOff += l; }
                        ps += ` alpn=${alpn.join(',')}`;
                    } else if (k === 4) {
                        let ips = []; for (let j=0; j<pl; j+=4) ips.push(`${v[off+j]}.${v[off+j+1]}.${v[off+j+2]}.${v[off+j+3]}`);
                        ps += ` ipv4hint=${ips.join(',')}`;
                    } else if (k === 5) {
                        ps += ` ech=${toB64(off, off + pl)}`;
                    } else if (k === 6) {
                        let ips = []; for (let j=0; j<pl; j+=16) { const p = []; for (let k=0; k<8; k++) p.push(((v[off+j+k*2]<<8)|v[off+j+k*2+1]).toString(16)); ips.push(compressIPv6(p.join(':'))); }
                        ps += ` ipv6hint=${ips.join(',')}`;
                    } else { ps += ` key${k}=${toHex(off, off+pl)}`; }
                    off += pl;
                }
                d = `${prio} ${fqdn(tgt)}${ps}`;

            } else {
                const bytes = v.slice(off, off + len);
                d = bytes.every(b => b >= 32 && b <= 126) ? String.fromCharCode(...bytes) : toHex(off, off + len);
            }
        } catch { d = "Error parsing RDATA"; }
        off = start + len;
        return d;
    };

    try {
        const qd = (v[4] << 8) | v[5];
        const an = (v[6] << 8) | v[7];
        const ns = (v[8] << 8) | v[9];
        const ar = (v[10] << 8) | v[11];

        for (let i=0; i<qd && off<v.length; i++) {
            const name = fqdn(parseName());
            const type = (v[off] << 8) | v[off+1];
            res.Question.push({ name, type });
            off += 4;
        }

        const parseSection = (count) => {
            const items = [];
            for (let i=0; i<count && off<v.length; i++) {
                const name = fqdn(parseName());
                const type = (v[off]   << 8) | v[off+1];
                const ttl  = ((v[off+4]<<24|v[off+5]<<16|v[off+6]<<8|v[off+7]) >>> 0);
                const len  = (v[off+8] << 8) | v[off+9];
                off += 10;
                const data = parseRdata(type, len);
                items.push({ name, type, TTL: ttl, data });
            }
            return items;
        };

        res.Answer     = parseSection(an);
        res.Authority  = parseSection(ns);
        res.Additional = parseSection(ar).filter(r => r.type !== 41); // Hide OPT
    } catch { res.Comment = "Parse error"; }
    return res;
}

// Build NXDOMAIN response (RCODE=3) - Domain does not exist
function buildNxdomain(query) {
    const v = new Uint8Array(query);
    if (v.length < 12) {
        const sf = new Uint8Array(12);
        sf[2] = 0x84; sf[3] = 0x83;
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
    res[3] = 0x80 | 0x03; // RA=1, RCODE=3 (NXDOMAIN)
    res[4] = 0; res[5] = 1;
    res[6] = 0; res[7] = 0;
    res[8] = 0; res[9] = 0;
    res[10] = 0; res[11] = 0;
    return res.buffer;
}

// NODATA response: RCODE=0 (NOERROR), ANCOUNT=0
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
    res[3] = 0x80; // RA=1, RCODE=0 (NOERROR)
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
    res[3] = 0x80 | 0x02; // RA=1, RCODE=2 (SERVFAIL)
    res[4] = 0; res[5] = 1;
    res[6] = 0; res[7] = 0;
    res[8] = 0; res[9] = 0;
    res[10] = 0; res[11] = 0;
    return res.buffer;
}

// ==================== ECS INJECTION ====================
// Inject EDNS Client Subnet (ECS) into DNS query per RFC 7871
// prefixOverride: override default prefix length (from edns_client_subnet param)
function injectECS(query, clientIP, prefixOverride = null) {
    if (!ECS_INJECTION_ENABLED || !clientIP || clientIP === 'unknown') return query;
    try {
        const v = new Uint8Array(query);
        if (v.length < 12) return query;

        const clean = stripOPT(v);

        const ipv4Mapped = clientIP.match(IPV4_MAPPED_REGEX);
        if (ipv4Mapped) clientIP = ipv4Mapped[1];

        let family, prefixLen, addrBytes;
        if (clientIP.includes(':')) {
            family = 2; prefixLen = prefixOverride ?? ECS_PREFIX_V6;
            const allBytes = ipv6ToBytes(clientIP);
            if (!allBytes) return query;
            const byteLen = Math.ceil(prefixLen / 8);
            addrBytes = allBytes.slice(0, byteLen);
        } else {
            family = 1; prefixLen = prefixOverride ?? ECS_PREFIX_V4;
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

        const currentArCount = (clean[10] << 8) | clean[11];
        const newArCount = currentArCount + 1;

        const result = new Uint8Array(clean.length + opt.length);
        result.set(clean);
        result.set(opt, clean.length);
        result[10] = (newArCount >> 8) & 0xFF;
        result[11] = newArCount & 0xFF;
        return result.buffer;
    } catch { return query; }
}

// Strip existing OPT (EDNS) records from DNS query
function stripOPT(view) {
    let off = 12;
    const qd = (view[4] << 8) | view[5];
    for (let i = 0; i < qd && off < view.length; i++) {
        while (off < view.length) {
            const l = view[off];
            if (l === 0) { off++; break; }
            if ((l & 0xC0) === 0xC0) { off += 2; break; }
            off += l + 1;
        }
        off += 4;
    }
    const an = (view[6] << 8) | view[7];
    const ns = (view[8] << 8) | view[9];
    for (let i = 0; i < an + ns && off < view.length; i++) {
        while (off < view.length) {
            const l = view[off];
            if (l === 0) { off++; break; }
            if ((l & 0xC0) === 0xC0) { off += 2; break; }
            off += l + 1;
        }
        if (off + 10 > view.length) break;
        off += 10 + ((view[off + 8] << 8) | view[off + 9]);
    }
    const ar = (view[10] << 8) | view[11];
    let arOff = off;
    const keptRecords = [];
    for (let i = 0; i < ar && arOff < view.length; i++) {
        const recStart = arOff;
        while (arOff < view.length) {
            const l = view[arOff];
            if (l === 0) { arOff++; break; }
            if ((l & 0xC0) === 0xC0) { arOff += 2; break; }
            arOff += l + 1;
        }
        if (arOff + 10 > view.length) break;
        const type  = (view[arOff] << 8) | view[arOff + 1];
        const rdlen = (view[arOff + 8] << 8) | view[arOff + 9];
        if (arOff + 10 + rdlen > view.length) break;
        arOff += 10 + rdlen;
        if (type !== 41) keptRecords.push(view.subarray(recStart, arOff));
    }
    let totalLen = off;
    for (const rec of keptRecords) totalLen += rec.length;
    const r = new Uint8Array(totalLen);
    r.set(view.subarray(0, off));
    let writeOff = off;
    for (const rec of keptRecords) { r.set(rec, writeOff); writeOff += rec.length; }
    r[10] = (keptRecords.length >> 8) & 0xFF;
    r[11] = keptRecords.length & 0xFF;
    return r;
}

// Convert IPv6 address string to 16-byte array
function ipv6ToBytes(ip) {
    try {
        if (!ip || typeof ip !== 'string') return null;
        if (!IPV6_VALID_REGEX.test(ip)) return null;

        const halves = ip.split('::');
        if (halves.length > 2) return null;

        const left  = halves[0] ? halves[0].split(':').filter(x => x) : [];
        const right = halves.length > 1 && halves[1] ? halves[1].split(':').filter(x => x) : [];
        const totalGroups = left.length + right.length;
        if (totalGroups > 8) return null;

        for (const g of [...left, ...right]) {
            if (g.length > 4 || !IPV6_GROUP_REGEX.test(g)) return null;
        }

        const missing = 8 - totalGroups;
        const full = [...left, ...Array(missing).fill('0'), ...right];
        const bytes = [];
        for (const s of full) {
            const v = parseInt(s || '0', 16);
            if (isNaN(v)) return null;
            bytes.push((v >> 8) & 0xFF, v & 0xFF);
        }
        return bytes;
    } catch { return null; }
}

// Extract ECS (EDNS Client Subnet, option code 8, RFC 7871) from an incoming DNS query.
// Used to honour client-supplied ECS when ECS_INJECTION_ENABLED is true,
// e.g. when the user configures edns-addr in dnsproxy / AdGuard Home.
// Returns { ip: string, prefix: number } or null if no valid ECS found.
function extractECSFromQuery(buf) {
    try {
        const v = new Uint8Array(buf);
        if (v.length < 12) return null;

        // Skip question section
        let off = 12;
        const qd = (v[4] << 8) | v[5];
        for (let i = 0; i < qd && off < v.length; i++) {
            while (off < v.length) {
                const l = v[off];
                if (l === 0) { off++; break; }
                if ((l & 0xC0) === 0xC0) { off += 2; break; }
                off += l + 1;
            }
            off += 4; // QTYPE + QCLASS
        }

        // Skip AN + NS sections
        const an = (v[6] << 8) | v[7];
        const ns = (v[8] << 8) | v[9];
        for (let i = 0; i < an + ns && off < v.length; i++) {
            while (off < v.length) {
                const l = v[off];
                if (l === 0) { off++; break; }
                if ((l & 0xC0) === 0xC0) { off += 2; break; }
                off += l + 1;
            }
            if (off + 10 > v.length) return null;
            const rdlen = (v[off + 8] << 8) | v[off + 9];
            off += 10 + rdlen;
        }

        // Scan Additional section for OPT record (type 41)
        const ar = (v[10] << 8) | v[11];
        for (let i = 0; i < ar && off < v.length; i++) {
            // Parse record name (OPT name is always 0x00)
            while (off < v.length) {
                const l = v[off];
                if (l === 0) { off++; break; }
                if ((l & 0xC0) === 0xC0) { off += 2; break; }
                off += l + 1;
            }
            if (off + 10 > v.length) break;
            const type  = (v[off] << 8) | v[off + 1];
            const rdlen = (v[off + 8] << 8) | v[off + 9];
            off += 10;
            if (type === 41) {
                // Walk OPT RDATA option list
                let optOff = off;
                const optEnd = off + rdlen;
                while (optOff + 4 <= optEnd) {
                    const optCode = (v[optOff] << 8) | v[optOff + 1];
                    const optLen  = (v[optOff + 2] << 8) | v[optOff + 3];
                    optOff += 4;
                    if (optCode === 8 && optLen >= 4) {
                        // ECS: FAMILY(2) + SOURCE_PREFIX(1) + SCOPE_PREFIX(1) + ADDRESS(variable)
                        const family       = (v[optOff] << 8) | v[optOff + 1];
                        const sourcePrefix = v[optOff + 2];
                        // scope prefix (v[optOff+3]) is a server field — ignore in client queries
                        const addrBytes = v.slice(optOff + 4, optOff + optLen);
                        if (family === 1) {
                            // IPv4 — pad to 4 bytes
                            const parts = [0, 0, 0, 0];
                            for (let j = 0; j < Math.min(addrBytes.length, 4); j++) parts[j] = addrBytes[j];
                            return { ip: parts.join('.'), prefix: sourcePrefix };
                        } else if (family === 2) {
                            // IPv6 — pad to 16 bytes, format as groups
                            const fullBytes = new Uint8Array(16);
                            fullBytes.set(addrBytes.slice(0, Math.min(addrBytes.length, 16)));
                            const groups = [];
                            for (let j = 0; j < 8; j++) {
                                groups.push(((fullBytes[j * 2] << 8) | fullBytes[j * 2 + 1]).toString(16));
                            }
                            return { ip: groups.join(':'), prefix: sourcePrefix };
                        }
                    }
                    optOff += optLen;
                }
            }
            off += rdlen;
        }
    } catch { }
    return null;
}

// ==================== DNS REDIRECT ====================
function encodeDomainName(domain) {
    if (!domain || domain === '.') return new Uint8Array([0]);
    const parts = domain.replace(/\.$/, '').split('.');
    let totalLen = 0;
    for (const p of parts) totalLen += p.length + 1;
    const buf = new Uint8Array(totalLen + 1);
    let off = 0;
    for (const p of parts) {
        buf[off++] = p.length;
        for (let i = 0; i < p.length; i++) buf[off++] = p.charCodeAt(i);
    }
    buf[off++] = 0;
    return buf;
}

function decodeName(v, startOff) {
    let labels = [];
    let curr = startOff;
    let jumped = false;
    let nextOff = -1;
    let depth = 0;
    while (depth < 20 && curr < v.length) {
        const b = v[curr];
        if (b === 0) {
            if (!jumped) nextOff = curr + 1;
            curr++;
            break;
        }
        if ((b & 0xC0) === 0xC0) {
            if (curr + 1 >= v.length) break;
            const ptr = ((b & 0x3F) << 8) | v[curr + 1];
            if (!jumped) nextOff = curr + 2;
            jumped = true;
            curr = ptr;
            depth++;
        } else {
            const l = v[curr++];
            if (curr + l > v.length) break;
            let label = "";
            for (let i = 0; i < l; i++) label += String.fromCharCode(v[curr++]);
            labels.push(label);
        }
    }
    return { name: labels.length === 0 ? "." : labels.join('.'), nextOff: jumped ? nextOff : curr };
}

function rewriteQname(query, targetDomain) {
    const v = new Uint8Array(query);
    if (v.length < 12) return query;
    let qnameEnd = 12;
    while (qnameEnd < v.length) {
        const len = v[qnameEnd];
        if (len === 0) { qnameEnd++; break; }
        if ((len & 0xC0) === 0xC0) { qnameEnd += 2; break; }
        qnameEnd += len + 1;
    }
    const targetWire = encodeDomainName(targetDomain);
    const afterQname = v.subarray(qnameEnd);
    const result = new Uint8Array(12 + targetWire.length + afterQname.length);
    result.set(v.subarray(0, 12));
    result.set(targetWire, 12);
    result.set(afterQname, 12 + targetWire.length);
    return result.buffer;
}

function buildRedirectResponse(originalQuery, upstreamResponse, originalDomain, targetDomain) {
    const uv = new Uint8Array(upstreamResponse);
    const qv = new Uint8Array(originalQuery);
    if (uv.length < 12 || qv.length < 12) return upstreamResponse;

    let uOff = 12;
    const uQd = (uv[4] << 8) | uv[5];
    for (let i = 0; i < uQd; i++) {
        uOff = decodeName(uv, uOff).nextOff + 4;
    }

    const anCount = (uv[6] << 8) | uv[7];
    const ansRecords = [];
    for (let i = 0; i < anCount && uOff < uv.length; i++) {
        const dn = decodeName(uv, uOff);
        uOff = dn.nextOff;
        if (uOff + 10 > uv.length) break;
        const type  = (uv[uOff]   << 8) | uv[uOff + 1];
        const cls   = (uv[uOff+2] << 8) | uv[uOff + 3];
        const ttl   = ((uv[uOff+4]<<24)|(uv[uOff+5]<<16)|(uv[uOff+6]<<8)|uv[uOff+7]) >>> 0;
        const rdlen = (uv[uOff+8] << 8) | uv[uOff + 9];
        uOff += 10;
        if (uOff + rdlen > uv.length) break;

        let rdata = uv.slice(uOff, uOff + rdlen);
        if (type === 5 || type === 2 || type === 12) { // CNAME, NS, PTR
            rdata = encodeDomainName(decodeName(uv, uOff).name);
        } else if (type === 15) { // MX
            const pref = uv.slice(uOff, uOff + 2);
            const name = encodeDomainName(decodeName(uv, uOff + 2).name);
            const combined = new Uint8Array(2 + name.length);
            combined.set(pref); combined.set(name, 2);
            rdata = combined;
        } else if (type === 33) { // SRV
            const fixed = uv.slice(uOff, uOff + 6);
            const name = encodeDomainName(decodeName(uv, uOff + 6).name);
            const combined = new Uint8Array(6 + name.length);
            combined.set(fixed); combined.set(name, 6);
            rdata = combined;
        }
        ansRecords.push({ type, cls, ttl, rdata });
        uOff += rdlen;
    }

    let oQEnd = 12;
    oQEnd = decodeName(qv, 12).nextOff + 4;

    const targetWire = encodeDomainName(targetDomain);
    const cnameSize = 2 + 10 + targetWire.length;
    let ansSize = 0;
    for (const rec of ansRecords) ansSize += targetWire.length + 10 + rec.rdata.length;

    const res = new Uint8Array(oQEnd + cnameSize + ansSize);
    res.set(qv.subarray(0, oQEnd));
    res[2] = 0x80 | (qv[2] & 0x7F);
    res[3] = uv[3];
    res[4] = 0; res[5] = 1;
    const newAnCount = 1 + ansRecords.length;
    res[6] = (newAnCount >> 8) & 0xFF;
    res[7] = newAnCount & 0xFF;
    res[8] = 0; res[9] = 0;
    res[10] = 0; res[11] = 0;

    let off = oQEnd;
    res[off++] = 0xC0; res[off++] = 0x0C; // Pointer to original query name
    res[off++] = 0x00; res[off++] = 0x05; // TYPE CNAME
    res[off++] = 0x00; res[off++] = 0x01; // CLASS IN
    res[off++] = 0x00; res[off++] = 0x00;
    res[off++] = 0x01; res[off++] = 0x2C; // TTL 300
    res[off++] = (targetWire.length >> 8) & 0xFF;
    res[off++] = targetWire.length & 0xFF;
    res.set(targetWire, off); off += targetWire.length;

    for (const rec of ansRecords) {
        res.set(targetWire, off); off += targetWire.length;
        res[off++] = (rec.type >> 8) & 0xFF; res[off++] = rec.type & 0xFF;
        res[off++] = (rec.cls >> 8) & 0xFF; res[off++] = rec.cls & 0xFF;
        res[off++] = (rec.ttl >> 24) & 0xFF; res[off++] = (rec.ttl >> 16) & 0xFF;
        res[off++] = (rec.ttl >> 8) & 0xFF; res[off++] = rec.ttl & 0xFF;
        res[off++] = (rec.rdata.length >> 8) & 0xFF; res[off++] = rec.rdata.length & 0xFF;
        res.set(rec.rdata, off); off += rec.rdata.length;
    }
    return res.buffer;
}

// ==================== DNS FORWARDING ====================
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

// Resolve DNS query with fallback and geo-bypass logic
// prefixOverride: custom ECS prefix length from edns_client_subnet param
async function resolveQuery(query, clientIP, prefixOverride = null) {
    const processed = injectECS(query, clientIP, prefixOverride);
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

    // Geo-bypass: if upstream returns loopback (127.0.0.1), the domain is geo-blocked.
    // Re-resolve via Mullvad (no ECS) to bypass regional restrictions.
    if (result && hasLoopbackInAnswer(result)) {
        try {
            // Forward WITHOUT ECS so Mullvad doesn't apply geo-restrictions
            const respMullvad = await forwardQuery(query, UPSTREAM_GEO_BYPASS);
            if (!hasLoopbackInAnswer(respMullvad)) return respMullvad;
            return buildNxdomain(query);
        } catch {
            return buildServfail(query);
        }
    }

    return result;
}

// ==================== HELPERS ====================
// Ensure blocklists are loaded (await on first load, background refresh after)
async function ensureBlocklistsLoaded(url, context) {
  if (!blocklistsFetched) {
    // First time: await to ensure lists are loaded
    await refreshBlocklists(url);
  } else if (context) {
    // Already fetched: background refresh only
    context.waitUntil(refreshBlocklists(url));
  }
}

// ==================== AUTO ECS FROM CF DATA ====================
// Determine best ECS IP from Cloudflare request metadata (country + ASN)
// Used as fallback when no explicit /ecs/<cc> path or edns_client_subnet param is set.
function getAutoEcsIP(request) {
    try {
        const cf = request.cf;
        if (!cf) return null;
        // Check ASN-based mapping first (fine-grained, e.g. Vietnamese ISPs)
        const asn = cf.asn;
        if (asn && ASN_TO_ECS_IP[asn]) return ASN_TO_ECS_IP[asn];
        // Fall back to country code mapping
        const cc = (cf.country || '').toLowerCase();
        if (cc && CC_TO_ECS_IP[cc]) return CC_TO_ECS_IP[cc];
    } catch { }
    return null;
}

// ==================== HANDLERS ====================
async function handleDNSQuery(request, context, forceEcsIP = null) {
    // Use forceEcsIP (from /ecs/<cc> path), or auto-detect from CF metadata
    const clientIP = forceEcsIP || getAutoEcsIP(request) || request.headers.get('CF-Connecting-IP') || 'unknown';
    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Accept' };
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    let query;
    const domainParam = url.searchParams.get('domain') || url.searchParams.get('name');

    // Parse edns_client_subnet: e.g. "103.186.65.82" or "103.186.65.0/24" or "2001:db8::/32"
    let ecsIP = clientIP, ecsPrefix = null;
    if (domainParam) {
        const ecsParam = url.searchParams.get('edns_client_subnet');
        if (ecsParam) {
            const slash = ecsParam.indexOf('/');
            ecsIP    = slash !== -1 ? ecsParam.slice(0, slash) : ecsParam;
            ecsPrefix = slash !== -1 ? parseInt(ecsParam.slice(slash + 1)) : null;
        }
    }

    if (domainParam) {
        const typeParam = url.searchParams.get('type') || 'A';
        let qtype = 1;

        // Try to parse as integer first (e.g. ?type=28)
        const parsedInt = parseInt(typeParam);
        if (!isNaN(parsedInt)) {
            qtype = parsedInt;
        } else {
            const typeStr = typeParam.toUpperCase();
            const typeMap = {
                'A': 1, 'NS': 2, 'MD': 3, 'MF': 4, 'CNAME': 5, 'SOA': 6, 'MB': 7, 'MG': 8, 'MR': 9, 'NULL': 10,
                'WKS': 11, 'PTR': 12, 'HINFO': 13, 'MINFO': 14, 'MX': 15, 'TXT': 16, 'RP': 17, 'AFSDB': 18, 'X25': 19, 'ISDN': 20,
                'RT': 21, 'NSAP': 22, 'NSAP-PTR': 23, 'SIG': 24, 'KEY': 25, 'PX': 26, 'GPOS': 27, 'AAAA': 28, 'LOC': 29, 'NXT': 30,
                'EID': 31, 'NIMLOC': 32, 'SRV': 33, 'ATMA': 34, 'NAPTR': 35, 'KX': 36, 'CERT': 37, 'A6': 38, 'DNAME': 39, 'SINK': 40,
                'OPT': 41, 'APL': 42, 'DS': 43, 'SSHFP': 44, 'IPSECKEY': 45, 'RRSIG': 46, 'NSEC': 47, 'DNSKEY': 48, 'DHCID': 49, 'NSEC3': 50,
                'NSEC3PARAM': 51, 'TLSA': 52, 'SMIMEA': 53, 'HIP': 55, 'NINFO': 56, 'RKEY': 57, 'TALINK': 58, 'CDS': 59, 'CDNSKEY': 60,
                'OPENPGPKEY': 61, 'CSYNC': 62, 'ZONEMD': 63, 'SVCB': 64, 'HTTPS': 65, 'DSYNC': 66, 'HHIT': 67, 'BRID': 68, 'SPF': 99, 'UINFO': 100,
                'UID': 101, 'GID': 102, 'UNSPEC': 103, 'NID': 104, 'L32': 105, 'L64': 106, 'LP': 107, 'EUI48': 108, 'EUI64': 109, 'NXNAME': 128,
                'TKEY': 249, 'TSIG': 250, 'IXFR': 251, 'AXFR': 252, 'MAILB': 253, 'MAILA': 254, 'ANY': 255, 'ALL': 255, 'URI': 256, 'CAA': 257, 'AVC': 258,
                'DOA': 259, 'AMTRELAY': 260, 'RESINFO': 261, 'WALLET': 262, 'CLA': 263, 'IPN': 264, 'TA': 32768, 'DLV': 32769
            };
            qtype = typeMap[typeStr] || 1;
        }
        let finalDomain = domainParam.toLowerCase();
        // If query type is PTR (12) or NAPTR (35) and name is an IP address, auto-convert to reverse domain
        const checkIP = finalDomain.endsWith('.') ? finalDomain.slice(0, -1) : finalDomain;
        if ((qtype === 12 || qtype === 35) && isValidIP(checkIP)) {
            finalDomain = ipToReverseDomain(checkIP);
        }
        const qname = encodeDomainName(finalDomain);
        const buf = new Uint8Array(12 + qname.length + 4);
        const id = Math.floor(Math.random() * 65536);
        buf.set([id >> 8, id & 0xFF, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        buf.set(qname, 12);
        const qOff = 12 + qname.length;
        buf[qOff] = qtype >> 8; buf[qOff+1] = qtype & 0xFF; // QTYPE (16-bit)
        buf[qOff+2] = 0; buf[qOff+3] = 1; // QCLASS (IN)
        query = buf.buffer;
    } else if (request.method === 'POST') {
        query = await request.arrayBuffer();
    } else if (request.method === 'GET') {
        const dns = url.searchParams.get('dns');
        if (!dns) return new Response('Missing dns parameter', { status: 400, headers: cors });
        const b64 = dns.replace(/-/g, '+').replace(/_/g, '/');
        const padded = b64 + '=='.slice(0, (4 - b64.length % 4) % 4);
        query = Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer;
    } else {
        return new Response('Method not allowed', { status: 405, headers: cors });
    }

    // If ECS injection is enabled and the client already embedded an ECS option
    // (e.g. via dnsproxy edns-addr / AdGuard Home edns-addr config), honour it
    // instead of using the server-side CF-Connecting-IP.
    // Skip this when forceEcsIP is set (i.e. /ecs/<cc> path) — the country IP takes priority.
    // NOTE: Firefox TRR (Trusted Recursive Resolver) sends ECS ::/56 or ::/0 as a
    // privacy signal — an all-zeros IPv6 that means "don't geo-target me".
    // We must detect and ignore these, falling back to CF-Connecting-IP.
    if (ECS_INJECTION_ENABLED && !forceEcsIP) {
        const clientECS = extractECSFromQuery(query);
        if (clientECS) {
            // Reject all-zeros IPs (privacy signals from Firefox TRR, etc.)
            const isAllZeros = clientECS.ip.includes(':')
                ? clientECS.ip.replace(/[:\s]/g, '').split('').every(c => c === '0')  // IPv6 :: or 0:0:0:...:0
                : clientECS.ip === '0.0.0.0';                                          // IPv4
            if (!isAllZeros) {
                ecsIP     = clientECS.ip;
                ecsPrefix = clientECS.prefix;
            }
        }
    }

    // [DOH VERIFICATION] Intercept token-encoded queries
    const queryDomains = extractAllDomains(query);
    for (const d of queryDomains) {
        // Query đi qua DoH Worker → cache domain để /check WS có thể xác nhận
        if (d && d.endsWith('.dnscheck.tools')) {
            const cache = caches.default;
            context.waitUntil(cache.put(
                `https://doh-verify.internal/dnscheck/${d}`,
                new Response('1', { headers: { 'Cache-Control': 'max-age=120' } })
            ));
        }
    }

    // Block unwanted query types early to save upstream requests
    if (BLOCKED_QTYPES.size > 0) {
        const qtype = extractQtype(query);
        if (qtype !== null && BLOCKED_QTYPES.has(qtype)) {
            const data = buildNodata(query);
            if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json', 'X-Blocked-Type': String(qtype) } });
            return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Blocked-Type': String(qtype) } });
        }
    }

    // Load data if any domain-based filter is enabled
    if (AD_BLOCK_ENABLED || BLOCK_PRIVATE_TLD || DNS_REDIRECT_ENABLED || MULLVAD_UPSTREAM_ENABLED) {
        await ensureBlocklistsLoaded(request.url, context);

        const domains = extractAllDomains(query);
        for (const domain of domains) {
            if (!domain) continue;

            // Mullvad Dedicated Upstream
            if (MULLVAD_UPSTREAM_ENABLED && isMullvadDomain(domain)) {
                try {
                    const processed = injectECS(query, ecsIP, ecsPrefix);
                    const data = await forwardQuery(processed, UPSTREAM_GEO_BYPASS);
                    if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json', 'X-Upstream': 'Mullvad' } });
                    return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Upstream': 'Mullvad' } });
                } catch {
                    const data = buildServfail(query);
                    if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json', 'X-Upstream': 'Mullvad-Failed' } });
                    return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Upstream': 'Mullvad-Failed' } });
                }
            }

            // Private TLD check (NXDOMAIN)
            if (BLOCK_PRIVATE_TLD && isDomainPrivate(domain)) {
                const data = buildNxdomain(query);
                if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json', 'X-Blocked-Private': domain } });
                return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Blocked-Private': domain } });
            }

            // Ad block check (NXDOMAIN)
            if (AD_BLOCK_ENABLED && isDomainBlocked(domain)) {
                const data = buildNxdomain(query);
                if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json', 'X-Blocked': domain } });
                return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Blocked': domain } });
            }

            // DNS redirect
            if (DNS_REDIRECT_ENABLED && redirectRules.has(domain)) {
                const targetDomain = redirectRules.get(domain);
                try {
                    const rewritten = rewriteQname(query, targetDomain);
                    let data = await resolveQuery(rewritten, ecsIP, ecsPrefix);
                    data = buildRedirectResponse(query, data, domain, targetDomain);
                    if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json', 'X-Redirected': `${domain} -> ${targetDomain}` } });
                    return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Redirected': `${domain} -> ${targetDomain}` } });
                } catch { }
            }
        }
    }

    // Forward to upstream
    try {
        const data = await resolveQuery(query, ecsIP, ecsPrefix);
        if (domainParam) return new Response(JSON.stringify(dnsResponseToJson(data)), { headers: { ...cors, 'Content-Type': 'application/json' } });
        return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message' } });
    } catch (e) {
        return new Response(JSON.stringify({ Status: 2, Comment: `Upstream error: ${e.message}` }), { status: 502, headers: { ...cors, 'Content-Type': 'application/json' } });
    }
}

// ==================== DOH VERIFICATION PAGE (WEBSOCKET) ====================
async function handleCheckWS(request, webSocket, context) {
    webSocket.accept();

    const CF_RANGES_V4 = ['173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22','141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20','197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13','104.24.0.0/14','172.64.0.0/13','131.0.72.0/22'];
    const CF_RANGES_V6 = ['2400:cb00::/32','2606:4700::/32','2803:f800::/32','2405:b500::/32','2405:8100::/32','2a06:98c0::/29','2c0f:f248::/32'];

    function ipInCidr(ip, cidr) {
        try {
            const [range, bits] = cidr.split('/');
            const mask = ~((1 << (32 - parseInt(bits))) - 1);
            const toInt = s => s.split('.').reduce((a,b) => (a<<8)|+b, 0);
            return (toInt(ip) & mask) === (toInt(range) & mask);
        } catch { return false; }
    }

    function isCloudflareIP(ip) {
        if (ip.includes(':')) {
            return CF_RANGES_V6.some(r => {
                const [range, bits] = r.split('/');
                const prefixLen = parseInt(bits, 10);
                const rangeBytes = ipv6ToBytes(range);
                const ipBytes = ipv6ToBytes(ip);
                if (!rangeBytes || !ipBytes) return false;
                const byteLen = Math.floor(prefixLen / 8);
                const bitLen = prefixLen % 8;
                for (let i = 0; i < byteLen; i++) if (rangeBytes[i] !== ipBytes[i]) return false;
                if (bitLen > 0) {
                    const mask = (0xFF << (8 - bitLen)) & 0xFF;
                    if ((rangeBytes[byteLen] & mask) !== (ipBytes[byteLen] & mask)) return false;
                }
                return true;
            });
        }
        return CF_RANGES_V4.some(r => ipInCidr(ip, r));
    }

    webSocket.addEventListener('message', async ({ data }) => {
        try {
            const msg = JSON.parse(data);
            if (msg.type !== 'entries') return;

            const cache = caches.default;
            const entries = msg.entries; // [{qname, ip}]

            // Deduplicate qnames to reduce the number of subrequests
            const uniqueQnames = [...new Set(entries.map(e => e.qname.toLowerCase().replace(/\.$/, '')))];
            const cacheResults = new Map();
            
            // Chunk into batches of up to 20 to avoid Cloudflare's 50 concurrent subrequests limit
            for (let i = 0; i < uniqueQnames.length; i += 20) {
                const chunk = uniqueQnames.slice(i, i + 20);
                await Promise.all(chunk.map(async qname => {
                    const inCache = !!(await cache.match(`https://doh-verify.internal/dnscheck/${qname}`));
                    cacheResults.set(qname, inCache);
                }));
            }

            // Map the cache results back to the original entries
            const checkedEntries = entries.map(e => {
                const qname = e.qname.toLowerCase().replace(/\.$/, '');
                return { ...e, qname, inCache: cacheResults.get(qname) };
            });

            const hasDoh = checkedEntries.some(e => e.inCache);

            // Entries not passing through DoH — this is the user's alternate DNS
            const nonDohEntries = checkedEntries.filter(e => !e.inCache);
            const leakProviders = new Set();
            for (const e of nonDohEntries) {
                if (isCloudflareIP(e.ip)) leakProviders.add('Cloudflare');
                // Other providers are self-classified by the client using existing RANGES
            }

            webSocket.send(JSON.stringify({
                type: 'result',
                hasDoh,
                // Return cached qnames so the client can filter IPs for provider detection
                dohQnames: checkedEntries.filter(e => e.inCache).map(e => e.qname),
                cfLeak: leakProviders.has('Cloudflare'),
            }));
            safeCloseWebSocket(webSocket);
        } catch { safeCloseWebSocket(webSocket); }
    });
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(ws) {
    try {
        if (ws.readyState === WS_READY_STATE_OPEN || ws.readyState === WS_READY_STATE_CLOSING) {
            ws.close(1000);
        }
    } catch { }
}

// ==================== UNFILTERED HANDLER ====================
// Bypasses ad-block and DNS redirect — direct upstream resolution with ECS only.
// Useful for diagnostics or trusted clients that need unfiltered results.
async function handleUnfiltered(request, context) {
    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Accept', 'Cache-Control': 'no-store' };
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    const clientIP = getAutoEcsIP(request) || request.headers.get('CF-Connecting-IP') || 'unknown';
    let query;
    const url = new URL(request.url);

    if (request.method === 'POST') {
        const buffer = await request.arrayBuffer();
        if (buffer.byteLength > 512) return new Response('Query too large', { status: 413, headers: cors });
        query = buffer;
    } else if (request.method === 'GET') {
        const dns = url.searchParams.get('dns');
        if (!dns) return new Response('Missing dns parameter', { status: 400, headers: cors });
        const b64 = dns.replace(/-/g, '+').replace(/_/g, '/');
        const padded = b64 + '=='.slice(0, (4 - b64.length % 4) % 4);
        try { query = Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer; }
        catch { return new Response('Invalid dns parameter', { status: 400, headers: cors }); }
    } else {
        return new Response('Method not allowed', { status: 405, headers: cors });
    }

    try {
        const data = await resolveQuery(query, clientIP);
        const domainParam = url.searchParams.get('domain') || url.searchParams.get('name');
        if (domainParam) {
            return new Response(JSON.stringify(dnsResponseToJson(data)), {
                headers: { ...cors, 'Content-Type': 'application/json', 'X-Upstream': 'unfiltered' }
            });
        }
        return new Response(data, { headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Upstream': 'unfiltered' } });
    } catch {
        return new Response('Upstream error', { status: 502, headers: cors });
    }
}

// ==================== DEBUG HANDLER ====================
// Returns live gateway status: list sizes, upstream URLs, feature flags.
async function handleDebug(request, context) {
    const cors = { 'Access-Control-Allow-Origin': '*' };
    await ensureBlocklistsLoaded(request.url, context);
    const debugData = {
        timestamp: new Date().toISOString(),
        upstreams: {
            primary:   UPSTREAM_PRIMARY,
            fallback:  UPSTREAM_FALLBACK,
            geoBypass: UPSTREAM_GEO_BYPASS
        },
        features: {
            adBlock:        { enabled: AD_BLOCK_ENABLED,          blocklist: adBlocklist.size, allowlist: adAllowlist.size },
            ecs:            { enabled: ECS_INJECTION_ENABLED,      prefixV4: `/${ECS_PREFIX_V4}`, prefixV6: `/${ECS_PREFIX_V6}` },
            privateTld:     { enabled: BLOCK_PRIVATE_TLD,          entries: privateTlds.size },
            dnsRedirect:    { enabled: DNS_REDIRECT_ENABLED,       rules: redirectRules.size },
            mullvadUpstream:{ enabled: MULLVAD_UPSTREAM_ENABLED,   entries: mullvadUpstreamDomains.size }
        },
        queryFilters: { BLOCK_ANY, BLOCK_AAAA, BLOCK_PTR, BLOCK_HTTPS },
        listLastFetched: blocklistLastFetch ? new Date(blocklistLastFetch).toISOString() : 'never'
    };
    return new Response(JSON.stringify(debugData, null, 2), {
        headers: { ...cors, 'Content-Type': 'application/json' }
    });
}

// ==================== ROUTING ====================
async function handleRequest(request, context) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, ''); // Remove trailing slash
    const upgradeHeader = request.headers.get('Upgrade')?.toLowerCase();

    // Route to Verification Check (WebSocket upgrade)
    if (path === '/check' && upgradeHeader === 'websocket') {
        const [client, server] = Object.values(new WebSocketPair());
        handleCheckWS(request, server, context).catch(() => safeCloseWebSocket(server));
        return new Response(null, { status: 101, webSocket: client });
    }

    // Primary DoH endpoint — standard DNS-over-HTTPS
    if (path === '/dns-query') return handleDNSQuery(request, context);

    // Unfiltered endpoint — bypass ad-block and redirect rules (raw upstream)
    if (path === '/unfiltered') return handleUnfiltered(request, context);

    // Debug endpoint — live gateway status (list sizes, feature flags, upstreams)
    if (path === '/debug') return handleDebug(request, context);

    // ECS country/ISP override endpoint — e.g. /ecs/vn-fpt-hcm
    if (path.startsWith('/ecs/')) {
        const cc = path.slice(5).toLowerCase(); // e.g. 'vn', 'vn-fpt-hcm', 'sg'
        const ecsIP = CC_TO_ECS_IP[cc];
        if (!ecsIP) {
            const validKeys = Object.keys(CC_TO_ECS_IP).sort().join('\n');
            return new Response(`Unknown country/ISP code: "${cc}"\n\nValid codes:\n${validKeys}`, {
                status: 404,
                headers: { 'Content-Type': 'text/plain; charset=utf-8' }
            });
        }
        // Forward DNS query using the representative ECS IP for the selected country/ISP
        return handleDNSQuery(request, context, ecsIP);
    }

    if (path.startsWith('/apple')) {
        const host = new URL(request.url).hostname;
        
        let dohUrl = `https://${host}/dns-query`;
        let displayName = `${host} DoH`;
        let identifierSuffix = '';
        let filename = `${host}.mobileconfig`;

        // Check if it's a variant (e.g. /apple/vn-vnpt-hcm)
        if (path.length > 7 && path.charAt(6) === '/') {
            const vid = path.slice(7).toLowerCase();
            if (CC_TO_ECS_IP[vid]) {
                dohUrl = `https://${host}/ecs/${vid}`;
                displayName = `${host} DoH - ${vid.toUpperCase()}`;
                identifierSuffix = `.${vid}`;
                filename = `${host}-${vid}.mobileconfig`;
            } else {
                return new Response("Unknown variant code", { status: 404 });
            }
        }

        const uuid1 = crypto.randomUUID();
        const uuid2 = crypto.randomUUID();
        const uuid3 = crypto.randomUUID();
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
            <key>PayloadDescription</key>
            <string>Private DNS Resolution by ${host}</string>
            <key>PayloadDisplayName</key>
            <string>${displayName}</string>
            <key>PayloadIdentifier</key>
            <string>com.cloudflare.${uuid1}.dnsSettings.managed${identifierSuffix}</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>${uuid3}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>ProhibitDisablement</key>
            <false/>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Private DNS Resolution by ${host}
    - Privacy &amp; Zero Logs
    - Global Anycast Network
    - Smart Ad Blocking</string>
    <key>PayloadDisplayName</key>
    <string>${displayName}</string>
    <key>PayloadIdentifier</key>
    <string>com.cloudflare.${uuid2}${identifierSuffix}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
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
                'Content-Disposition': `attachment; filename="${filename}"`
            }
        });
    }

    return new Response('Not Found', { status: 404 });
}

export async function onRequest(context) {
    return handleRequest(context.request, context);
}
