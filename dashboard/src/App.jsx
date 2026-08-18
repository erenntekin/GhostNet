import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Globe from "react-globe.gl";
import "flag-icons/css/flag-icons.min.css";
import "./App.css";

function CountryBadge({ code }) {
  if (!code) return null;
  return (
    <span className="country-badge">
      <span className={`fi fi-${code.toLowerCase()}`} />
      <span className="country-code">{code}</span>
    </span>
  );
}

const API_BASE = "http://localhost:8001";
const WS_URL = "ws://localhost:8001/ws/live";
const MAX_PULSES = 200;
const PULSE_LIFETIME_MS = 10000;
const MAX_FEED = 40;

const RISK_COLORS = {
  critical: "#ff3b3b",
  high: "#ff9f1c",
  medium: "#ffd60a",
  low: "#4cc9f0",
};

const MITRE_MAP = {
  "DNS Compromise": { tactic: "Resource Development", id: "T1584.002", name: "Compromise Infrastructure: DNS Server" },
  "DNS Poisoning": { tactic: "Resource Development", id: "T1584.002", name: "Compromise Infrastructure: DNS Server" },
  "Fraud Orders": { tactic: "Impact", id: "T1657", name: "Financial Theft" },
  "DDoS Attack": { tactic: "Impact", id: "T1498", name: "Network Denial of Service" },
  "FTP Brute-Force": { tactic: "Credential Access", id: "T1110", name: "Brute Force" },
  "Ping of Death": { tactic: "Impact", id: "T1499", name: "Endpoint Denial of Service" },
  "Phishing": { tactic: "Initial Access", id: "T1566", name: "Phishing" },
  "Fraud VoIP": { tactic: "Impact", id: "T1657", name: "Financial Theft" },
  "Open Proxy": { tactic: "Command and Control", id: "T1090", name: "Proxy" },
  "Web Spam": { tactic: "Resource Development", id: "T1584", name: "Compromise Infrastructure" },
  "Email Spam": { tactic: "Command and Control", id: "T1071.003", name: "Application Layer Protocol: Mail" },
  "Blog Spam": { tactic: "Resource Development", id: "T1584", name: "Compromise Infrastructure" },
  "VPN IP": { tactic: "Command and Control", id: "T1090.003", name: "Proxy: Multi-hop Proxy" },
  "Port Scan": { tactic: "Reconnaissance", id: "T1595.001", name: "Active Scanning: Scanning IP Blocks" },
  "Hacking": { tactic: "Initial Access", id: "T1190", name: "Exploit Public-Facing Application" },
  "SQL Injection": { tactic: "Initial Access", id: "T1190", name: "Exploit Public-Facing Application" },
  "Spoofing": { tactic: "Defense Evasion", id: "T1036", name: "Masquerading" },
  "Brute-Force": { tactic: "Credential Access", id: "T1110", name: "Brute Force" },
  "Bad Web Bot": { tactic: "Reconnaissance", id: "T1595", name: "Active Scanning" },
  "Exploited Host": { tactic: "Resource Development", id: "T1584.005", name: "Compromise Infrastructure: Botnet" },
  "Web App Attack": { tactic: "Initial Access", id: "T1190", name: "Exploit Public-Facing Application" },
  "SSH": { tactic: "Credential Access", id: "T1110", name: "Brute Force" },
  "IoT Targeted": { tactic: "Resource Development", id: "T1584.005", name: "Compromise Infrastructure: Botnet" },
};

const MITRE_TACTIC_COLOR = {
  "Reconnaissance": "#4cc9f0",
  "Resource Development": "#2dd4bf",
  "Initial Access": "#f472b6",
  "Credential Access": "#818cf8",
  "Command and Control": "#a78bfa",
  "Defense Evasion": "#fbbf24",
  "Impact": "#ff3b3b",
};

const CATEGORY_DEFINITIONS = {
  "DNS Compromise": "An attacker gained unauthorized control over a DNS server, letting them redirect traffic to malicious destinations.",
  "DNS Poisoning": "Corrupting a DNS resolver's cache with false records so users are silently redirected to attacker-controlled sites.",
  "Fraud Orders": "Placing fraudulent purchase orders, typically using stolen payment details.",
  "DDoS Attack": "Flooding a target with traffic from many sources at once to knock it offline.",
  "FTP Brute-Force": "Repeatedly guessing FTP file-server login credentials.",
  "Ping of Death": "Sending oversized or malformed network packets designed to crash the target system.",
  "Phishing": "Impersonating a trusted source to trick victims into revealing credentials or installing malware.",
  "Fraud VoIP": "Abusing internet telephony services for toll fraud or scam calls.",
  "Open Proxy": "An improperly secured proxy server being used to relay traffic and hide the true origin of abuse.",
  "Web Spam": "Automated posting of spam content (links, ads) to websites, forums, or comment sections.",
  "Email Spam": "Sending unsolicited bulk email, often for scams or malware distribution.",
  "Blog Spam": "Automated posting of spam comments/links on blogs to manipulate search rankings.",
  "VPN IP": "Address belongs to a known VPN service, flagged for visibility, not necessarily malicious on its own.",
  "Port Scan": "Systematically probing a target's network ports to find services that can be attacked.",
  "Hacking": "General unauthorized access attempt against a system.",
  "SQL Injection": "Injecting malicious SQL code through a website's input fields to manipulate its database.",
  "Spoofing": "Forging the source address of network traffic to impersonate another host.",
  "Brute-Force": "Systematically trying many password/credential combinations until one works.",
  "Bad Web Bot": "An automated crawler that ignores site rules (robots.txt) or scrapes/abuses a site.",
  "Exploited Host": "A device that has been compromised and is now being used to launch further attacks.",
  "Web App Attack": "Attempting to exploit a vulnerability in a web application.",
  "SSH": "Repeatedly attempting to log into a server over SSH, usually via brute-force.",
  "IoT Targeted": "Attack traffic specifically aimed at Internet-of-Things devices, often to recruit them into a botnet.",
};

const TACTIC_ICONS = {
  "Credential Access": "🔑",
  "Reconnaissance": "🔍",
  "Initial Access": "🚪",
  "Command and Control": "📡",
  "Impact": "💥",
  "Resource Development": "🏗",
  "Defense Evasion": "🥷",
};

function mitreUrl(techniqueId) {
  const [base, sub] = techniqueId.split(".");
  return sub
    ? `https://attack.mitre.org/techniques/${base}/${sub}/`
    : `https://attack.mitre.org/techniques/${base}/`;
}

function TechniqueDrawer({ category, byCategory, onClose }) {
  useEffect(() => {
    if (!category) return;
    function onKey(e) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [category, onClose]);

  if (!category) return null;
  const def = CATEGORY_DEFINITIONS[category] ?? "No definition available.";
  const m = MITRE_MAP[category];
  const totalCount = byCategory?.[category];
  const tracked = totalCount != null;
  const trackedCategories = byCategory ? Object.keys(byCategory).sort() : [];

  return (
    <div className="drawer-backdrop drawer-backdrop-top" onClick={onClose}>
      <div className="technique-drawer" onClick={(e) => e.stopPropagation()}>
        <button className="drawer-close" onClick={onClose} aria-label="Close">×</button>
        <div className="drawer-icon">{m ? TACTIC_ICONS[m.tactic] ?? "⚔" : "⚔"}</div>
        <h2>{category}</h2>
        {m && <span className="drawer-tactic-badge">{m.tactic}</span>}
        <p className="drawer-definition">{def}</p>
        {m ? (
          <div className="drawer-mitre">
            <p className="lookup-subheading">MITRE ATT&amp;CK mapping</p>
            <a className="drawer-technique-link" href={mitreUrl(m.id)} target="_blank" rel="noreferrer">
              {m.id}: {m.name} ↗
            </a>
          </div>
        ) : (
          <p className="empty">No MITRE ATT&amp;CK mapping available for this category.</p>
        )}
        <div className="drawer-stat">
          {tracked ? (
            <>
              <span className="drawer-stat-value">{totalCount.toLocaleString()}</span>
              <span className="drawer-stat-label">event{totalCount === 1 ? "" : "s"} recorded with this category, across the full pipeline history</span>
            </>
          ) : (
            <p className="drawer-stat-untracked">
              No historical count for this category. It comes from AbuseIPDB's own live per-IP lookup, which
              isn't persisted in bulk. Only {trackedCategories.join(", ")} are tracked across pipeline history.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function CategoryFilterBar({ categories, active, onToggle, onShowDetail }) {
  if (categories.length === 0) {
    return (
      <p className="category-filter-empty">Attack-type filter fills in as live events arrive.</p>
    );
  }
  return (
    <div className="category-filter-bar">
      {active && (
        <button className="category-chip category-chip-clear" onClick={() => onToggle(null)}>
          × clear filter
        </button>
      )}
      {categories.map((c) => (
        <span key={c} className={`category-chip-wrap ${active === c ? "active" : ""}`}>
          <button className="category-chip" onClick={() => onToggle(active === c ? null : c)}>
            {c}
          </button>
          <button
            className="category-chip-info"
            onClick={() => onShowDetail(c)}
            title={`View ${c} details`}
            aria-label={`View details for ${c}`}
          >
            ⓘ
          </button>
        </span>
      ))}
    </div>
  );
}

const COUNTRY_CENTROIDS = {
  AD: [1.58, 42.55], AE: [53.85, 23.42], AF: [67.71, 33.94], AG: [-61.80, 17.06],
  AI: [-63.07, 18.22], AL: [20.17, 41.15], AM: [45.04, 40.07], AO: [17.87, -11.20],
  AQ: [-0.07, -75.25], AR: [-63.62, -38.42], AS: [-170.13, -14.27], AT: [14.55, 47.52],
  AU: [133.78, -25.27], AW: [-69.97, 12.52], AZ: [47.58, 40.14], BA: [17.68, 43.92],
  BB: [-59.54, 13.19], BD: [90.36, 23.68], BE: [4.47, 50.50], BF: [-1.56, 12.24],
  BG: [25.49, 42.73], BH: [50.64, 25.93], BI: [29.92, -3.37], BJ: [2.32, 9.31],
  BM: [-64.75, 32.32], BN: [114.73, 4.54], BO: [-63.59, -16.29], BR: [-51.93, -14.24],
  BS: [-77.40, 25.03], BT: [90.43, 27.51], BW: [24.68, -22.33], BY: [27.95, 53.71],
  BZ: [-88.50, 17.19], CA: [-106.35, 56.13], CD: [21.76, -4.04], CF: [20.94, 6.61],
  CG: [15.83, -0.23], CH: [8.23, 46.82], CI: [-5.55, 7.54], CK: [-159.78, -21.24],
  CL: [-71.54, -35.68], CM: [12.35, 7.37], CN: [104.20, 35.86], CO: [-74.30, 4.57],
  CR: [-83.75, 9.75], CU: [-77.78, 21.52], CV: [-24.01, 16.54], CY: [33.43, 35.13],
  CZ: [15.47, 49.82], DE: [10.45, 51.17], DJ: [42.59, 11.83], DK: [9.50, 56.26],
  DM: [-61.37, 15.41], DO: [-70.16, 18.74], DZ: [1.66, 28.03], EC: [-78.18, -1.83],
  EE: [25.01, 58.60], EG: [30.80, 26.82], EH: [-12.89, 24.22], ER: [39.78, 15.18],
  ES: [-3.75, 40.46], ET: [40.49, 9.15], FI: [25.75, 61.92], FJ: [179.41, -16.58],
  FK: [-59.52, -51.80], FM: [150.55, 7.43], FO: [-6.91, 61.89], FR: [2.21, 46.23],
  GA: [11.61, -0.80], GB: [-3.44, 55.38], GD: [-61.60, 12.26], GE: [43.36, 42.32],
  GF: [-53.13, 3.93], GG: [-2.59, 49.47], GH: [-1.02, 7.95], GI: [-5.35, 36.14],
  GL: [-42.60, 71.71], GM: [-15.31, 13.44], GN: [-9.70, 9.95], GP: [-61.55, 16.27],
  GQ: [10.27, 1.65], GR: [21.82, 39.07], GT: [-90.23, 15.78], GU: [144.79, 13.44],
  GW: [-15.18, 11.80], GY: [-58.93, 4.86], HK: [114.11, 22.40], HN: [-86.24, 15.20],
  HR: [15.20, 45.10], HT: [-72.29, 18.97], HU: [19.50, 47.16], ID: [113.92, -0.79],
  IE: [-8.24, 53.41], IL: [34.85, 31.05], IM: [-4.55, 54.24], IN: [78.96, 20.59],
  IO: [71.88, -6.34], IQ: [43.68, 33.22], IR: [53.69, 32.43], IS: [-19.02, 64.96],
  IT: [12.57, 41.87], JE: [-2.13, 49.21], JM: [-77.30, 18.11], JO: [36.24, 30.59],
  JP: [138.25, 36.20], KE: [37.91, -0.02], KG: [74.77, 41.20], KH: [104.99, 12.57],
  KI: [-168.73, -3.37], KM: [43.87, -11.88], KN: [-62.78, 17.36], KP: [127.51, 40.34],
  KR: [127.77, 35.91], KW: [47.48, 29.31], KY: [-80.57, 19.51], KZ: [66.92, 48.02],
  LA: [102.50, 19.86], LB: [35.86, 33.85], LC: [-60.98, 13.91], LI: [9.56, 47.17],
  LK: [80.77, 7.87], LR: [-9.43, 6.43], LS: [28.23, -29.61], LT: [23.88, 55.17],
  LU: [6.13, 49.82], LV: [24.60, 56.88], LY: [17.23, 26.34], MA: [-7.09, 31.79],
  MC: [7.41, 43.75], MD: [28.37, 47.41], ME: [19.37, 42.71], MG: [46.87, -18.77],
  MH: [171.18, 7.13], MK: [21.75, 41.61], ML: [-3.99, 17.57], MM: [95.96, 21.91],
  MN: [103.85, 46.86], MO: [113.55, 22.20], MP: [145.38, 17.33], MQ: [-61.02, 14.64],
  MR: [-10.94, 21.01], MS: [-62.19, 16.74], MT: [14.38, 35.94], MU: [57.55, -20.35],
  MV: [73.22, 3.20], MW: [34.30, -13.25], MX: [-102.55, 23.63], MY: [101.98, 4.21],
  MZ: [35.53, -18.67], NA: [18.49, -22.96], NC: [165.62, -20.90], NE: [8.08, 17.61],
  NG: [8.68, 9.08], NI: [-85.21, 12.87], NL: [5.29, 52.13], NO: [8.47, 60.47],
  NP: [84.12, 28.39], NR: [166.93, -0.52], NU: [-169.87, -19.05], NZ: [174.89, -40.90],
  OM: [55.92, 21.51], PA: [-80.78, 8.54], PE: [-75.02, -9.19], PF: [-149.41, -17.68],
  PG: [143.96, -6.31], PH: [121.77, 12.88], PK: [69.35, 30.38], PL: [19.15, 51.92],
  PM: [-56.27, 46.94], PR: [-66.59, 18.22], PS: [35.23, 31.95], PT: [-8.22, 39.40],
  PW: [134.58, 7.51], PY: [-58.44, -23.44], QA: [51.18, 25.35], RE: [55.53, -21.12],
  RO: [24.97, 45.94], RS: [21.01, 44.02], RU: [105.32, 61.52], RW: [29.87, -1.94],
  SA: [45.08, 23.89], SB: [160.16, -9.65], SC: [55.49, -4.68], SD: [30.22, 12.86],
  SE: [18.64, 60.13], SG: [103.82, 1.35], SH: [-10.03, -24.14], SI: [14.99, 46.15],
  SK: [19.70, 48.67], SL: [-11.78, 8.46], SM: [12.46, 43.94], SN: [-14.45, 14.50],
  SO: [46.20, 5.15], SR: [-56.03, 3.92], SS: [31.31, 6.88], ST: [6.61, 0.19],
  SV: [-88.90, 13.79], SY: [38.997, 34.80], SZ: [31.47, -26.52], TC: [-71.80, 21.69],
  TD: [18.73, 15.45], TG: [0.82, 8.62], TH: [100.99, 15.87], TJ: [71.28, 38.86],
  TL: [125.73, -8.87], TM: [59.56, 38.97], TN: [9.54, 33.89], TO: [-175.20, -21.18],
  TR: [35.24, 38.96], TT: [-61.22, 10.69], TV: [177.65, -7.11], TW: [120.96, 23.70],
  TZ: [34.89, -6.37], UA: [31.17, 48.38], UG: [32.29, 1.37], US: [-95.71, 37.09],
  UY: [-55.77, -32.52], UZ: [64.59, 41.38], VA: [12.45, 41.90], VC: [-61.29, 12.98],
  VE: [-66.59, 6.42], VG: [-64.62, 18.42], VI: [-64.90, 18.34], VN: [108.28, 14.06],
  VU: [166.96, -15.38], WF: [-177.16, -13.77], WS: [-172.10, -13.76], YE: [48.52, 15.55],
  YT: [45.17, -12.83], ZA: [22.94, -30.56], ZM: [27.85, -13.13], ZW: [29.15, -19.02],
  XK: [20.90, 42.60],
};

const COUNTRY_NAMES = {
  US: "United States", CN: "China", RU: "Russia", BR: "Brazil", IN: "India",
  DE: "Germany", FR: "France", GB: "United Kingdom", VN: "Vietnam", KR: "South Korea",
  NL: "Netherlands", SG: "Singapore", ID: "Indonesia", UA: "Ukraine", JP: "Japan",
  HK: "Hong Kong", AO: "Angola", TW: "Taiwan", BE: "Belgium",
};

function countryName(code) {
  return COUNTRY_NAMES[code] || code || "Unknown";
}

function riskColor(risk) {
  return RISK_COLORS[risk] || "#8892b0";
}

function Globe3D({ baseMarkers, pulses, highlight, onMarkerClick }) {
  const containerRef = useRef(null);
  const globeRef = useRef(null);
  const [size, setSize] = useState({ width: 100, height: 100 });

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return undefined;
    const rect = el.getBoundingClientRect();
    setSize({ width: rect.width, height: rect.height });
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      setSize({ width, height });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const g = globeRef.current;
    if (!g) return;
    g.pointOfView({ lat: 15, lng: 10, altitude: 2.1 });
    const controls = g.controls();
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.35;
    controls.enableZoom = true;
    controls.minDistance = 150;
    controls.maxDistance = 480;
  }, []);

  const points = useMemo(() => {
    const maxCount = Math.max(1, ...baseMarkers.map((m) => m.count));
    const historical = baseMarkers.map((m) => ({
      lat: m.coords[1],
      lng: m.coords[0],
      color: "#2dd4bf",
      radius: 0.35 + 0.55 * (Math.log(m.count + 1) / Math.log(maxCount + 1)),
      altitude: 0.005,
      label: `${m.country}: ${m.count.toLocaleString()}`,
    }));
    const live = pulses.map((p) => ({
      lat: p.latitude,
      lng: p.longitude,
      color: riskColor(p.risk_level),
      radius: 0.5,
      altitude: 0.015,
      label: `${p.ip} (${p.city ? `${p.city}, ` : ""}${p.country_code})`,
      ip: p.ip,
    }));
    const searched = highlight
      ? [{ lat: highlight.coords[1], lng: highlight.coords[0], color: "#ffffff", radius: 0.7, altitude: 0.02, label: highlight.label }]
      : [];
    return [...historical, ...live, ...searched];
  }, [baseMarkers, pulses, highlight]);

  const rings = useMemo(
    () => pulses.map((p) => ({ lat: p.latitude, lng: p.longitude, color: riskColor(p.risk_level) })),
    [pulses]
  );

  return (
    <div ref={containerRef} className="globe-container">
      <Globe
        ref={globeRef}
        width={size.width}
        height={size.height}
        backgroundColor="rgba(0,0,0,0)"
        globeImageUrl="https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-night.jpg"
        bumpImageUrl="https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-topology.png"
        showAtmosphere
        atmosphereColor="#4cc9f0"
        atmosphereAltitude={0.16}
        pointsData={points}
        pointLat="lat"
        pointLng="lng"
        pointColor="color"
        pointRadius="radius"
        pointAltitude="altitude"
        pointLabel="label"
        pointResolution={12}
        onPointClick={(p) => p.ip && onMarkerClick && onMarkerClick(p.ip)}
        ringsData={rings}
        ringLat="lat"
        ringLng="lng"
        ringColor={(r) => () => r.color}
        ringMaxRadius={4.5}
        ringPropagationSpeed={2.5}
        ringRepeatPeriod={1100}
      />
    </div>
  );
}

const CONCENTRATION_COLORS = ["#4cc9f0", "#2dd4bf", "#a78bfa", "#f472b6", "#fbbf24"];

function Donut({ segments, restLabel = "Other", centerLabel }) {
  const sum = segments.reduce((s, x) => s + x.value, 0);
  const restValue = Math.max(0, 1 - sum);
  let cursor = 0;
  const stops = segments.map((s) => {
    const start = cursor;
    cursor += s.value;
    return `${s.color} ${(start * 100).toFixed(2)}% ${(cursor * 100).toFixed(2)}%`;
  });
  if (restValue > 0.001) stops.push(`#2a3550 ${(cursor * 100).toFixed(2)}% 100%`);

  return (
    <div className="feature-donut-wrap">
      <div className="feature-donut" style={{ background: `conic-gradient(${stops.join(", ")})` }}>
        <div className="feature-donut-hole">
          <span className="feature-donut-total">{(sum * 100).toFixed(0)}%</span>
          <span className="feature-donut-total-label">{centerLabel}</span>
        </div>
      </div>
      <div className="feature-donut-legend">
        {segments.map((s, i) => (
          <div key={i} className="feature-donut-legend-row">
            <span className="feature-donut-swatch" style={{ background: s.color }} />
            <span className="feature-donut-legend-label">{s.label}</span>
            <span className="feature-donut-legend-pct">{(s.value * 100).toFixed(1)}%</span>
          </div>
        ))}
        {restValue > 0.001 && (
          <div className="feature-donut-legend-row">
            <span className="feature-donut-swatch" style={{ background: "#2a3550" }} />
            <span className="feature-donut-legend-label">{restLabel}</span>
            <span className="feature-donut-legend-pct">{(restValue * 100).toFixed(1)}%</span>
          </div>
        )}
      </div>
    </div>
  );
}

function ConcentrationDonut({ topCountries, total }) {
  if (!topCountries?.length || !total) return null;
  const segments = topCountries.slice(0, 5).map((c, i) => ({
    country: c.country,
    value: c.count / total,
    color: CONCENTRATION_COLORS[i],
  }));
  const sum = segments.reduce((s, x) => s + x.value, 0);
  const restValue = Math.max(0, 1 - sum);

  let cursor = 0;
  const stops = segments.map((s) => {
    const start = cursor;
    cursor += s.value;
    return `${s.color} ${(start * 100).toFixed(2)}% ${(cursor * 100).toFixed(2)}%`;
  });
  if (restValue > 0.001) stops.push(`#2a3550 ${(cursor * 100).toFixed(2)}% 100%`);

  const LABEL_RADIUS = 112;
  let angleCursor = 0;
  const labels = segments.map((s) => {
    const startAngle = angleCursor;
    angleCursor += s.value * 360;
    const midAngle = (startAngle + angleCursor) / 2;
    const rad = (midAngle * Math.PI) / 180;
    const sin = Math.sin(rad);
    const cos = Math.cos(rad);
    const rotation = sin < 0 ? midAngle + 90 : midAngle - 90;
    return {
      key: s.country,
      country: s.country,
      pct: s.value * 100,
      dx: LABEL_RADIUS * sin,
      dy: -LABEL_RADIUS * cos,
      rotation,
    };
  });
  if (restValue > 0.001) {
    const midAngle = (angleCursor + 360) / 2;
    const rad = (midAngle * Math.PI) / 180;
    const sin = Math.sin(rad);
    const cos = Math.cos(rad);
    const rotation = sin < 0 ? midAngle + 90 : midAngle - 90;
    labels.push({
      key: "rest",
      country: null,
      pct: restValue * 100,
      dx: LABEL_RADIUS * sin,
      dy: -LABEL_RADIUS * cos,
      rotation,
    });
  }

  return (
    <div className="concentration-donut-wrap">
      <div className="concentration-donut" style={{ background: `conic-gradient(${stops.join(", ")})` }}>
        <div className="concentration-donut-hole">
          <span className="concentration-donut-total">{(sum * 100).toFixed(0)}%</span>
          <span className="concentration-donut-total-label">top 5</span>
        </div>
        {labels.map((l) => (
          <div
            key={l.key}
            className={`concentration-donut-label${l.country ? "" : " concentration-donut-label-on-dark"}`}
            style={{
              transform: `translate(-50%, -50%) translate(${l.dx.toFixed(1)}px, ${l.dy.toFixed(1)}px) rotate(${l.rotation.toFixed(1)}deg)`,
            }}
          >
            {l.country ? <span className={`fi fi-${l.country.toLowerCase()}`} /> : <span>Other</span>}
            <span className="concentration-donut-label-pct">{l.pct.toFixed(1)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function GeographyPanel({ summary, liveCounts, selectedCountry, onSelect }) {
  const top = summary?.top_countries ?? [];
  const total = summary?.total ?? 0;
  const top5Pct = total ? Math.round((top.slice(0, 5).reduce((s, c) => s + c.count, 0) / total) * 100) : 0;
  const trend = useTrendDelta("gini", 100);
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Where the traffic concentrates</h2>
      </div>
      <p className="trend-subtitle">
        {top5Pct}% of everything hitting this pipeline comes from just 5 countries. Geo-based rate-limiting
        or blocking for those 5 alone would catch most of it, without touching legitimate traffic from
        anywhere else.
      </p>
      <ConcentrationDonut topCountries={top} total={total} />
      {summary?.gini_coefficient != null && (
        <p className="trend-subtitle" style={{ marginTop: 12 }}>
          Concentration score (Gini coefficient): <span className="mono">{summary.gini_coefficient.toFixed(2)}</span>.
          0 would mean spread evenly across every country, 1 would mean all from a single one.
          {trend && trend !== "stable" && ` Currently ${trend}.`}
        </p>
      )}

      <details className="lookup-details tech-detail-toggle" style={{ marginTop: 14 }}>
        <summary>Full ranking (real counts)</summary>
        <div className="tech-detail-body">
          <TopCountriesPanel
            summary={summary}
            liveCounts={liveCounts}
            selectedCountry={selectedCountry}
            onSelect={onSelect}
            maxItems={8}
            historicalOnly
            bare
          />
        </div>
      </details>
    </div>
  );
}

function TopCountriesPanel({ summary, liveCounts, selectedCountry, onSelect, compact, historicalOnly, maxItems, bare }) {
  const [mode, setMode] = useState("historical");
  const historical = summary?.top_countries ?? [];
  const live = useMemo(
    () =>
      Object.entries(liveCounts)
        .map(([country, count]) => ({ country, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 15),
    [liveCounts]
  );
  const all = historicalOnly ? historical : mode === "historical" ? historical : live;
  const limit = maxItems ?? (compact ? 6 : null);
  const countries = limit ? all.slice(0, limit) : all;
  const max = all[0]?.count ?? 1;
  const body = (
    <div className="panel-body">
      {countries.length === 0 && (
        <p className="empty">
          {mode === "live" ? "No live events received yet this session." : "Waiting for data..."}
        </p>
      )}
      {countries.map((c) => {
        const content = (
          <>
            <span className="bar-label"><CountryBadge code={c.country} /></span>
            <div className="bar-track">
              <div className="bar-fill" style={{ width: `${(c.count / max) * 100}%` }} />
            </div>
            <span className="bar-value">{c.count}</span>
          </>
        );
        return historicalOnly ? (
          <div key={c.country} className="bar-row bar-row-static">
            {content}
          </div>
        ) : (
          <button
            key={c.country}
            className={`bar-row ${selectedCountry === c.country ? "active" : ""}`}
            onClick={() => onSelect(selectedCountry === c.country ? null : c.country)}
          >
            {content}
          </button>
        );
      })}
    </div>
  );

  if (bare) return body;

  return (
    <div className={`panel ${compact ? "map-top-countries" : ""}`}>
      <div className="panel-header">
        <h2>Top countries</h2>
        {!historicalOnly && (
          <div className="mode-toggle">
            <button
              className={mode === "historical" ? "active" : ""}
              onClick={() => setMode("historical")}
            >
              historical
            </button>
            <button className={mode === "live" ? "active" : ""} onClick={() => setMode("live")}>
              live session
            </button>
          </div>
        )}
      </div>
      {body}
    </div>
  );
}

function LiveFeedPanel({ events, onIpClick, onExport, categories, categoryFilter, onToggleCategory, onShowDetail }) {
  return (
    <div className="panel live-feed-panel console-panel">
      <div className="panel-header">
        <h2><span className="rec-dot" />Recent events</h2>
        <button className="export-btn-prominent" onClick={onExport} disabled={events.length === 0}>
          ⇩ Export CSV
        </button>
      </div>
      <CategoryFilterBar categories={categories} active={categoryFilter} onToggle={onToggleCategory} onShowDetail={onShowDetail} />
      <div className="panel-body feed">
        {events.length === 0 && <p className="empty">No matching live events yet.</p>}
        {events.map((e) => (
          <button
            key={e.id}
            className="feed-row"
            style={{ borderLeftColor: riskColor(e.risk_level) }}
            onClick={() => onIpClick(e.ip)}
          >
            <div className="feed-row-top">
              <CountryBadge code={e.country_code} />
              <span className="feed-ip">{e.ip}</span>
              <span
                className="feed-risk hint"
                data-tip="Score recorded when this IP was first ingested. A live lookup (click this row) queries AbuseIPDB right now and can land on a different score/decision."
                style={{ color: riskColor(e.risk_level) }}
              >
                {e.risk_level}
              </span>
            </div>
            <div className="feed-row-bottom">
              <span className="feed-source">{e.source}</span>
              <span className="feed-category">{e.categories?.[0] || "uncategorized"}</span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function topPctLabel(unusualPct) {
  if (unusualPct == null) return "unusual";
  const topPct = Math.max(1, 100 - unusualPct);
  return `${topPct}% rarest`;
}

function AnomalyRows({ items, onIpClick, showWhy }) {
  if (items.length === 0) return <p className="empty">No anomalies flagged in the current window.</p>;
  return (
    <div className="anomaly-list">
      {items.map((a, i) => (
        <button key={a.ip + i} className="anomaly-row" onClick={() => onIpClick(a.ip)}>
          <div className="anomaly-row-top">
            <CountryBadge code={a.country_code} />
            <span className="mono anomaly-ip">{a.ip}</span>
            <span
              className="anomaly-score hint"
              data-tip={`Raw IsolationForest score: ${a.anomaly_score.toFixed(3)} (lower = more isolated from the rest of the traffic)`}
            >
              {topPctLabel(a.unusual_pct)}
            </span>
          </div>
          <div className="anomaly-row-bottom">
            <span className="anomaly-source">{a.source}</span>
            <span className="anomaly-category">{a.category || "uncategorized"}</span>
          </div>
          {showWhy && a.why && <p className="anomaly-why">→ {a.why}</p>}
        </button>
      ))}
    </div>
  );
}

function AnomalyPanel({ onIpClick }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    function load() {
      fetch(`${API_BASE}/api/anomalies?limit=6`)
        .then((r) => r.json())
        .then((d) => { setItems(d.items ?? []); setLoading(false); })
        .catch(() => setLoading(false));
    }
    load();
    const interval = setInterval(load, 60000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="panel anomaly-panel-compact console-panel console-panel-alert">
      <div className="panel-header">
        <h2 className="hint" data-tip="IsolationForest, unsupervised: flags events whose source/country/category/score combination doesn't look like the rest of the traffic. See Data → Exhibit F.">
          <span className="rec-dot rec-dot-amber" />Anomalies right now
        </h2>
      </div>
      {loading ? <p className="empty">Loading...</p> : <AnomalyRows items={items} onIpClick={onIpClick} />}
    </div>
  );
}

const ML_FIELD_NAMES = ["country_bucket", "risk_level", "source", "category", "abuse_confidence_score"];

function humanizeFeatureName(raw) {
  const stripped = raw.replace(/^cat__/, "").replace(/^remainder__/, "");
  const field = ML_FIELD_NAMES.find((f) => stripped === f || stripped.startsWith(`${f}_`));
  const humanize = (s) => s.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
  if (!field) return humanize(stripped);
  const value = stripped.slice(field.length + 1);
  return value ? `${humanize(field)}: ${value}` : humanize(field);
}

const MODEL_LABELS = {
  logistic_regression: "Logistic Regression",
  random_forest: "Random Forest",
};

function ConfusionMatrix({ matrix }) {
  if (!matrix) return null;
  const [[tn, fp], [fn, tp]] = matrix;
  const total = tn + fp + fn + tp;
  const cell = (value, kind, label) => (
    <div className={`confusion-cell confusion-${kind}`}>
      <span className="confusion-value">{value.toLocaleString()}</span>
      <span className="confusion-label">{label}</span>
      <span className="confusion-pct">{total ? ((value / total) * 100).toFixed(1) : "0.0"}%</span>
    </div>
  );
  return (
    <div className="confusion-matrix">
      <div className="confusion-axis confusion-axis-top">predicted: no reoffense → reoffense</div>
      <div className="confusion-grid">
        {cell(tn, "correct", "true negative")}
        {cell(fp, "wrong", "false positive")}
        {cell(fn, "wrong", "false negative")}
        {cell(tp, "correct", "true positive")}
      </div>
      <div className="confusion-axis confusion-axis-side">actual: no → yes</div>
    </div>
  );
}

const FEATURE_DONUT_COLORS = ["#4cc9f0", "#818cf8", "#2dd4bf", "#f472b6", "#fbbf24", "#a78bfa", "#34d399", "#fb7185"];

function FeatureDonut({ features }) {
  const top = features.slice(0, 8);
  const segments = top.map((f, i) => ({
    label: humanizeFeatureName(f.feature),
    value: f.importance,
    color: FEATURE_DONUT_COLORS[i % FEATURE_DONUT_COLORS.length],
  }));
  return <Donut segments={segments} restLabel="Other features" centerLabel={`top ${top.length}`} />;
}

function FrequencyPictogram({ count, total = 10, accent, caption }) {
  return (
    <div className={`freq-pictogram exhibit-accent-${accent}`}>
      <div className="freq-pictogram-dots">
        {Array.from({ length: total }).map((_, i) => (
          <span key={i} className={`freq-dot${i < count ? " freq-dot-filled" : ""}`} />
        ))}
      </div>
      <p className="freq-pictogram-caption">{caption}</p>
    </div>
  );
}

function ModelPerformancePanel() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/api/ml/model-info`)
      .then((r) => r.json())
      .then((d) => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const prod = data?.models?.[data?.production_model];
  const modelEntries = data?.models ? Object.entries(data.models) : [];

  return (
    <div className="panel">
      {loading && <p className="empty">Loading...</p>}
      {!loading && !data && <p className="empty">No trained model found. Run ml/train_reoffense_model.py.</p>}
      {!loading && data && prod && (
        <>
          <div className="model-hero">
            <div className="model-hero-freq-row">
              <FrequencyPictogram
                accent="blue"
                count={Math.round(prod.precision * 10)}
                caption={<>Of every <strong>10 IPs</strong> it flags as high-risk, about <strong>{Math.round(prod.precision * 10)}</strong> actually reoffend.</>}
              />
              <FrequencyPictogram
                accent="indigo"
                count={Math.round(prod.recall * 10)}
                caption={<>Of every <strong>10 IPs</strong> that do reoffend, it catches about <strong>{Math.round(prod.recall * 10)}</strong>.</>}
              />
            </div>
            <p className="model-hero-explain">
              That second number is why the higher-recall model is the one deployed. A missed reoffender costs
              more here than chasing down a false alarm. (Single-number summary, if you want one: ROC-AUC{" "}
              <span className="mono hint" data-tip="Area under the ROC curve on held-out test data the model never trained on. 0.5 = a coin flip, 1.0 = perfect.">
                {prod.roc_auc.toFixed(2)}
              </span>.)
            </p>
          </div>

          <div className="provenance-row">
            <div className="provenance-tile">
              <span className="provenance-value">{data.trained_on_rows.toLocaleString()}</span>
              <span className="provenance-label">real IPs, training data</span>
            </div>
            <div className="provenance-tile">
              <span className="provenance-value">{data.live_scored_count != null ? data.live_scored_count.toLocaleString() : "—"}</span>
              <span className="provenance-label">events scored live</span>
            </div>
          </div>
          <p className="exhibit-footnote">
            Looking only at what's known the instant an IP first shows up (source, category, initial score),
            scored live inside the same Spark job that writes to Postgres.
          </p>

          <details className="lookup-details tech-detail-toggle">
            <summary>Technical detail: model comparison, confusion matrix, feature importance</summary>
            <div className="tech-detail-body">
              <div className="tech-detail-block">
                <p className="lookup-subheading">Two models trained, better one deployed</p>
                <div className="history-table-wrapper">
                  <table className="history-table">
                    <thead>
                      <tr>
                        <th>Model</th>
                        <th>Accuracy</th>
                        <th>Precision</th>
                        <th>Recall</th>
                        <th>F1</th>
                        <th>ROC-AUC</th>
                      </tr>
                    </thead>
                    <tbody>
                      {modelEntries.map(([name, m]) => (
                        <tr key={name} className={name === data.production_model ? "cross-source-row" : ""}>
                          <td>{MODEL_LABELS[name] ?? name}{name === data.production_model ? " ⚡" : ""}</td>
                          <td>{(m.accuracy * 100).toFixed(1)}%</td>
                          <td>{(m.precision * 100).toFixed(1)}%</td>
                          <td>{(m.recall * 100).toFixed(1)}%</td>
                          <td>{(m.f1 * 100).toFixed(1)}%</td>
                          <td>{m.roc_auc.toFixed(3)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="briefing-limitation-row">
                  ⚡ deployed. Higher recall, since a missed reoffender costs more here than a false alarm.
                </p>
              </div>

              <div className="tech-detail-row">
                <div className="tech-detail-block">
                  <p className="lookup-subheading">Right and wrong, in practice</p>
                  <ConfusionMatrix matrix={prod.confusion_matrix} />
                </div>

                <div className="tech-detail-block">
                  <p className="lookup-subheading">What drives the prediction</p>
                  <FeatureDonut features={data.feature_importance ?? []} />
                </div>
              </div>
            </div>
          </details>

          <p className="exhibit-footnote" style={{ marginTop: 10 }}>
            One signal among others. It pairs with cross-source corroboration, doesn't replace it.
          </p>
        </>
      )}
    </div>
  );
}

function AnomalyModelPanel({ onIpClick }) {
  const [data, setData] = useState(null);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAllAnomalies, setShowAllAnomalies] = useState(false);

  useEffect(() => {
    Promise.all([
      fetch(`${API_BASE}/api/ml/anomaly-info`).then((r) => r.json()).catch(() => null),
      fetch(`${API_BASE}/api/anomalies?limit=15`).then((r) => r.json()).catch(() => null),
    ]).then(([info, anomalies]) => {
      setData(info);
      setItems(anomalies?.items ?? []);
      setLoading(false);
    });
  }, []);

  return (
    <div className="panel">
      {loading && <p className="empty">Loading...</p>}
      {!loading && !data && <p className="empty">No trained anomaly model found. Run ml/train_anomaly_model.py.</p>}
      {!loading && data && (() => {
        const holds = Math.abs(data.contamination - data.observed_anomaly_rate) < 0.01;
        return (
          <>
            <div className="model-hero">
              <div className="freq-compare exhibit-accent-amber">
                <div className="freq-compare-item">
                  <span className="freq-compare-value">{(data.contamination * 100).toFixed(0)}%</span>
                  <span className="freq-compare-label">told to expect unusual</span>
                </div>
                <span className={`freq-compare-sign ${holds ? "freq-compare-sign-match" : "freq-compare-sign-off"}`}>
                  {holds ? "≈" : "≠"}
                </span>
                <div className="freq-compare-item">
                  <span className="freq-compare-value">{(data.observed_anomaly_rate * 100).toFixed(1)}%</span>
                  <span className="freq-compare-label">actually were, in training</span>
                </div>
              </div>
              <p className="model-hero-explain">
                This model was never shown examples of "unusual" traffic. It just learned what normal traffic
                looks like, and flags anything that doesn't match. There's no right-or-wrong answer to grade it
                against, so the simplest honest check is: does it flag about as often as expected? Right now,{" "}
                {holds ? "yes." : "no, it's drifting from that."}
              </p>
            </div>

            <div className="provenance-row">
              <div className="provenance-tile">
                <span className="provenance-value">{data.trained_on_rows.toLocaleString()}</span>
                <span className="provenance-label">events, unsupervised</span>
              </div>
              <div className="provenance-tile">
                <span className="provenance-value">{data.live_scored_count != null ? data.live_scored_count.toLocaleString() : "—"}</span>
                <span className="provenance-label">scored live</span>
              </div>
            </div>

            <p className="lookup-subheading">Most anomalous right now</p>
            <AnomalyRows items={showAllAnomalies ? items : items.slice(0, 5)} onIpClick={onIpClick} showWhy />
            {items.length > 5 && (
              <button className="show-more-link" onClick={() => setShowAllAnomalies((v) => !v)}>
                {showAllAnomalies ? "Show fewer" : `Show ${items.length - 5} more`}
              </button>
            )}

            <details className="lookup-details tech-detail-toggle" style={{ marginTop: 10 }}>
              <summary>Technical detail: methodology</summary>
              <p className="exhibit-footnote" style={{ marginTop: 8 }}>{data.methodology}</p>
            </details>

            <p className="exhibit-footnote" style={{ marginTop: 10 }}>
              Flags rare combinations, not confirmed threats. Cross-check with cross-source corroboration or the
              reoffense score before acting.
            </p>
          </>
        );
      })()}
    </div>
  );
}

const ATTACK_PATTERN_COLORS = ["#4cc9f0", "#818cf8", "#2dd4bf", "#f472b6", "#fbbf24", "#a78bfa", "#34d399", "#fb7185"];

function AttackPatternDonut({ categories }) {
  if (!categories?.length) return null;
  const segments = categories.map((c, i) => ({
    key: c.category,
    value: c.pct_of_categorized / 100,
    color: ATTACK_PATTERN_COLORS[i % ATTACK_PATTERN_COLORS.length],
  }));

  let cursor = 0;
  const stops = segments.map((s) => {
    const start = cursor;
    cursor += s.value;
    return `${s.color} ${(start * 100).toFixed(2)}% ${(cursor * 100).toFixed(2)}%`;
  });
  if (cursor < 0.999) stops.push(`#2a3550 ${(cursor * 100).toFixed(2)}% 100%`);

  const LABEL_RADIUS = 112;
  const MIN_PCT_TO_LABEL = 4;
  let angleCursor = 0;
  const labels = segments
    .map((s) => {
      const startAngle = angleCursor;
      angleCursor += s.value * 360;
      if (s.value * 100 < MIN_PCT_TO_LABEL) return null;
      const midAngle = (startAngle + angleCursor) / 2;
      const rad = (midAngle * Math.PI) / 180;
      const sin = Math.sin(rad);
      const cos = Math.cos(rad);
      const rotation = sin < 0 ? midAngle + 90 : midAngle - 90;
      return {
        key: s.key,
        pct: s.value * 100,
        dx: LABEL_RADIUS * sin,
        dy: -LABEL_RADIUS * cos,
        rotation,
      };
    })
    .filter(Boolean);

  return (
    <div className="concentration-donut-wrap">
      <div className="concentration-donut" style={{ background: `conic-gradient(${stops.join(", ")})` }}>
        <div className="concentration-donut-hole">
          <span className="concentration-donut-total">{categories.length}</span>
          <span className="concentration-donut-total-label">categories</span>
        </div>
        {labels.map((l) => (
          <div
            key={l.key}
            className="concentration-donut-label"
            style={{
              transform: `translate(-50%, -50%) translate(${l.dx.toFixed(1)}px, ${l.dy.toFixed(1)}px) rotate(${l.rotation.toFixed(1)}deg)`,
            }}
          >
            <span className="concentration-donut-label-pct">{l.pct.toFixed(1)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AttackPatternsPanel() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const trend = useTrendDelta("categorized_pct");

  useEffect(() => {
    fetch(`${API_BASE}/api/attack-patterns`)
      .then((r) => r.json())
      .then((d) => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  return (
    <div className="panel">
      {loading && <p className="empty">Loading...</p>}
      {!loading && !data && <p className="empty">Could not load attack pattern data.</p>}
      {!loading && data && (
        <>
          <p className="trend-subtitle">
            These percentages cover the <strong>{data.total_categorized.toLocaleString()} events</strong>{" "}
            ({data.pct_categorized_of_total}% of traffic) that report a category. The rest, mostly AbuseIPDB's
            bulk feed, doesn't specify one.
            {trend && trend !== "stable" && ` That coverage share is currently ${trend}.`}
          </p>
          <AttackPatternDonut categories={data.categories} />
          <div className="attack-pattern-list">
            {data.categories.map((c, i) => (
              <div key={c.category} className="attack-pattern-row">
                <div className="attack-pattern-row-top">
                  <span
                    className="attack-pattern-swatch"
                    style={{ background: ATTACK_PATTERN_COLORS[i % ATTACK_PATTERN_COLORS.length] }}
                  />
                  <span className="attack-pattern-name">{c.category}</span>
                  <span className="attack-pattern-pct">{c.pct_of_categorized}%</span>
                </div>
                {c.top_country && (
                  <p className="attack-pattern-detail">
                    Most often from <CountryBadge code={c.top_country.country} /> ({c.top_country.count.toLocaleString()} events)
                    {c.tactic && <> · MITRE tactic: {c.tactic}</>}
                  </p>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function InfrastructureClustersPanel({ onIpClick }) {
  const [clusters, setClusters] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/api/infrastructure-clusters`)
      .then((r) => r.json())
      .then((d) => { setClusters(d.clusters || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  function exportSubnets() {
    const lines = clusters.map((c) => `deny ${c.subnet};`);
    const blob = new Blob(
      ["# GhostNet auto-generated nginx deny-list: subnets with 3+ independently-flagged IPs\n" + lines.join("\n") + "\n"],
      { type: "text/plain" }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ghostnet-subnet-denylist.conf";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <button className="export-btn-prominent" style={{ marginLeft: "auto" }} onClick={exportSubnets} disabled={clusters.length === 0}>
          ⇩ block-list
        </button>
      </div>
      <p className="trend-subtitle">
        Attackers often rent a whole block of addresses and burn through them one by one. Block one,
        and they just switch to the next from the same block. Below are blocks of 256 addresses (a
        "/24") where 3 or more have already attacked. The button exports the whole list, ready to drop
        into a firewall, so the next address from that block gets blocked before it even shows up.
      </p>
      {loading && <p className="empty">Loading...</p>}
      {!loading && clusters.length === 0 && <p className="empty">No subnet with 3+ flagged IPs found.</p>}
      {!loading && clusters.length > 0 && (
        <div className="history-table-wrapper">
          <table className="history-table">
            <thead>
              <tr>
                <th>Subnet</th>
                <th>Country</th>
                <th className="hint" data-tip="Distinct IPs from this /24 seen in GhostNet's own pipeline">
                  Flagged IPs
                </th>
                <th>Sources</th>
                <th>Max score</th>
                <th>Sample IPs</th>
              </tr>
            </thead>
            <tbody>
              {clusters.map((c, i) => (
                <tr key={i}>
                  <td className="mono">{c.subnet}</td>
                  <td><CountryBadge code={c.country_code} /></td>
                  <td>{c.ip_count}</td>
                  <td>{c.sources.join(", ")}</td>
                  <td>{c.max_score}</td>
                  <td className="mono">
                    <span className="category-tags">
                      {c.sample_ips.slice(0, 3).map((ip) => (
                        <button key={ip} className="category-tag" onClick={() => onIpClick(ip)}>{ip}</button>
                      ))}
                      {c.ip_count > 3 && <span className="quality-check-desc">+{c.ip_count - 3} more</span>}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function RepeatOffendersPanel({ onIpClick }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [crossSourceTotal, setCrossSourceTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const trend = useTrendDelta("cross_source_pct");

  useEffect(() => {
    fetch(`${API_BASE}/api/repeat-offenders?page=1&page_size=20`)
      .then((r) => r.json())
      .then((data) => {
        setItems(data.items || []);
        setTotal(data.total || 0);
        setCrossSourceTotal(data.cross_source_total || 0);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  function exportBlocklist(format) {
    const lines = items.map((it) =>
      format === "iptables" ? `iptables -A INPUT -s ${it.ip} -j DROP` : `deny ${it.ip};`
    );
    const header =
      format === "iptables"
        ? "#!/bin/sh\n# GhostNet auto-generated blocklist: ranked by cross-source corroboration first\n"
        : "# GhostNet auto-generated nginx deny-list: ranked by cross-source corroboration first\n";
    const blob = new Blob([header + lines.join("\n") + "\n"], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = format === "iptables" ? "ghostnet-blocklist.sh" : "ghostnet-denylist.conf";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="panel repeat-offenders-panel">
      <div className="panel-header">
        <h2>Repeat offenders: {total.toLocaleString()} IPs seen more than once</h2>
        <div className="export-action-row">
          <button className="export-btn-prominent" onClick={() => exportBlocklist("iptables")} disabled={items.length === 0}>
            ⇩ iptables
          </button>
          <button className="export-btn-prominent" onClick={() => exportBlocklist("nginx")} disabled={items.length === 0}>
            ⇩ nginx
          </button>
        </div>
      </div>
      <p className="trend-subtitle">
        Ranked by how many separate sources confirmed each IP (⚡), not just how often it showed up.{" "}
        <strong>{crossSourceTotal.toLocaleString()} of {total.toLocaleString()}</strong> were confirmed by more
        than one.
        {trend && trend !== "stable" && ` That share is currently ${trend}.`}
      </p>
      {loading && <p className="empty">Loading...</p>}
      {!loading && (
        <div className="history-table-wrapper">
          <table className="history-table">
            <thead>
              <tr>
                <th>IP</th>
                <th>Country</th>
                <th className="hint" data-tip="Which independent feeds have flagged this IP. 2+ means real cross-source corroboration, not just repetition">
                  Sources
                </th>
                <th className="hint" data-tip="How many times this IP appears in GhostNet's own THREAT_EVENTS table, not AbuseIPDB's global report count">
                  Seen in GhostNet
                </th>
                <th>Max score</th>
                <th>Last reported</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it, i) => (
                <tr key={i} onClick={() => onIpClick(it.ip)} className={it.source_count >= 2 ? "cross-source-row" : ""}>
                  <td className="mono">{it.ip}</td>
                  <td><CountryBadge code={it.country_code} /></td>
                  <td>
                    <div className="source-chip-row">
                      {it.source_count >= 2 && <span className="source-flash">⚡</span>}
                      {(it.sources ?? []).map((s) => (
                        <span key={s} className="source-chip">{s}</span>
                      ))}
                    </div>
                  </td>
                  <td>{it.report_count}×</td>
                  <td>{it.max_score}</td>
                  <td className="mono">{formatTimestamp(it.last_reported_at)}</td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={6} className="empty">No repeat offenders found.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function PipelineHealthPanel() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/api/pipeline-health`)
      .then((r) => r.json())
      .then((d) => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const maxBatch = Math.max(1, ...(data?.recent_batches ?? []).map((b) => b.count));
  const STATUS_ICON = { pass: "✓", warn: "⚠", fail: "✗" };

  return (
    <div className="panel pipeline-health-panel">
      <div className="panel-header">
        <h2>Pipeline health &amp; data quality</h2>
      </div>
      {loading && <p className="empty">Loading...</p>}
      {!loading && data && (
        <>
          <p className="trend-subtitle">
            Not about the threats. This is about whether the system itself is working: is data arriving fast, is
            it clean. Measured only on rows that actually flowed through the real Kafka → Spark → Postgres
            pipeline. The animated map/feed on the Live page is a separate visual layer that never writes to
            this database, so it can't pad or fake these numbers either way.
          </p>

          <div className="provenance-row">
            <div className="provenance-tile">
              <span className="provenance-value">
                {data.latency_p50_seconds != null ? `${Math.round(data.latency_p50_seconds)}s` : "—"}
              </span>
              <span className="provenance-label">median latency</span>
            </div>
            <div className="provenance-tile">
              <span className="provenance-value">
                {data.latency_p95_seconds != null ? `${Math.round(data.latency_p95_seconds)}s` : "—"}
              </span>
              <span className="provenance-label">p95, {(data.latency_sample_size ?? 0).toLocaleString()} rows measured</span>
            </div>
          </div>
          <p className="exhibit-footnote">
            Time between an event happening and landing in the database. Writes happen in short batches every
            few minutes, not one row at a time. Minutes, not milliseconds, is the expected shape of this number.
          </p>

          <div className="health-stats">
            <div className="health-stat">
              <span className="health-stat-value">{data.throughput_per_min ?? "—"}</span>
              <span className="health-stat-label">events/min (last 10min)</span>
            </div>
            <div className="health-stat">
              <span className="health-stat-value">{data.pct_valid_geo ?? "—"}%</span>
              <span className="health-stat-label">records with valid geolocation</span>
            </div>
            <div className="health-stat">
              <span className="health-stat-value">{data.by_source?.length ?? 0}</span>
              <span className="health-stat-label">
                data source{data.by_source?.length === 1 ? "" : "s"}
                {data.by_source?.length ? ` (${data.by_source.map((s) => s.source).join(", ")})` : ""}
              </span>
            </div>
          </div>

          <details className="lookup-details tech-detail-toggle" style={{ marginTop: 10 }}>
            <summary>Technical detail: recent batches, data quality checks</summary>
            <div style={{ marginTop: 10 }}>
              <p className="lookup-subheading">Recent batches</p>
              <div className="batch-list">
                {(data.recent_batches ?? []).slice(0, 6).map((b, i) => (
                  <div key={i} className="batch-row">
                    <span className="mono batch-time">{formatTimestamp(b.loaded_at)}</span>
                    <div className="bar-track">
                      <div className="bar-fill" style={{ width: `${(b.count / maxBatch) * 100}%` }} />
                    </div>
                    <span className="batch-count">{b.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
              {data.quality_checks?.length > 0 && (
                <div className="known-issues">
                  <p className="lookup-subheading">Data quality checks (computed live, not hardcoded)</p>
                  {data.quality_checks.map((c, i) => (
                    <p key={i} className={`quality-check-row quality-${c.status}`}>
                      {STATUS_ICON[c.status]} <strong>{c.name}</strong>
                      {c.status !== "pass" && ` (${c.failed.toLocaleString()}/${c.total.toLocaleString()}, ${c.pct}%)`}
                      <span className="quality-check-desc"> {c.description}</span>
                    </p>
                  ))}
                </div>
              )}
            </div>
          </details>
        </>
      )}
    </div>
  );
}

function StreamingPerformancePanel() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/api/pipeline-metrics`)
      .then((r) => r.json())
      .then((d) => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const maxRows = Math.max(1, ...(data?.recent_batches ?? []).map((b) => b.rows));

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Streaming performance</h2>
      </div>
      {loading && <p className="empty">Loading...</p>}
      {!loading && (!data || data.sample_size === 0) && (
        <p className="empty">
          No micro-batches recorded yet. The Spark job triggers every {data?.trigger_interval ?? "5 minutes"},
          check back shortly.
        </p>
      )}
      {!loading && data && data.sample_size > 0 && (
        <>
          <div className="streaming-perf-stats">
            <div className="health-stat hint" data-tip="Time psycopg2's execute_values took to write each micro-batch to Postgres, timed directly around the call">
              <span className="health-stat-value">{data.write_duration_p50_ms}ms</span>
              <span className="health-stat-label">median write duration (p95 {data.write_duration_p95_ms}ms)</span>
            </div>
            <div className="health-stat">
              <span className="health-stat-value">{data.sample_size}</span>
              <span className="health-stat-label">micro-batches recorded</span>
            </div>
            <div className="health-stat hint" data-tip="Spark Structured Streaming's configured trigger(processingTime=...) interval">
              <span className="health-stat-value">{data.trigger_interval}</span>
              <span className="health-stat-label">trigger interval</span>
            </div>
          </div>
          <p className="lookup-subheading">Recent micro-batches</p>
          <div className="batch-list">
            {data.recent_batches.slice(0, 6).map((b, i) => (
              <div key={i} className="batch-row">
                <span className="mono batch-time">{formatTimestamp(b.recorded_at)}</span>
                <div className="bar-track">
                  <div className="bar-fill" style={{ width: `${(b.rows / maxRows) * 100}%` }} />
                </div>
                <span className="batch-count batch-count-wide">
                  {b.rows.toLocaleString()} rows · {b.write_duration_ms}ms
                  {b.rows_per_sec ? ` · ${b.rows_per_sec.toLocaleString()}/s` : ""}
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

const HISTORY_PAGE_SIZE = 25;

function HistoryPage({ onIpClick }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [country, setCountry] = useState("");
  const [sort, setSort] = useState("loaded_at");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams({ page, page_size: HISTORY_PAGE_SIZE, sort });
    if (country) params.set("country", country);
    fetch(`${API_BASE}/api/history?${params}`)
      .then((r) => r.json())
      .then((data) => {
        setItems(data.items || []);
        setTotal(data.total || 0);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [page, country, sort]);

  const totalPages = Math.max(1, Math.ceil(total / HISTORY_PAGE_SIZE));

  return (
    <div className="panel history-panel">
      <div className="panel-header">
        <h2>History explorer: {total.toLocaleString()} records</h2>
        <div className="mode-toggle">
          <button className={sort === "loaded_at" ? "active" : ""} onClick={() => { setSort("loaded_at"); setPage(1); }}>
            newest ingested
          </button>
          <button className={sort === "reported_at" ? "active" : ""} onClick={() => { setSort("reported_at"); setPage(1); }}>
            newest reported
          </button>
          <button className={sort === "score" ? "active" : ""} onClick={() => { setSort("score"); setPage(1); }}>
            highest score
          </button>
        </div>
        <input
          className="search-input history-filter"
          placeholder="Filter by country code (e.g. US)"
          value={country}
          onChange={(e) => { setCountry(e.target.value.toUpperCase().slice(0, 2)); setPage(1); }}
        />
      </div>
      <div className="history-table-wrapper">
        <table className="history-table">
          <thead>
            <tr>
              <th>IP</th>
              <th>Country</th>
              <th>Risk</th>
              <th>Score</th>
              <th>Last reported</th>
              <th>Ingested</th>
            </tr>
          </thead>
          <tbody>
            {items.map((it, i) => (
              <tr key={i} onClick={() => onIpClick(it.ip)}>
                <td className="mono">{it.ip}</td>
                <td><CountryBadge code={it.country_code} /></td>
                <td>
                  <span className="feed-dot" style={{ background: riskColor(it.risk_level) }} /> {it.risk_level}
                </td>
                <td>{it.abuse_confidence_score}</td>
                <td className="mono">{formatTimestamp(it.last_reported_at)}</td>
                <td className="mono">{formatTimestamp(it.loaded_at)}</td>
              </tr>
            ))}
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={6} className="empty">No records match this filter.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="history-pagination">
        <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>‹ prev</button>
        <span>page {page} / {totalPages}</span>
        <button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>next ›</button>
      </div>
    </div>
  );
}

function formatTimestamp(raw) {
  if (!raw) return "—";
  const iso = String(raw);
  const hasTz = /[Zz]|[+-]\d{2}:?\d{2}$/.test(iso);
  const d = new Date(iso.replace(" ", "T") + (hasTz ? "" : "Z"));
  if (Number.isNaN(d.getTime())) return "—";
  const diffSec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}min ago`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}h ago`;
  const diffDay = Math.floor(diffHour / 24);
  if (diffDay < 7) return `${diffDay}d ago`;
  return d.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });
}

const PRIORITY_ORDER = { high: 0, medium: 1, low: 2 };
const PRIORITY_LABEL = { high: "● Act now", medium: "◐ Worth doing", low: "○ Nice to have" };

function PostureArc({ pct, label, tone }) {
  const [animated, setAnimated] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setAnimated(pct), 120);
    return () => clearTimeout(t);
  }, [pct]);

  const r = 90;
  const cx = 110;
  const cy = 108;
  const pathLen = Math.PI * r;
  const offset = pathLen * (1 - Math.min(100, Math.max(0, animated)) / 100);
  const path = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`;

  return (
    <div className="posture-arc">
      <svg viewBox="0 0 220 118" className="posture-arc-svg">
        <path d={path} className="posture-arc-track" />
        <path
          d={path}
          className={`posture-arc-fill posture-arc-${tone}`}
          style={{ strokeDasharray: pathLen, strokeDashoffset: offset }}
        />
      </svg>
      <div className="posture-arc-center">
        <span className="posture-arc-value">{pct}%</span>
        <span className="posture-arc-label">{label}</span>
      </div>
    </div>
  );
}

function IntelligenceBriefing({ onJumpToExhibit }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshedAt, setRefreshedAt] = useState(null);
  const [, forceTick] = useState(0);

  function loadBriefing() {
    setLoading((prev) => (data ? prev : true));
    fetch(`${API_BASE}/api/briefing`)
      .then((r) => r.json())
      .then((d) => { setData(d); setLoading(false); setRefreshedAt(Date.now()); })
      .catch(() => setLoading(false));
  }

  useEffect(() => {
    loadBriefing();
    const interval = setInterval(loadBriefing, 300000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const tick = setInterval(() => forceTick((n) => n + 1), 5000);
    return () => clearInterval(tick);
  }, []);

  const recommendations = [...(data?.recommendations ?? [])].sort(
    (a, b) => (PRIORITY_ORDER[a.priority] ?? 9) - (PRIORITY_ORDER[b.priority] ?? 9)
  );

  return (
    <div className="intel-page">
      <div className="intel-letterhead">
        <span className="evidence-index-eyebrow">Intelligence briefing</span>
        <span className="briefing-refresh">
          {refreshedAt ? `analyzed ${Math.max(0, Math.round((Date.now() - refreshedAt) / 1000))}s ago` : ""}
          <button className="briefing-refresh-btn" onClick={loadBriefing} title="Re-analyze now">↻</button>
        </span>
      </div>
      {loading && <p className="empty">Analyzing pipeline data...</p>}
      {!loading && data && (
        <div className="intel-body">
          {recommendations.length > 0 && (() => {
            const urgent = recommendations.filter((r) => r.priority === "high").length;
            const urgencyPct = Math.round((urgent / recommendations.length) * 100);
            const tone = urgencyPct >= 50 ? "red" : urgencyPct >= 25 ? "amber" : "green";
            return (
              <div className="intel-cover">
                <PostureArc pct={urgencyPct} label="need action now" tone={tone} />
                <h1 className="intel-cover-title">What to do next</h1>
                <div className="intel-posture-stat-row">
                  <span className="intel-posture-value">{urgent}</span>
                  <span className="intel-posture-label">urgent, of {recommendations.length} findings</span>
                </div>
              </div>
            );
          })()}

          {recommendations.length > 0 && (
            <>
              <div className="intel-section-label">
                <span>Findings</span>
                <span className="intel-section-label-rule" />
                <span>ranked by urgency</span>
              </div>
              <div className="findings">
              {recommendations.map((r, i) => (
                <div key={i} className={`finding finding-${r.priority}`}>
                  <span className="finding-num">{String(i + 1).padStart(2, "0")}</span>
                  <div className="finding-body">
                    <div className="finding-top">
                      <span className="finding-priority">{PRIORITY_LABEL[r.priority] ?? r.priority}</span>
                      <p className="finding-action">{r.action}</p>
                    </div>
                    <p className="finding-impact">{r.impact}</p>
                    {r.exhibit_id && (
                      <button className="finding-link" onClick={() => onJumpToExhibit(r.exhibit_id)}>
                        → see evidence
                      </button>
                    )}
                  </div>
                </div>
              ))}
              </div>
            </>
          )}

          {data.limitations?.length > 0 && (
            <details className="lookup-details briefing-limitations-details">
              <summary>Limitations &amp; confidence</summary>
              <div className="briefing-limitations">
                {data.limitations.map((l, i) => (
                  <p key={i} className="briefing-limitation-row">◦ {l}</p>
                ))}
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

function MiniBarChart({ items, accent }) {
  if (items.length === 0) return <p className="empty mini-empty">No data yet.</p>;
  const max = Math.max(1, ...items.map((it) => it.value));
  return (
    <div className="mini-bar-chart">
      {items.map((it, i) => (
        <div key={i} className="mini-bar-row">
          <span className="mini-bar-label">{it.label}</span>
          <div className="mini-bar-track">
            <div className={`mini-bar-fill exhibit-accent-${accent}`} style={{ width: `${(it.value / max) * 100}%` }} />
          </div>
          <span className="mini-bar-value">{it.value.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

const MINI_HEALTH_ICON = { pass: "✓", warn: "⚠", fail: "✗" };

function MiniHealthDots({ latencySeconds, checks, accent }) {
  return (
    <div className="mini-health">
      <div className="mini-health-latency">
        <span className={`mini-health-value exhibit-accent-${accent}`}>
          {latencySeconds != null ? `${Math.round(latencySeconds)}s` : "—"}
        </span>
        <span className="mini-health-label">median latency</span>
      </div>
      <div className="mini-health-dots">
        {checks.length === 0 && <span className="mini-health-empty">—</span>}
        {checks.map((c, i) => (
          <span key={i} className={`mini-health-dot mini-health-${c.status}`} title={c.name}>
            {MINI_HEALTH_ICON[c.status] ?? "?"}
          </span>
        ))}
      </div>
    </div>
  );
}

function MiniProportionBar({ part, total, accent }) {
  const pct = total > 0 ? Math.round((part / total) * 100) : 0;
  return (
    <div className="mini-proportion">
      <div className="mini-proportion-track">
        <div className={`mini-proportion-fill exhibit-accent-${accent}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="mini-proportion-pct">{pct}%</span>
    </div>
  );
}

function MiniAnomalyList({ items, accent }) {
  if (items.length === 0) return <p className="empty mini-empty">No data yet.</p>;
  return (
    <div className={`mini-anomaly-list exhibit-accent-${accent}`}>
      {items.map((a, i) => (
        <div key={i} className="mini-anomaly-row">
          <CountryBadge code={a.country_code} />
          <span className="mini-anomaly-ip mono">{a.ip}</span>
          <span className="mini-anomaly-source">{a.source}</span>
        </div>
      ))}
    </div>
  );
}

function useTrendDelta(key, scale = 1) {
  const [delta, setDelta] = useState(null);
  useEffect(() => {
    fetch(`${API_BASE}/api/trends`)
      .then((r) => r.json())
      .then((d) => {
        const snapshots = d.snapshots ?? [];
        if (snapshots.length < 2) return;
        const values = snapshots.map((s) => (s[key] ?? 0) * scale);
        const diff = values[values.length - 1] - values[0];
        setDelta(Math.abs(diff) < 0.5 ? "stable" : diff > 0 ? "rising" : "falling");
      })
      .catch(() => {});
  }, [key, scale]);
  return delta;
}

function useCountUp(value, duration = 900) {
  const [display, setDisplay] = useState(value ?? 0);
  const prevRef = useRef(value ?? 0);
  useEffect(() => {
    if (value == null) return;
    const start = prevRef.current;
    const end = value;
    if (start === end) return;
    const startTime = performance.now();
    let raf;
    function tick(now) {
      const t = Math.min(1, (now - startTime) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(Math.round(start + (end - start) * eased));
      if (t < 1) raf = requestAnimationFrame(tick);
      else prevRef.current = end;
    }
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value, duration]);
  return display;
}

function DataCard({ ex, onSelect }) {
  return (
    <button className={`data-card data-card-${ex.kind} exhibit-accent-${ex.accent}`} onClick={() => onSelect(ex.id)}>
      {ex.cardBody}
    </button>
  );
}

function DataSection({ title, accent, children }) {
  return (
    <div className="data-section">
      <div className="data-section-label">
        <span className={`data-section-marker exhibit-accent-${accent}`} />
        <span>{title}</span>
        <span className="data-section-label-rule" />
      </div>
      {children}
    </div>
  );
}

function DataDashboard({ summary, exhibits, onSelect, onBrowseHistory }) {
  const total = summary?.total ?? 0;
  const totalDisplay = useCountUp(total);
  const byId = (id) => exhibits.find((ex) => ex.id === id);
  const modelExhibits = [byId("exhibit-ml"), byId("exhibit-anomalies")].filter(Boolean);
  const sourceExhibits = [byId("exhibit-geo"), byId("exhibit-attack-patterns")].filter(Boolean);
  const actionExhibits = [byId("exhibit-corroboration"), byId("exhibit-infrastructure")].filter(Boolean);
  const trustExhibits = [byId("exhibit-pipeline")].filter(Boolean);

  return (
    <div className="data-dashboard">
      <div className="data-dashboard-header">
        <div>
          <span className="evidence-index-eyebrow">Data</span>
          <h1>Pipeline at a glance</h1>
        </div>
        <div className="evidence-index-meta">
          <div className="evidence-meta-item">
            <span className="evidence-meta-value mono">{totalDisplay.toLocaleString()}</span>
            <span className="evidence-meta-label">threats tracked</span>
          </div>
          <div className="evidence-meta-item">
            <span className="evidence-meta-value">{formatTimestamp(summary?.last_loaded_at)}</span>
            <span className="evidence-meta-label">last updated</span>
          </div>
        </div>
      </div>

      <DataSection title="What the models found" accent="indigo">
        <div className="hero-grid">
          {modelExhibits.map((ex) => <DataCard key={ex.id} ex={ex} onSelect={onSelect} />)}
        </div>
      </DataSection>

      <DataSection title="Where it's coming from" accent="blue">
        <div className="evidence-grid evidence-grid-2col">
          {sourceExhibits.map((ex) => <DataCard key={ex.id} ex={ex} onSelect={onSelect} />)}
        </div>
      </DataSection>

      <DataSection title="What to block first" accent="violet">
        <div className="evidence-grid evidence-grid-2col">
          {actionExhibits.map((ex) => <DataCard key={ex.id} ex={ex} onSelect={onSelect} />)}
        </div>
      </DataSection>

      <DataSection title="Can these numbers be trusted" accent="teal">
        <div className="evidence-grid evidence-grid-1col">
          {trustExhibits.map((ex) => <DataCard key={ex.id} ex={ex} onSelect={onSelect} />)}
        </div>
      </DataSection>

      <button className="evidence-card evidence-card-history" onClick={onBrowseHistory}>
        <span className="evidence-tile-letter">↗</span>
        <div className="evidence-card-history-text">
          <span className="evidence-card-title">Full raw history</span>
          <span className="evidence-card-verdict">
            {total.toLocaleString()} records, every field, searchable and exportable. The receipts behind
            every number on this page.
          </span>
        </div>
      </button>
    </div>
  );
}

const ACCENT_HEX = {
  blue: "#4cc9f0",
  teal: "#2dd4bf",
  violet: "#a78bfa",
  rose: "#f472b6",
  indigo: "#818cf8",
  amber: "#fbbf24",
};

const KIND_EYEBROW = {
  model: "Trained model",
  status: "System status",
  action: "Export-ready",
  distribution: "Distribution",
};

function ExhibitHeader({ title, stat, description, accent, kind }) {
  return (
    <div className="exhibit-header">
      <div className="exhibit-eyebrow-row" style={{ color: ACCENT_HEX[accent] }}>
        <span className="exhibit-marker" />
        <span className="exhibit-eyebrow">{KIND_EYEBROW[kind] ?? "Evidence"}</span>
      </div>
      <div className="exhibit-title-row">
        <h2>{title}</h2>
        {stat && <span className={`exhibit-stat exhibit-accent-${accent}`}>{stat}</span>}
      </div>
      {description && <p className="exhibit-description">{description}</p>}
    </div>
  );
}

function MapLegend() {
  return (
    <div className="map-legend">
      <div className="legend-row">
        <span className="legend-swatch legend-swatch-teal" />
        Historical volume (shade = report count, hover a dot for exact numbers)
      </div>
      <div className="legend-row">
        <span className="legend-swatch legend-swatch-pulse" />
        Live event just received (color = risk level)
      </div>
      <div className="legend-row">
        <span className="legend-swatch legend-swatch-white" />
        Your current search result
      </div>
    </div>
  );
}

function MapPanel({
  baseMarkers,
  pulses,
  highlight,
  expanded,
  onToggle,
  onMarkerClick,
  mapMode,
  setMapMode,
  summary,
  liveCounts,
  selectedCountry,
  onSelectCountry,
}) {
  return (
    <div className={`panel map-panel ${expanded ? "expanded" : ""}`}>
      <div className="panel-header">
        <h2>World map</h2>
        <div className="mode-toggle">
          <button className={mapMode === "all" ? "active" : ""} onClick={() => setMapMode("all")}>
            historical + live
          </button>
          <button className={mapMode === "live" ? "active" : ""} onClick={() => setMapMode("live")}>
            live only
          </button>
        </div>
        <button className="close-btn" onClick={onToggle}>
          {expanded ? "close" : "expand ↗"}
        </button>
      </div>
      <div className="map-wrapper">
        <Globe3D
          baseMarkers={mapMode === "live" ? [] : baseMarkers}
          pulses={pulses}
          highlight={highlight}
          onMarkerClick={onMarkerClick}
        />
        <TopCountriesPanel
          summary={summary}
          liveCounts={liveCounts}
          selectedCountry={selectedCountry}
          onSelect={onSelectCountry}
          compact
        />
        <MapLegend />
      </div>
    </div>
  );
}

function SearchBar({ onSearch, loading }) {
  const [value, setValue] = useState("");
  const inputRef = useRef(null);

  useEffect(() => {
    function onKey(e) {
      if (e.key !== "/") return;
      const tag = document.activeElement?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || document.activeElement?.isContentEditable) return;
      e.preventDefault();
      inputRef.current?.focus();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <form
      className="search-console"
      onSubmit={(e) => {
        e.preventDefault();
        if (value.trim()) onSearch(value.trim());
      }}
    >
      <span className="search-console-prompt">❯</span>
      <input
        ref={inputRef}
        className="search-console-input"
        placeholder="query an IP or CIDR range"
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      {!value && <kbd className="search-console-kbd">/</kbd>}
      <button className="search-console-run" type="submit" disabled={loading}>
        {loading ? "…" : "run"}
      </button>
    </form>
  );
}

function CidrResults({ result, onIpClick }) {
  if (result.error) return <p className="empty">{result.error}</p>;
  const reported = result.reported ?? [];
  const corroborated = reported.filter((r) => (r.source_count ?? 0) >= 2).length;
  return (
    <>
      <p className="modal-ip">{result.network_address}</p>
      <p className="empty">
        netmask {result.netmask} • {result.num_possible_hosts} possible hosts • {reported.length} reported
        {corroborated > 0 && <> • <strong className="cidr-corroborated-count">{corroborated} cross-source confirmed</strong></>}
      </p>
      {reported.length === 0 && <p className="empty">No reported IPs found in this range.</p>}
      {reported
        .sort((a, b) => (b.source_count ?? 0) - (a.source_count ?? 0) || b.abuse_confidence_score - a.abuse_confidence_score)
        .map((r, i) => (
          <button key={i} className="feed-row" onClick={() => onIpClick(r.ip)}>
            <span className="feed-dot" style={{ background: riskColor(
              r.abuse_confidence_score >= 90 ? "critical" : r.abuse_confidence_score >= 70 ? "high"
                : r.abuse_confidence_score >= 40 ? "medium" : "low"
            ) }} />
            <span className="feed-ip">{r.ip}</span>
            {(r.source_count ?? 0) >= 2 && <span className="feed-category">⚡ {r.source_count} sources</span>}
            <span className="feed-country">{r.abuse_confidence_score}/100</span>
            <span className="feed-risk">{r.total_reports} reports</span>
          </button>
        ))}
    </>
  );
}

const CLOUD_PROVIDER_PATTERNS = [
  { label: "AWS", re: /amazon|aws/i },
  { label: "Google Cloud", re: /google/i },
  { label: "Microsoft Azure", re: /microsoft|azure/i },
  { label: "OVH", re: /\bovh\b/i },
  { label: "DigitalOcean", re: /digitalocean/i },
  { label: "Hetzner", re: /hetzner/i },
  { label: "Alibaba Cloud", re: /alibaba/i },
  { label: "Oracle Cloud", re: /\boracle\b/i },
  { label: "Linode/Akamai", re: /linode|akamai/i },
  { label: "Cloudflare", re: /cloudflare/i },
  { label: "Vultr", re: /vultr/i },
  { label: "Tencent Cloud", re: /tencent/i },
];

function cloudProviderFromAsn(asn) {
  if (!asn) return null;
  const match = CLOUD_PROVIDER_PATTERNS.find(({ re }) => re.test(asn));
  return match?.label ?? null;
}

function summarizeVerdict(live) {
  let origin;
  if (live.is_tor) origin = "Exiting a Tor node, so its true origin is deliberately hidden";
  else if (live.geo?.is_proxy_or_vpn) origin = "Relayed through a VPN/proxy, not the attacker's real address";
  else if (live.geo?.is_hosting) origin = "A rented server/datacenter, likely dedicated attack infrastructure";
  else if (live.geo?.is_mobile) origin = "A mobile carrier address, likely a compromised phone or shared CGNAT IP";
  else origin = "A residential/business ISP address, likely a compromised device (e.g. botnet member)";

  const category = live.recent_categories?.[0];
  const activity = category ? ` Last flagged for: ${category.toLowerCase()}.` : "";

  return `${origin}.${activity}`;
}

const RECOMMENDATION_LABEL = {
  block: "Block",
  monitor: "Monitor",
  insufficient_data: "Unclear",
};

const RECOMMENDATION_CLASS = {
  block: "block",
  monitor: "monitor",
  insufficient_data: "insufficient",
};

function riskFactors(row) {
  if (!row) return [];
  const factors = [];
  if (row.source === "abuseipdb" && !row.category) factors.push("AbuseIPDB, no category");
  if (row.abuse_confidence_score >= 90) factors.push("high initial score");
  if (row.risk_level === "critical" || row.risk_level === "high") factors.push(`flagged ${row.risk_level}`);
  return factors.slice(0, 2);
}

function ScoreMeter({ label, pct, accent, tip, caption, compact }) {
  const [animated, setAnimated] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setAnimated(pct), 80);
    return () => clearTimeout(t);
  }, [pct]);
  const fullTip = compact ? [tip, caption].filter(Boolean).join(". ") : tip;
  return (
    <div className={`score-meter exhibit-accent-${accent}${compact ? " score-meter-compact" : ""}`}>
      <div className="score-meter-top">
        <span className={fullTip ? "score-meter-label hint" : "score-meter-label"} data-tip={fullTip}>{label}</span>
        <span className="score-meter-pct">{pct}%</span>
      </div>
      <div className="score-meter-track">
        <div className="score-meter-fill" style={{ width: `${animated}%` }} />
      </div>
      {caption && !compact && <p className="score-meter-caption">{caption}</p>}
    </div>
  );
}

function IpReportContent({ result, onShowDetail }) {
  const live = result?.live_lookup;
  const history = result?.local_history ?? [];
  const recAction = result?.attribution?.recommendation ?? "insufficient_data";
  const recLabel = RECOMMENDATION_LABEL[recAction] ?? RECOMMENDATION_LABEL.insufficient_data;
  const recReason = result?.attribution?.reason ?? "Could not verify a decision for this IP right now.";
  const recClass = RECOMMENDATION_CLASS[recAction] ?? "insufficient";
  const scoredRow = history.find((h) => h.reoffense_probability != null);
  const sources = [...new Set(history.map((h) => h.source).filter(Boolean))];

  const reasons = riskFactors(scoredRow);

  return (
    <div className="ip-report">
      <div className="ip-report-dossier">
        <div className="dossier-top">
        <div className={`verdict-stamp stamp-${recClass}`}>
          <span className="verdict-stamp-word">{recLabel}</span>
        </div>

        <div className="dossier-main">
          <div className="dossier-id-line">
            <span className="modal-ip">{result.ip}</span>
            {live ? (
              <>
                <span className="ip-report-location">
                  {live.geo?.city ? `${live.geo.city}, ` : ""}
                  {countryName(live.country_code)}
                </span>
                {live.is_whitelisted && <span className="meta-flag meta-flag-good">whitelisted</span>}
                {live.is_tor && <span className="meta-flag meta-flag-bad">Tor exit node</span>}
                {live.geo?.is_proxy_or_vpn && <span className="meta-flag meta-flag-bad">VPN/proxy</span>}
                {live.geo?.is_hosting && (
                  <span className="meta-flag">
                    {cloudProviderFromAsn(live.geo?.asn) ? `${cloudProviderFromAsn(live.geo.asn)} (hosting)` : "datacenter/hosting"}
                  </span>
                )}
                {live.geo?.is_mobile && <span className="meta-flag">mobile carrier</span>}
              </>
            ) : (
              result.geo && (
                <>
                  <span className="ip-report-location">
                    {[result.geo.city, result.geo.region].filter(Boolean).join(", ") || "—"}
                  </span>
                  {result.geo.is_proxy_or_vpn && <span className="meta-flag meta-flag-bad">VPN/proxy</span>}
                  {result.geo.is_hosting && (
                    <span className="meta-flag">
                      {cloudProviderFromAsn(result.geo.asn) ? `${cloudProviderFromAsn(result.geo.asn)} (hosting)` : "datacenter/hosting"}
                    </span>
                  )}
                  {result.geo.is_mobile && <span className="meta-flag">mobile carrier</span>}
                </>
              )
            )}
          </div>
          <p className="ip-report-reason">{recReason}</p>
          {live ? (
            <p className="ip-report-summary">{summarizeVerdict(live)}</p>
          ) : (
            <p className="ip-report-summary">
              Live lookup unavailable (AbuseIPDB unreachable or rate-limited, 1000/day free tier). Independent OSINT
              {result.geo ? " below" : ", unavailable either"}, unaffected by that limit.
            </p>
          )}
        </div>
        </div>

        {live && (
          <div className="dossier-metrics">
            <ScoreMeter
              compact
              label="AbuseIPDB confidence"
              pct={live.abuse_confidence_score}
              accent="rose"
              tip="AbuseIPDB's own score (0-100): how confident their community's abuse reports are that this IP is malicious."
            />
            {scoredRow?.reoffense_probability != null && (
              <ScoreMeter
                compact
                label="Reoffense risk"
                pct={Math.round(scoredRow.reoffense_probability * 100)}
                accent="indigo"
                tip="Our own model's predicted chance this IP gets reported again, learned from repeat-offender patterns in this pipeline's history. See Data → Exhibit E."
                caption={reasons.length > 0 ? reasons.join(" · ") : undefined}
              />
            )}
          </div>
        )}
      </div>

      {live ? (
        <>
          {live.recent_categories?.length > 0 && (
            <div className="ip-report-tags">
              {live.recent_categories.map((cat) => {
                const tactic = MITRE_MAP[cat]?.tactic;
                const tacticColor = MITRE_TACTIC_COLOR[tactic];
                return (
                  <button
                    key={cat}
                    className="category-tag"
                    style={tacticColor ? { borderColor: `${tacticColor}66`, color: tacticColor } : undefined}
                    onClick={() => onShowDetail(cat)}
                  >
                    {tacticColor && <span className="category-tag-dot" style={{ background: tacticColor }} />}
                    {cat}
                  </button>
                );
              })}
            </div>
          )}

          <details className="lookup-details">
            <summary>More details</summary>
            <div className="lookup-grid">
              <div className="hint" data-tip="Internet Service Provider that owns this IP block">
                <span className="lookup-key">ISP</span>{live.isp || "—"}
              </div>
              <div className="hint" data-tip="Domain name associated with this IP's registration">
                <span className="lookup-key">Domain</span>{live.domain || "—"}
              </div>
              <div className="hint" data-tip="How the IP block is registered">
                <span className="lookup-key">Usage type</span>{live.usage_type || "—"}
              </div>
              <div className="hint" data-tip="Autonomous System Number: the network that routes this IP">
                <span className="lookup-key">AS number</span>{live.geo?.asn || "—"}
              </div>
              <div className="hint" data-tip="How many times AbuseIPDB users have reported this exact IP">
                <span className="lookup-key">Total reports</span>{live.total_reports}
              </div>
              <div className="hint" data-tip="More distinct reporters means stronger corroboration">
                <span className="lookup-key">Distinct reporters</span>{live.num_distinct_users ?? "—"}
              </div>
              <div className="hint" data-tip="Local timezone at this IP's geolocated position">
                <span className="lookup-key">Timezone</span>{live.geo?.timezone || "—"}
              </div>
            </div>
            {live.hostnames?.length > 0 && (
              <div className="lookup-row hint" data-tip="Hostname(s) this IP resolves back to">
                <span className="lookup-key">Reverse DNS</span>
                {live.hostnames.join(", ")}
              </div>
            )}
            <p className="disclaimer">ISP/usage type reflect registration, not necessarily the device (CGNAT is common).</p>
          </details>
        </>
      ) : (
        result.geo
          ? <p className="ip-report-summary">AS {result.geo.asn || "—"}</p>
          : <p className="empty">No independent geolocation data available either.</p>
      )}

      {history.length > 0 && (
        <div className="ip-report-history">
          <p className="ip-report-history-label hint" data-tip="Independent of AbuseIPDB's live answer above: this exact IP's history in our own Kafka→Spark→Postgres pipeline">
            {history.length} sighting{history.length > 1 ? "s" : ""} in our pipeline{sources.length > 0 ? ` (${sources.join(", ")})` : ""}
          </p>
          <table className="ip-report-history-table">
            <tbody>
              {history.slice(0, 3).map((r, i) => (
                <tr key={i}>
                  <td><span className="history-risk-dot" style={{ background: riskColor(r.risk_level) }} />{r.risk_level}</td>
                  <td className="ip-report-history-time">{formatTimestamp(r.last_reported_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function IpLookupPanel({ result, cidrResult, error, loading, onIpClick, onShowDetail }) {
  return (
    <div className="panel">
      <h2>{cidrResult ? "Range lookup" : "IP lookup"}</h2>
      <div className="panel-body panel-body-centered">
        {loading && <p className="empty">Looking up...</p>}
        {!loading && !result && !cidrResult && !error && (
          <div className="lookup-empty">
            <span className="lookup-empty-icon">◎</span>
            <p className="lookup-empty-title">Search any IP or CIDR range</p>
            <p className="lookup-empty-hint">Instant block / monitor recommendation, backed by cross-source evidence and the reoffense model.</p>
          </div>
        )}
        {error && <p className="empty">{error}</p>}
        {cidrResult && <CidrResults result={cidrResult} onIpClick={onIpClick} />}
        {result && <IpReportContent result={result} onShowDetail={onShowDetail} />}
      </div>
    </div>
  );
}

async function fetchIpReport(ip) {
  const [ipRes, attrRes] = await Promise.all([
    fetch(`${API_BASE}/api/ip/${ip}`),
    fetch(`${API_BASE}/api/attribution/${ip}`).catch(() => null),
  ]);
  if (!ipRes.ok) throw new Error("Request failed");
  const data = await ipRes.json();
  const attribution = attrRes && attrRes.ok ? await attrRes.json().catch(() => null) : null;
  return { ...data, attribution };
}

function IpDrawer({ ip, onClose, onShowDetail }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!ip) return;
    setLoading(true);
    setError(null);
    setResult(null);
    fetchIpReport(ip)
      .then((d) => { setResult(d); setLoading(false); })
      .catch(() => { setError("Could not look up this IP right now."); setLoading(false); });
  }, [ip]);

  useEffect(() => {
    if (!ip) return;
    function onKey(e) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [ip, onClose]);

  if (!ip) return null;

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <div className="technique-drawer ip-drawer" onClick={(e) => e.stopPropagation()}>
        <button className="drawer-close" onClick={onClose} aria-label="Close">×</button>
        {loading && <p className="empty">Looking up...</p>}
        {error && <p className="empty">{error}</p>}
        {result && <IpReportContent result={result} onShowDetail={onShowDetail} />}
      </div>
    </div>
  );
}

export default function App() {
  const [summary, setSummary] = useState(null);
  const [pulses, setPulses] = useState([]);
  const [feed, setFeed] = useState([]);
  const [liveCount, setLiveCount] = useState(0);
  const [connected, setConnected] = useState(false);
  const [mapExpanded, setMapExpanded] = useState(false);
  const [selectedCountry, setSelectedCountry] = useState(null);
  const [categoryFilter, setCategoryFilter] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchResult, setSearchResult] = useState(null);
  const [cidrResult, setCidrResult] = useState(null);
  const [searchError, setSearchError] = useState(null);
  const [searchHighlight, setSearchHighlight] = useState(null);
  const [liveCounts, setLiveCounts] = useState({});
  const [mapMode, setMapMode] = useState("all");
  const [page, setPage] = useState("live");
  const [activeTechnique, setActiveTechnique] = useState(null);
  const [ipDrawerTarget, setIpDrawerTarget] = useState(null);
  const [selectedExhibit, setSelectedExhibit] = useState(null);
  const [exhibitReturnPage, setExhibitReturnPage] = useState(null);
  const [, forceTick] = useState(0);
  const pulseId = useRef(0);
  function jumpToExhibit(exhibitId) {
    if (!exhibitId) return;
    setExhibitReturnPage(page);
    setPage("data");
    setSelectedExhibit(exhibitId);
  }
  function closeExhibit() {
    setSelectedExhibit(null);
    if (exhibitReturnPage) {
      setPage(exhibitReturnPage);
      setExhibitReturnPage(null);
    }
  }

  function exportFeedCsv() {
    const rows = [["ip", "country_code", "risk_level", "timestamp"]];
    for (const e of feed) {
      rows.push([e.ip, e.country_code ?? "", e.risk_level ?? "", e.timestamp ?? new Date(e.id).toISOString()]);
    }
    const csv = rows.map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ghostnet-feed-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  useEffect(() => {
    const interval = setInterval(() => forceTick((n) => n + 1), 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    function loadSummary() {
      fetch(`${API_BASE}/api/summary`)
        .then((r) => r.json())
        .then(setSummary)
        .catch(() => {});
    }
    loadSummary();
    const interval = setInterval(loadSummary, 300000);
    return () => clearInterval(interval);
  }, []);

  const [hubExtras, setHubExtras] = useState({
    clusterCount: null,
    topSubnets: [],
    modelRocAuc: null,
    positiveRate: null,
    precision: null,
    recall: null,
    latencyP50: null,
    qualityChecks: [],
    topAnomalies: [],
    anomalyRate: null,
    contamination: null,
    observedAnomalyRate: null,
  });
  useEffect(() => {
    function loadHubExtras() {
      Promise.all([
        fetch(`${API_BASE}/api/infrastructure-clusters`).then((r) => r.json()).catch(() => null),
        fetch(`${API_BASE}/api/ml/model-info`).then((r) => r.json()).catch(() => null),
        fetch(`${API_BASE}/api/pipeline-health`).then((r) => r.json()).catch(() => null),
        fetch(`${API_BASE}/api/anomalies?limit=3`).then((r) => r.json()).catch(() => null),
        fetch(`${API_BASE}/api/ml/anomaly-info`).then((r) => r.json()).catch(() => null),
      ]).then(([clusters, model, health, anomalies, anomalyInfo]) => {
        const prod = model?.models?.[model?.production_model];
        setHubExtras({
          clusterCount: clusters?.clusters?.length ?? null,
          topSubnets: (clusters?.clusters ?? []).slice(0, 3),
          modelRocAuc: prod?.roc_auc ?? null,
          positiveRate: model?.positive_rate ?? null,
          precision: prod?.precision ?? null,
          recall: prod?.recall ?? null,
          latencyP50: health?.latency_p50_seconds ?? null,
          qualityChecks: health?.quality_checks ?? [],
          topAnomalies: anomalies?.items ?? [],
          anomalyRate: anomalyInfo?.observed_anomaly_rate ?? null,
          contamination: anomalyInfo?.contamination ?? null,
          observedAnomalyRate: anomalyInfo?.observed_anomaly_rate ?? null,
        });
      });
    }
    loadHubExtras();
    const interval = setInterval(loadHubExtras, 300000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    let ws;
    let reconnectTimer;
    let attempt = 0;
    let stopped = false;

    function connect() {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => {
        attempt = 0;
        setConnected(true);
      };
      ws.onclose = () => {
        setConnected(false);
        if (stopped) return;
        const delay = Math.min(1000 * 2 ** attempt, 15000);
        attempt += 1;
        reconnectTimer = setTimeout(connect, delay);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.latitude === undefined || data.longitude === undefined) return;
        const id = pulseId.current++;
        const entry = { ...data, id };
        setPulses((prev) => [...prev.slice(-MAX_PULSES + 1), entry]);
        setFeed((prev) => [entry, ...prev].slice(0, MAX_FEED));
        setLiveCount((c) => c + 1);
        if (data.country_code) {
          setLiveCounts((prev) => ({ ...prev, [data.country_code]: (prev[data.country_code] || 0) + 1 }));
        }
        setTimeout(() => {
          setPulses((prev) => prev.filter((p) => p.id !== id));
        }, PULSE_LIFETIME_MS);
      };
    }

    connect();
    return () => {
      stopped = true;
      clearTimeout(reconnectTimer);
      ws.close();
    };
  }, []);

  const matchesFilters = useCallback(
    (e) => {
      if (selectedCountry && e.country_code !== selectedCountry) return false;
      if (categoryFilter && !(e.categories ?? []).includes(categoryFilter)) return false;
      return true;
    },
    [selectedCountry, categoryFilter]
  );

  const filteredFeed = useMemo(() => feed.filter(matchesFilters), [feed, matchesFilters]);

  const filteredPulses = useMemo(() => pulses.filter(matchesFilters), [pulses, matchesFilters]);

  const seenCategories = useMemo(() => {
    const set = new Set();
    for (const e of feed) {
      for (const c of e.categories ?? []) set.add(c);
    }
    return [...set].sort();
  }, [feed]);

  const baseMarkers = useMemo(() => {
    const countries = summary?.top_countries ?? [];
    return countries
      .filter((c) => COUNTRY_CENTROIDS[c.country])
      .filter((c) => !selectedCountry || c.country === selectedCountry)
      .map((c) => ({ country: c.country, count: c.count, coords: COUNTRY_CENTROIDS[c.country] }));
  }, [summary, selectedCountry]);

  async function handleSearch(query) {
    setSearchLoading(true);
    setSearchError(null);
    setSearchResult(null);
    setCidrResult(null);

    if (query.includes("/")) {
      try {
        const res = await fetch(`${API_BASE}/api/cidr/${encodeURIComponent(query)}`);
        const data = await res.json();
        setCidrResult(data);
        setSearchHighlight(null);
      } catch {
        setSearchError("Could not look up this range right now.");
      } finally {
        setSearchLoading(false);
      }
      return;
    }

    try {
      const data = await fetchIpReport(query);
      setSearchResult(data);
      const geo = data.live_lookup?.geo;
      const cc = data.live_lookup?.country_code || data.local_history[0]?.country_code;
      if (geo?.lat != null && geo?.lon != null) {
        setSearchHighlight({ coords: [geo.lon, geo.lat], label: `${query} (${geo.city || cc})` });
      } else if (cc && COUNTRY_CENTROIDS[cc]) {
        setSearchHighlight({ coords: COUNTRY_CENTROIDS[cc], label: `${query} (${cc})` });
      } else {
        setSearchHighlight(null);
      }
    } catch {
      setSearchError("Could not look up this IP right now.");
    } finally {
      setSearchLoading(false);
    }
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1 className={`brand-logo ${connected ? "" : "brand-offline"}`} onClick={() => setPage("live")}>GhostNet</h1>
          {!connected && <span className="brand-offline-badge">offline</span>}
          <SearchBar onSearch={handleSearch} loading={searchLoading} />
        </div>
        <nav className="page-nav">
          <button className={page === "analytics" ? "active" : ""} onClick={() => setPage("analytics")}>
            Intelligence
          </button>
          <button className={page === "live" ? "active" : ""} onClick={() => setPage("live")}>
            Live
          </button>
          <button className={page === "data" ? "active" : ""} onClick={() => setPage("data")}>
            Data
          </button>
        </nav>
        <div className="topbar-right">
          {selectedCountry && (
            <div className="filters">
              <button className="filter-chip" onClick={() => setSelectedCountry(null)}>
                {selectedCountry} ×
              </button>
            </div>
          )}
          <div className="counters">
            <button className="counter counter-clickable" onClick={() => setPage("history")} title="Browse the underlying records">
              <span className="counter-value">{summary?.total ?? "-"}</span>
              <span className="counter-label">total history ↗</span>
            </button>
            <div className="counter">
              <span className="counter-value">{liveCount}</span>
              <span className="counter-label">received live</span>
            </div>
          </div>
        </div>
      </header>

      {!mapExpanded && page === "live" && (
        <div className="main-content">
          <div className="grid">
            <div className="col left">
              <LiveFeedPanel
                events={filteredFeed}
                onIpClick={handleSearch}
                onExport={exportFeedCsv}
                categories={seenCategories}
                categoryFilter={categoryFilter}
                onToggleCategory={setCategoryFilter}
                onShowDetail={setActiveTechnique}
              />
              <AnomalyPanel onIpClick={handleSearch} />
            </div>
            <div className="col right">
              <MapPanel
                baseMarkers={baseMarkers}
                pulses={filteredPulses}
                highlight={searchHighlight}
                expanded={false}
                onToggle={() => setMapExpanded(true)}
                onMarkerClick={handleSearch}
                mapMode={mapMode}
                setMapMode={setMapMode}
                summary={summary}
                liveCounts={liveCounts}
                selectedCountry={selectedCountry}
                onSelectCountry={setSelectedCountry}
              />
              <IpLookupPanel
                result={searchResult}
                cidrResult={cidrResult}
                error={searchError}
                loading={searchLoading}
                onIpClick={handleSearch}
                onShowDetail={setActiveTechnique}
              />
            </div>
          </div>
        </div>
      )}

      {page === "analytics" && (
        <div className="main-content analytics-page intelligence-only">
          <IntelligenceBriefing onJumpToExhibit={jumpToExhibit} />
        </div>
      )}

      {page === "data" && (() => {
        const geoTop = summary?.top_countries?.[0];
        const geoTotal = summary?.total ?? 0;

        const catEntries = Object.entries(summary?.by_category ?? {}).sort((a, b) => b[1] - a[1]);
        const catTotal = catEntries.reduce((s, [, v]) => s + v, 0);

        const pipelineFailing = hubExtras.qualityChecks.filter((c) => c.status !== "pass").length;

        const crossSourcePct = summary?.repeat_offenders
          ? Math.round(((summary.cross_source_corroborated ?? 0) / summary.repeat_offenders) * 100)
          : null;

        const exhibits = [
          {
            id: "exhibit-geo",
            title: "Geography",
            accent: "blue",
            kind: "distribution",
            stat: geoTop ? <><CountryBadge code={geoTop.country} /> {Math.round((geoTop.count / geoTotal) * 100)}% of all traffic</> : null,
            cardBody: (
              <>
                <span className="data-card-eyebrow">Where it's from</span>
                <ConcentrationDonut topCountries={summary?.top_countries ?? []} total={geoTotal} />
              </>
            ),
            description: "Where attacks come from, and how concentrated that is. A handful of countries account for most of it.",
            render: () => (
              <GeographyPanel
                summary={summary}
                liveCounts={liveCounts}
                selectedCountry={selectedCountry}
                onSelect={setSelectedCountry}
              />
            ),
          },
          {
            id: "exhibit-attack-patterns",
            title: "Attack patterns",
            accent: "violet",
            kind: "distribution",
            stat: catEntries.length > 0 ? `${catEntries[0][0]} leads` : null,
            cardBody: (
              <>
                <span className="data-card-eyebrow">What kind of attack</span>
                <AttackPatternDonut
                  categories={catEntries.map(([category, count]) => ({
                    category,
                    pct_of_categorized: catTotal ? (count / catTotal) * 100 : 0,
                  }))}
                />
                <div className="mini-legend-row">
                  {catEntries.map(([category], i) => (
                    <span key={category} className="mini-legend-item">
                      <span className="mini-legend-swatch" style={{ background: ATTACK_PATTERN_COLORS[i % ATTACK_PATTERN_COLORS.length] }} />
                      {category}
                    </span>
                  ))}
                </div>
              </>
            ),
            description: "What kind of attack this actually is, and whether that differs by where it's from.",
            render: () => <AttackPatternsPanel />,
          },
          {
            id: "exhibit-corroboration",
            title: "Cross-source corroboration",
            accent: "violet",
            kind: "action",
            stat: `${(summary?.cross_source_corroborated ?? 0).toLocaleString()} of ${(summary?.repeat_offenders ?? 0).toLocaleString()} confirmed independently`,
            cardBody: (
              <>
                <div className="data-card-action-top">
                  <span className="data-card-eyebrow">Ready to block</span>
                  <span className="data-card-action-tag">⇩ export-ready</span>
                </div>
                <div className="data-card-headline">
                  <span className="data-card-headline-value">{(summary?.cross_source_corroborated ?? 0).toLocaleString()}</span>
                  <span className="data-card-headline-unit">IPs confirmed by 2+ sources</span>
                </div>
                {crossSourcePct != null && (
                  <MiniProportionBar accent="violet" part={summary?.cross_source_corroborated ?? 0} total={summary?.repeat_offenders ?? 0} />
                )}
              </>
            ),
            description: "IPs that more than one independent source flagged on their own. Agreement like that makes them the safest ones to block.",
            render: () => <RepeatOffendersPanel onIpClick={setIpDrawerTarget} />,
          },
          {
            id: "exhibit-infrastructure",
            title: "Shared infrastructure",
            accent: "rose",
            kind: "action",
            stat: hubExtras.clusterCount != null ? `${hubExtras.clusterCount} subnets flagged` : null,
            cardBody: (
              <>
                <div className="data-card-action-top">
                  <span className="data-card-eyebrow">Ready to block</span>
                  <span className="data-card-action-tag">⇩ export-ready</span>
                </div>
                <div className="data-card-headline">
                  <span className="data-card-headline-value">{hubExtras.clusterCount ?? "—"}</span>
                  <span className="data-card-headline-unit">subnets to block by range, not by IP</span>
                </div>
                <MiniBarChart
                  accent="rose"
                  items={hubExtras.topSubnets.map((c) => ({
                    label: <span className="mono">{c.subnet}</span>,
                    value: c.ip_count,
                  }))}
                />
              </>
            ),
            description: "A single IP is easy for an attacker to throw away. The block of 256 addresses it's rented from usually isn't, so blocking the whole block stops the next one too.",
            render: () => <InfrastructureClustersPanel onIpClick={setIpDrawerTarget} />,
          },
          {
            id: "exhibit-pipeline",
            title: "Pipeline integrity",
            accent: "teal",
            kind: "status",
            stat: hubExtras.latencyP50 != null ? `${Math.round(hubExtras.latencyP50)}s median latency, live-measured` : null,
            cardBody: (
              <>
                <span className="data-card-eyebrow">System health</span>
                <span className={`data-card-status-badge ${pipelineFailing > 0 ? "data-card-status-warn" : ""}`}>
                  {pipelineFailing > 0 ? `${pipelineFailing} issue${pipelineFailing > 1 ? "s" : ""}` : "Healthy"}
                </span>
                <MiniHealthDots accent="teal" latencySeconds={hubExtras.latencyP50} checks={hubExtras.qualityChecks} />
              </>
            ),
            description: "Can these numbers actually be trusted, not just a status light.",
            render: () => (
              <div className="exhibit-row">
                <PipelineHealthPanel />
                <StreamingPerformancePanel />
              </div>
            ),
          },
          {
            id: "exhibit-ml",
            title: "Reoffense risk model",
            accent: "indigo",
            kind: "model",
            stat: null,
            cardBody: (
              <>
                <span className="data-card-eyebrow">Trained model</span>
                {hubExtras.precision != null && hubExtras.recall != null && (
                  <div className="model-hero-freq-row">
                    <FrequencyPictogram
                      accent="blue"
                      count={Math.round(hubExtras.precision * 10)}
                      caption={<>About <strong>{Math.round(hubExtras.precision * 10)}/10</strong> flagged IPs actually reoffend.</>}
                    />
                    <FrequencyPictogram
                      accent="indigo"
                      count={Math.round(hubExtras.recall * 10)}
                      caption={<>Catches about <strong>{Math.round(hubExtras.recall * 10)}/10</strong> that do.</>}
                    />
                  </div>
                )}
                {hubExtras.positiveRate != null && (
                  <p className="data-card-caption">{Math.round(hubExtras.positiveRate * 100)}% of first-time IPs reoffend, so flag on sight.</p>
                )}
              </>
            ),
            description: "Predicts which brand-new attacker IPs will strike again, so they can be blocked before the second attack instead of just logged after it.",
            render: () => <ModelPerformancePanel />,
          },
          {
            id: "exhibit-anomalies",
            title: "Anomaly detection",
            accent: "amber",
            kind: "model",
            stat: hubExtras.anomalyRate != null ? `${(hubExtras.anomalyRate * 100).toFixed(1)}% flagged as unusual` : null,
            cardBody: (
              <>
                <span className="data-card-eyebrow">Trained model</span>
                {hubExtras.contamination != null && hubExtras.observedAnomalyRate != null && (
                  <div className="freq-compare exhibit-accent-amber">
                    <div className="freq-compare-item">
                      <span className="freq-compare-value">{(hubExtras.contamination * 100).toFixed(0)}%</span>
                      <span className="freq-compare-label">expected unusual</span>
                    </div>
                    <span
                      className={`freq-compare-sign ${Math.abs(hubExtras.contamination - hubExtras.observedAnomalyRate) < 0.01 ? "freq-compare-sign-match" : "freq-compare-sign-off"}`}
                    >
                      {Math.abs(hubExtras.contamination - hubExtras.observedAnomalyRate) < 0.01 ? "≈" : "≠"}
                    </span>
                    <div className="freq-compare-item">
                      <span className="freq-compare-value">{(hubExtras.observedAnomalyRate * 100).toFixed(1)}%</span>
                      <span className="freq-compare-label">actually unusual</span>
                    </div>
                  </div>
                )}
                <MiniAnomalyList accent="amber" items={hubExtras.topAnomalies} />
                <p className="data-card-caption">
                  {hubExtras.topAnomalies.length > 0
                    ? `${hubExtras.topAnomalies.length} unusual events flagged right now.`
                    : "No unusual events flagged right now."}
                </p>
              </>
            ),
            description: "Learns what normal traffic looks like, then flags whatever doesn't fit. That catches attacks nobody's written a rule for yet.",
            render: () => <AnomalyModelPanel onIpClick={setIpDrawerTarget} />,
          },
        ];
        const active = exhibits.find((ex) => ex.id === selectedExhibit);

        return (
          <div className="main-content data-page">
            {!active && (
              <DataDashboard
                summary={summary}
                exhibits={exhibits}
                onSelect={setSelectedExhibit}
                onBrowseHistory={() => setPage("history")}
              />
            )}
            {active && (
              <div className="evidence-focused">
                <button className="evidence-back" onClick={closeExhibit}>
                  {exhibitReturnPage ? "← Back to Intelligence" : "← All evidence"}
                </button>
                <section className={`exhibit exhibit-glow-${active.accent}`}>
                  <ExhibitHeader
                    title={active.title}
                    accent={active.accent}
                    kind={active.kind}
                    stat={active.stat}
                    description={active.description}
                  />
                  {active.render()}
                </section>
              </div>
            )}
          </div>
        );
      })()}

      {page === "history" && (
        <div className="main-content history-page">
          <HistoryPage onIpClick={setIpDrawerTarget} />
        </div>
      )}

      {mapExpanded && (
        <MapPanel
          baseMarkers={baseMarkers}
          pulses={filteredPulses}
          highlight={searchHighlight}
          expanded={true}
          onToggle={() => setMapExpanded(false)}
          onMarkerClick={handleSearch}
          mapMode={mapMode}
          setMapMode={setMapMode}
          summary={summary}
          liveCounts={liveCounts}
          selectedCountry={selectedCountry}
          onSelectCountry={setSelectedCountry}
        />
      )}

      <IpDrawer
        ip={ipDrawerTarget}
        onClose={() => setIpDrawerTarget(null)}
        onShowDetail={setActiveTechnique}
      />
      <TechniqueDrawer
        category={activeTechnique}
        byCategory={summary?.by_category}
        onClose={() => setActiveTechnique(null)}
      />
    </div>
  );
}
