/**
 * ScamCheck On-Device Detection Engine (Zero-Server, Zero-API-Cost)
 * Analyzes SMS, WhatsApp, emails, job offers, and URLs locally.
 */

const TOP_BRANDS = [
  "paypal", "amazon", "apple", "microsoft", "google", "netflix", "chase",
  "bankofamerica", "wellsfargo", "citibank", "usps", "fedex", "ups", "dhl",
  "irs", "venmo", "cashapp", "zelle", "coinbase", "binance", "instagram",
  "facebook", "whatsapp", "linkedin", "icloud", "adobe", "stripe", "shopify",
  "walmart", "target", "costco", "tmobile", "verizon", "att", "americanexpress"
];

const SHADY_TLDS = new Set([
  "xyz", "top", "click", "loan", "tk", "ml", "ga", "cf", "gq", "buzz",
  "work", "surf", "rest", "cam", "icu", "vip", "club", "win", "bid", "cyou"
]);

const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "ow.ly", "cutt.ly",
  "shorturl.at", "tiny.cc", "rebrand.ly", "buff.ly"
]);

const FREE_EMAIL_DOMAINS = new Set([
  "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "proton.me", "aol.com", "icloud.com"
]);

function normalizeHomoglyphs(str) {
  return str
    .toLowerCase()
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w");
}

export function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

export function extractUrls(text) {
  const regex = /(?:https?:\/\/|www\.)[^\s<>"{}|\\^`[\]]+|\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+(?:\/[^\s<>"{}|\\^`[\]]*)?/gi;
  const matches = text.match(regex) || [];
  return [...new Set(matches.map((u) => u.replace(/[.,;:!?)]+$/, "")))];
}

function inspectUrl(rawUrl) {
  const signals = [];
  let normalized = rawUrl.trim();
  if (!/^https?:\/\//i.test(normalized)) {
    normalized = "https://" + normalized;
  }
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    return signals;
  }

  const host = parsed.hostname.toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    signals.push({
      category: "URL & Domain",
      severity: "high",
      points: 35,
      title: `Raw IP address link (${host})`,
      detail: "Legitimate banks, couriers, and companies never send bare IP-address links."
    });
    return signals;
  }

  if (rawUrl.includes("@")) {
    signals.push({
      category: "URL & Domain",
      severity: "high",
      points: 35,
      title: "Deceptive '@' redirect in URL",
      detail: "Attackers put a trusted brand before '@' to hide the real destination domain."
    });
  }

  if (host.includes("xn--")) {
    signals.push({
      category: "URL & Domain",
      severity: "high",
      points: 30,
      title: `Punycode lookalike domain (${host})`,
      detail: "Uses non-ASCII lookalike characters to spoof a real brand."
    });
  }

  if (URL_SHORTENERS.has(host)) {
    signals.push({
      category: "URL & Domain",
      severity: "medium",
      points: 20,
      title: `Hidden destination via shortener (${host})`,
      detail: "Shortened links hide the true website; never click them for banking or account alerts."
    });
  }

  const parts = host.split(".");
  const tld = parts[parts.length - 1];
  if (SHADY_TLDS.has(tld)) {
    signals.push({
      category: "URL & Domain",
      severity: "medium",
      points: 20,
      title: `High-risk domain extension (.${tld})`,
      detail: `The .${tld} extension is heavily abused in disposable phishing campaigns.`
    });
  }

  if (parts.length >= 4) {
    signals.push({
      category: "URL & Domain",
      severity: "medium",
      points: 15,
      title: `Excessive subdomains (${host})`,
      detail: "Scammers stack brand names as subdomains (e.g., paypal.verify-login.site)."
    });
  }

  // Brand typosquatting & brand-in-hyphenated-domain check
  const sld = parts.length >= 2 ? parts[parts.length - 2] : host;
  const sldClean = normalizeHomoglyphs(sld);
  for (const brand of TOP_BRANDS) {
    if (sld === brand && !SHADY_TLDS.has(tld) && parts.length <= 3) {
      continue; // Exact official domain match (e.g. paypal.com)
    }
    if (host.includes(brand) && sld !== brand) {
      signals.push({
        category: "Brand Spoofing",
        severity: "high",
        points: 35,
        title: `Impersonates "${brand}" on unofficial domain (${host})`,
        detail: `Contains "${brand}" inside a lookalike domain rather than the official ${brand}.com.`
      });
      break;
    }
    const dist = levenshtein(sldClean, brand);
    if (dist > 0 && dist <= 2 && Math.abs(sldClean.length - brand.length) <= 2) {
      signals.push({
        category: "Brand Spoofing",
        severity: "high",
        points: 40,
        title: `Typosquatted brand domain (${host} vs ${brand})`,
        detail: `"${sld}" is a near-identical spelling trap designed to mimic ${brand}.`
      });
      break;
    }
  }

  return signals;
}

const PATTERN_RULES = [
  {
    id: "gift_card_crypto",
    category: "Payment Trap",
    severity: "high",
    points: 45,
    regex: /\b(gift\s*card|apple\s*card|google\s*play\s*card|steam\s*card|bitcoin|usdt|crypto\s*wallet|wire\s*transfer|western\s*union)\b/i,
    title: "Untraceable payment method requested",
    detail: "Legitimate employers, banks, and government agencies never ask for gift cards, crypto, or wire transfers."
  },
  {
    id: "otp_pin_trap",
    category: "Credential Theft",
    severity: "high",
    points: 40,
    regex: /\b((send|share|enter|read\s+back)\s+(me\s+)?(the\s+|your\s+)?(\d+-digit\s+)?(verification\s+)?(code|otp|pin)(\s+code)?|verify\s+your\s+(otp|pin|ssn|social\s*security))\b/i,
    title: "Asks for OTP, PIN, or SSN",
    detail: "Anyone asking you to read back or enter a 6-digit verification code is trying to hijack your account."
  },
  {
    id: "urgency_fear",
    category: "Urgency & Fear",
    severity: "medium",
    points: 20,
    regex: /\b(within\s+\d+\s*(hours?|hrs?|minutes?|mins?)|immediately|act\s+now|final\s+(notice|warning)|account\s+(will\s+be\s+)?(suspended|locked|closed|terminated)|legal\s+action|arrest\s+warrant|bench\s+warrant)\b/i,
    title: "Artificial urgency or threat language",
    detail: "Scammers create panic so you act before verifying with the real organization."
  },
  {
    id: "secrecy_isolation",
    category: "Manipulation",
    severity: "high",
    points: 25,
    regex: /\b(do\s+not\s+tell\s+anyone|keep\s+this\s+(confidential|secret)|don't\s+hang\s+up|stay\s+on\s+the\s+line)\b/i,
    title: "Secrecy or isolation pressure",
    detail: "Telling you not to talk to family or bank tellers is a classic scam isolation tactic."
  },
  {
    id: "delivery_toll_fee",
    category: "Delivery / Toll Phish",
    severity: "medium",
    points: 25,
    regex: /\b(unpaid\s+toll|redelivery\s+fee|customs\s+fee|package\s+(is\s+)?(held|on\s+hold|pending)|incomplete\s+address|usps|fedex|ups)\b.*\b(pay|fee|click|link|update|confirm)\b/i,
    title: "Fake delivery or unpaid toll fee pattern",
    detail: "Couriers and toll agencies do not text random links demanding small fee payments."
  },
  {
    id: "fake_job_telegram",
    category: "Fake Job Scam",
    severity: "high",
    points: 35,
    regex: /\b(interview\s+(via|on)\s+(telegram|whatsapp|signal)|text\s+only\s+interview|equipment\s+check|mobile\s+deposit\s+check|guaranteed\s+\$?\d+\s*\/?\s*(day|hr|hour)|no\s+experience\s+needed.*\$\d{3,})\b/i,
    title: "Fake recruiter / job offer pattern",
    detail: "Real companies do not interview solely over Telegram/WhatsApp or mail checks for equipment."
  },
  {
    id: "lottery_prize",
    category: "Reward Bait",
    severity: "high",
    points: 30,
    regex: /\b(you('ve|\s+have)?\s+won|unclaimed\s+(prize|funds|inheritance)|selected\s+as\s+(the\s+)?winner|claim\s+your\s+(reward|prize))\b/i,
    title: "Too-good-to-be-true prize or windfall",
    detail: "Unsolicited prize notifications are almost always advance-fee or credential harvesting traps."
  },
  {
    id: "voice_clone_emergency",
    category: "AI Voice-Clone Trap",
    severity: "high",
    points: 35,
    regex: /\b(lost\s+my\s+phone|new\s+number.*(mom|dad|grandma|grandpa)|crashed\s+(my\s+)?car|in\s+jail|bail\s+money|need\s+money\s+(urgently|right\s+now))\b/i,
    title: "Family emergency / AI voice-clone script",
    detail: "Verify immediately using your Family Safe-Word or call their known saved number directly."
  }
];

export function analyzeMessage(inputText) {
  const text = (inputText || "").trim();
  if (!text) {
    return {
      score: 0,
      verdict: "EMPTY",
      label: "Paste a message or link to check",
      signals: [],
      urls: [],
      actions: []
    };
  }

  const signals = [];
  const urls = extractUrls(text);

  for (const url of urls) {
    signals.push(...inspectUrl(url));
  }

  for (const rule of PATTERN_RULES) {
    if (rule.regex.test(text)) {
      signals.push({
        category: rule.category,
        severity: rule.severity,
        points: rule.points,
        title: rule.title,
        detail: rule.detail
      });
    }
  }

  // Check for recruiter claiming big company with free email
  const emailMatches = text.match(/[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g) || [];
  for (const email of emailMatches) {
    const domain = email.split("@")[1].toLowerCase();
    if (FREE_EMAIL_DOMAINS.has(domain) && /\b(hr|recruiter|hiring|offer|payroll|support|security)\b/i.test(text)) {
      signals.push({
        category: "Impersonation",
        severity: "medium",
        points: 20,
        title: `Free webmail (${domain}) used for official/HR message`,
        detail: "Legitimate HR, banks, and support teams email from their official company domain."
      });
      break;
    }
  }

  // Deduplicate by title
  const uniqueSignals = [];
  const seen = new Set();
  for (const s of signals) {
    if (!seen.has(s.title)) {
      seen.add(s.title);
      uniqueSignals.push(s);
    }
  }

  const rawScore = uniqueSignals.reduce((sum, s) => sum + s.points, 0);
  const score = Math.min(100, rawScore);

  let verdict = "SAFE";
  let label = "No Obvious Scam Signals Found";
  let actions = [
    "Still verify unexpected money or login requests through an official app or saved number.",
    "Never share 6-digit OTP codes with anyone."
  ];

  if (score >= 60) {
    verdict = "HIGH_RISK";
    label = "High-Risk Scam Detected";
    actions = [
      "Do NOT click any links, reply, or send money/gift cards.",
      "Block the sender and delete the message.",
      "If it claims to be your bank or family member, call them using your saved contact or Family Safe-Word.",
      "Tap 'Warn Family' below to alert your WhatsApp/family group."
    ];
  } else if (score >= 25) {
    verdict = "SUSPICIOUS";
    label = "Suspicious — Verify Before Acting";
    actions = [
      "Do not click links in the message; open the official app or website manually.",
      "Check the sender's real email domain or phone number carefully.",
      "Ask a trusted friend or family member before sending any personal info."
    ];
  }

  return {
    score,
    verdict,
    label,
    signals: uniqueSignals.sort((a, b) => b.points - a.points),
    urls,
    actions
  };
}
