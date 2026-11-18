/**
 * Offline Rotating Family Safe-Word Generator
 * Protects against AI voice-cloning emergency scams ("Mom, I'm in trouble!").
 * Uses a shared Family Seed + time bucket so all family phones match offline.
 */

const ADJECTIVES = [
  "AMBER", "BRAVE", "CEDAR", "DELTA", "EMBER", "FROST", "GOLDEN", "HARBOR",
  "IRON", "JADE", "KARMA", "LUNAR", "MAPLE", "NOBLE", "OCEAN", "PRISM",
  "QUARTZ", "RIVER", "SILVER", "TIGER", "URBAN", "VELVET", "WILLOW", "ZENITH"
];

const NOUNS = [
  "ANCHOR", "BEACON", "CANYON", "DOLPHIN", "EAGLE", "FALCON", "GLACIER", "HORIZON",
  "ISLAND", "JAGUAR", "KESTREL", "LANTERN", "MEADOW", "NEBULA", "ORCHARD", "PHOENIX",
  "QUIVER", "REDWOOD", "SUMMIT", "THUNDER", "VALLEY", "WALNUT", "YARROW", "ZIRCON"
];

function fnv1a32(str) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

export function generateRandomSeed() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < 12; i++) {
    if (i > 0 && i % 4 === 0) out += "-";
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

export function getTimeBucket(cadence = "weekly", nowMs = Date.now()) {
  const dayIndex = Math.floor(nowMs / 86400000);
  if (cadence === "daily") return `D-${dayIndex}`;
  return `W-${Math.floor(dayIndex / 7)}`;
}

export function computeSafeWord(seed, cadence = "weekly", nowMs = Date.now()) {
  const cleanSeed = (seed || "").trim().toUpperCase();
  if (!cleanSeed) {
    return { word: "SET-FAMILY-SEED", pin: "0000", bucket: getTimeBucket(cadence, nowMs) };
  }
  const bucket = getTimeBucket(cadence, nowMs);
  const h1 = fnv1a32(`${cleanSeed}::${bucket}::ADJ`);
  const h2 = fnv1a32(`${cleanSeed}::${bucket}::NOUN`);
  const h3 = fnv1a32(`${cleanSeed}::${bucket}::PIN`);

  const adj = ADJECTIVES[h1 % ADJECTIVES.length];
  const noun = NOUNS[h2 % NOUNS.length];
  const pin = String(1000 + (h3 % 9000));

  return {
    word: `${adj}-${noun}`,
    pin,
    bucket
  };
}
