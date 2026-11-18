import { analyzeMessage } from "./engine.js";
import { computeSafeWord, generateRandomSeed } from "./safeword.js";
import { generateWarningCardBlob } from "./card.js";

const VAULT_KEY = "scamcheck_vault_v1";
const SEED_KEY = "scamcheck_family_seed_v1";
const CADENCE_KEY = "scamcheck_cadence_v1";

const SAMPLES = {
  bank: "URGENT: Your Chase account will be suspended within 24 hours due to suspicious login. Verify immediately at https://chase-verify.paypa1-secure.xyz/login and send the 6-digit OTP code.",
  job: "Congratulations! You are selected for Remote Data Analyst (\$450/day, no experience needed). Interview via Telegram only with hr.recruiter@gmail.com. We will mail an equipment check.",
  usps: "USPS Alert: Your package is on hold due to incomplete address. Pay the \$1.95 redelivery fee now at https://bit.ly/3xFakeUsps",
  safe: "Hey! Running 10 minutes late for coffee, see you at the corner cafe."
};

const $ = (id) => document.getElementById(id);

function showToast(msg) {
  const el = $("toast");
  el.textContent = msg;
  el.style.display = "block";
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => {
    el.style.display = "none";
  }, 2400);
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// --- Navigation ---
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = btn.dataset.tab;
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${target}`));
    if (target === "vault") renderVault();
  });
});

// --- Vault Storage ---
function loadVault() {
  try {
    return JSON.parse(localStorage.getItem(VAULT_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveToVault(text, result) {
  const vault = loadVault();
  vault.unshift({
    id: Date.now(),
    ts: new Date().toISOString(),
    text,
    score: result.score,
    verdict: result.verdict,
    label: result.label,
    signals: result.signals.map((s) => s.title)
  });
  localStorage.setItem(VAULT_KEY, JSON.stringify(vault.slice(0, 100)));
}

function renderVault() {
  const query = ($("vault-search").value || "").trim().toLowerCase();
  const list = $("vault-list");
  const items = loadVault().filter((item) =>
    !query || item.text.toLowerCase().includes(query) || item.label.toLowerCase().includes(query)
  );

  if (items.length === 0) {
    list.innerHTML = `<div class="card"><p class="sub" style="margin:0;">No saved scans yet. Run a check on the first tab!</p></div>`;
    return;
  }

  list.innerHTML = items.map((item) => {
    const color = item.verdict === "HIGH_RISK" ? "#ef4444" : item.verdict === "SUSPICIOUS" ? "#f59e0b" : "#10b981";
    const dateStr = new Date(item.ts).toLocaleString();
    return `
      <div class="vault-item">
        <div class="vault-top">
          <strong style="color:${color}">${escapeHtml(item.label)} (${item.score}/100)</strong>
          <span>${escapeHtml(dateStr)}</span>
        </div>
        <div class="vault-snippet">${escapeHtml(item.text.slice(0, 180))}${item.text.length > 180 ? "..." : ""}</div>
        <button class="chip" data-recheck="${item.id}" type="button">Re-open in Scanner</button>
      </div>
    `;
  }).join("");

  list.querySelectorAll("[data-recheck]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const found = loadVault().find((x) => String(x.id) === btn.dataset.recheck);
      if (found) {
        $("scan-input").value = found.text;
        document.querySelector('[data-tab="scan"]').click();
        runScan(false);
      }
    });
  });
}

// --- Scanner ---
let lastScan = null;

function renderResult(result, rawText) {
  lastScan = { result, rawText };
  const container = $("scan-result");
  if (result.verdict === "EMPTY") {
    container.style.display = "none";
    showToast("Paste a message or link first");
    return;
  }

  const cls = result.verdict === "HIGH_RISK" ? "verdict-danger" : result.verdict === "SUSPICIOUS" ? "verdict-warn" : "verdict-safe";
  const barColor = result.verdict === "HIGH_RISK" ? "#ef4444" : result.verdict === "SUSPICIOUS" ? "#f59e0b" : "#10b981";

  const signalsHtml = result.signals.length
    ? result.signals.map((s) => `
        <div class="signal-item">
          <div class="signal-top">
            <span>${escapeHtml(s.title)}</span>
            <span class="${s.severity === "high" ? "badge-high" : "badge-medium"}">${s.severity.toUpperCase()}</span>
          </div>
          <div class="signal-detail">${escapeHtml(s.detail)}</div>
        </div>
      `).join("")
    : `<div class="signal-item"><div class="signal-detail" style="margin:0;">No known phishing, typosquatting, or scam-script signals triggered.</div></div>`;

  const actionsHtml = result.actions.map((a) => `<li>${escapeHtml(a)}</li>`).join("");

  container.innerHTML = `
    <div class="verdict-box ${cls}">
      <div class="verdict-header">
        <div class="verdict-title">${escapeHtml(result.label)}</div>
        <div class="score-pill">${result.score}/100</div>
      </div>
      <div class="meter-track">
        <div class="meter-fill" style="width:${Math.max(8, result.score)}%; background:${barColor};"></div>
      </div>
      ${signalsHtml}
      <h3 style="margin:14px 0 4px; font-size:0.95rem;">What To Do Next</h3>
      <ul class="action-list">${actionsHtml}</ul>
      <div class="btn-row" style="margin-top:14px;">
        <button id="btn-share-card" class="btn btn-primary" type="button">📤 Warn Family</button>
        <button id="btn-copy-summary" class="btn btn-secondary" type="button">📋 Copy Alert</button>
      </div>
    </div>
  `;
  container.style.display = "block";

  $("btn-share-card").addEventListener("click", shareWarningCard);
  $("btn-copy-summary").addEventListener("click", async () => {
    const summary = `ScamCheck Alert: ${result.label} (${result.score}/100)\nFlags: ${result.signals.map((s) => s.title).join(", ") || "None"}`;
    await navigator.clipboard.writeText(summary);
    showToast("Alert copied to clipboard");
  });
}

function runScan(persist = true) {
  const text = $("scan-input").value;
  const res = analyzeMessage(text);
  renderResult(res, text);
  if (persist && res.verdict !== "EMPTY") {
    saveToVault(text, res);
  }
}

async function shareWarningCard() {
  if (!lastScan) return;
  const { result, rawText } = lastScan;
  const blob = await generateWarningCardBlob(result, rawText);
  const file = new File([blob], "scamcheck-warning.png", { type: "image/png" });

  if (navigator.canShare && navigator.canShare({ files: [file] })) {
    try {
      await navigator.share({
        title: "ScamCheck Family Warning",
        text: `${result.label} (${result.score}/100) — Be careful with this message!`,
        files: [file]
      });
      return;
    } catch {
      // Fall back to download
    }
  }

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "scamcheck-warning.png";
  a.click();
  URL.revokeObjectURL(url);
  showToast("Warning Card PNG downloaded");
}

$("btn-run-scan").addEventListener("click", () => runScan(true));

$("btn-paste-scan").addEventListener("click", async () => {
  try {
    const clip = await navigator.clipboard.readText();
    if (!clip) {
      showToast("Clipboard is empty");
      return;
    }
    $("scan-input").value = clip;
    runScan(true);
  } catch {
    showToast("Tap inside the box and paste manually");
  }
});

document.querySelectorAll("[data-sample]").forEach((chip) => {
  chip.addEventListener("click", () => {
    $("scan-input").value = SAMPLES[chip.dataset.sample];
    runScan(true);
  });
});

// --- Family Safe-Word ---
function refreshSafeWord() {
  const seed = $("seed-input").value;
  const cadence = $("cadence-select").value;
  localStorage.setItem(SEED_KEY, seed);
  localStorage.setItem(CADENCE_KEY, cadence);
  const { word, pin, bucket } = computeSafeWord(seed, cadence);
  $("safeword-word").textContent = word;
  $("safeword-meta").textContent = `Backup PIN: ${pin} • Cycle: ${bucket}`;
}

function initSafeWord() {
  let seed = localStorage.getItem(SEED_KEY);
  if (!seed) {
    seed = generateRandomSeed();
    localStorage.setItem(SEED_KEY, seed);
  }
  $("seed-input").value = seed;
  $("cadence-select").value = localStorage.getItem(CADENCE_KEY) || "weekly";
  refreshSafeWord();
}

$("seed-input").addEventListener("input", refreshSafeWord);
$("cadence-select").addEventListener("change", refreshSafeWord);
$("btn-new-seed").addEventListener("click", () => {
  $("seed-input").value = generateRandomSeed();
  refreshSafeWord();
  showToast("New Family Seed generated");
});

$("btn-share-seed").addEventListener("click", async () => {
  const seed = $("seed-input").value.trim();
  const cadence = $("cadence-select").value;
  const msg = `Join our ScamCheck Family Safe-Word so AI voice clones can't fool us.\nSeed: ${seed}\nRotation: ${cadence}`;
  if (navigator.share) {
    try {
      await navigator.share({ title: "ScamCheck Family Seed", text: msg });
      return;
    } catch {}
  }
  await navigator.clipboard.writeText(msg);
  showToast("Family Seed copied to clipboard");
});

// --- Vault Controls ---
$("vault-search").addEventListener("input", renderVault);
$("btn-clear-vault").addEventListener("click", () => {
  localStorage.removeItem(VAULT_KEY);
  renderVault();
  showToast("Vault cleared");
});
$("btn-export-vault").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(loadVault(), null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "scamcheck-vault.json";
  a.click();
  URL.revokeObjectURL(url);
});

// --- Share Target & Offline SW ---
function handleIncomingShare() {
  const params = new URLSearchParams(window.location.search);
  const shared = [params.get("title"), params.get("text"), params.get("url")].filter(Boolean).join("\n");
  if (shared) {
    $("scan-input").value = shared;
    runScan(true);
  }
}

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("./sw.js").catch(() => {});
}

window.addEventListener("online", () => { $("offline-badge").textContent = "100% On-Device"; });
window.addEventListener("offline", () => { $("offline-badge").textContent = "Offline Ready"; });

initSafeWord();
handleIncomingShare();
