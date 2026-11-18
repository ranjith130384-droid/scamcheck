import test from "node:test";
import assert from "node:assert/strict";
import { analyzeMessage, levenshtein } from "../js/engine.js";
import { computeSafeWord } from "../js/safeword.js";

test("detects bank phishing with typosquatted domain + OTP trap", () => {
  const msg = "URGENT: Your Chase account will be suspended within 24 hours. Verify at https://chase-verify.paypa1-secure.xyz/login and send the 6-digit OTP code.";
  const res = analyzeMessage(msg);
  assert.equal(res.verdict, "HIGH_RISK");
  assert.ok(res.score >= 60);
  assert.ok(res.signals.some((s) => s.category === "Brand Spoofing"));
  assert.ok(res.signals.some((s) => s.category === "Credential Theft"));
});

test("detects fake job scam via Telegram + free email + equipment check", () => {
  const msg = "Remote Data Analyst (\$450/day, no experience needed). Interview via Telegram only with hr.recruiter@gmail.com. We will mail an equipment check.";
  const res = analyzeMessage(msg);
  assert.equal(res.verdict, "HIGH_RISK");
  assert.ok(res.signals.some((s) => s.category === "Fake Job Scam"));
  assert.ok(res.signals.some((s) => s.category === "Impersonation"));
});

test("detects USPS delivery fee phish with URL shortener", () => {
  const msg = "USPS Alert: Your package is on hold due to incomplete address. Pay the \$1.95 redelivery fee now at https://bit.ly/3xFakeUsps";
  const res = analyzeMessage(msg);
  assert.ok(res.score >= 40);
  assert.ok(res.signals.some((s) => s.category === "Delivery / Toll Phish"));
});

test("detects AI voice-clone family emergency script", () => {
  const msg = "Mom I lost my phone and crashed my car, I need money urgently via gift card do not tell anyone!";
  const res = analyzeMessage(msg);
  assert.equal(res.verdict, "HIGH_RISK");
  assert.ok(res.signals.some((s) => s.category === "AI Voice-Clone Trap"));
});

test("does not false-positive on normal everyday text or official domain", () => {
  const safeText = "Hey! Running 10 minutes late for coffee, see you at the corner cafe.";
  const res1 = analyzeMessage(safeText);
  assert.equal(res1.verdict, "SAFE");
  assert.equal(res1.score, 0);

  const officialLink = "Check your receipt at https://paypal.com/activity";
  const res2 = analyzeMessage(officialLink);
  assert.equal(res2.verdict, "SAFE");
});

test("levenshtein calculates edit distance accurately", () => {
  assert.equal(levenshtein("paypal", "paypa1"), 1);
  assert.equal(levenshtein("amazon", "amazon"), 0);
});

test("Family Safe-Word is deterministic across devices for same seed and time", () => {
  const fixedNow = 1795000000000;
  const a = computeSafeWord("K9M4-XP2L-7R8Q", "weekly", fixedNow);
  const b = computeSafeWord("k9m4-xp2l-7r8q", "weekly", fixedNow);
  assert.equal(a.word, b.word);
  assert.equal(a.pin, b.pin);
  assert.notEqual(a.word, "SET-FAMILY-SEED");
});
