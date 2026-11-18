# ScamCheck — 1-Tap Family Scam Shield (Mobile PWA)

Built with the **Software Factory** 1,000-role pyramid for **\$0** hosting and **\$0** runtime cost.

## Features
- **1-Tap Scam Scanner:** Detects typosquatted domains (`paypa1`, `.xyz`, Punycode, shorteners), urgency/fear manipulation, OTP/gift-card traps, fake Telegram job offers, and AI voice-clone emergency scripts—100% locally on the user's phone.
- **Family Safe-Word:** Offline rotating word-pair + PIN synced across family phones via a shared seed to defeat AI voice-clone calls.
- **Shareable Warning Card:** Generates a 1080×1080 PNG alert card on-device for 1-tap sharing to WhatsApp/iMessage.
- **Scan Vault & Playbook:** Local `localStorage` history with search, JSON export, and an active scam recovery guide.
- **Offline PWA + Android Share Target:** Installable on iOS (*Share -> Add to Home Screen*) and Android (*Install App*).

## Run Locally & Test
```bash
# Run unit tests
node --test tests/engine.test.mjs

# Serve locally
python3 -m http.server 8080
```

## Deploy Free (\$0)
Push this folder to GitHub and enable **GitHub Pages** (or connect to **Cloudflare Pages**)—no backend, database, or API keys needed.
