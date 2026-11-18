/**
 * Generates a shareable PNG Warning Card on an HTML5 Canvas
 * so users can forward scam alerts to family WhatsApp/iMessage groups.
 */

function wrapText(ctx, text, x, y, maxWidth, lineHeight, maxLines = 4) {
  const words = text.split(/\s+/);
  let line = "";
  let lineCount = 0;
  let curY = y;

  for (let i = 0; i < words.length; i++) {
    const testLine = line ? `${line} ${words[i]}` : words[i];
    if (ctx.measureText(testLine).width > maxWidth && line) {
      ctx.fillText(line, x, curY);
      line = words[i];
      curY += lineHeight;
      lineCount++;
      if (lineCount >= maxLines - 1) {
        const remaining = [line, ...words.slice(i + 1)].join(" ");
        let trimmed = remaining;
        while (ctx.measureText(`${trimmed}...`).width > maxWidth && trimmed.length > 0) {
          trimmed = trimmed.slice(0, -1);
        }
        ctx.fillText(`${trimmed}...`, x, curY);
        return curY + lineHeight;
      }
    } else {
      line = testLine;
    }
  }
  if (line) ctx.fillText(line, x, curY);
  return curY + lineHeight;
}

export async function generateWarningCardBlob(result, originalText) {
  const canvas = document.createElement("canvas");
  canvas.width = 1080;
  canvas.height = 1080;
  const ctx = canvas.getContext("2d");

  // Background
  const grad = ctx.createLinearGradient(0, 0, 1080, 1080);
  grad.addColorStop(0, "#0b1120");
  grad.addColorStop(1, "#1e293b");
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, 1080, 1080);

  const isHigh = result.verdict === "HIGH_RISK";
  const accent = isHigh ? "#ef4444" : result.verdict === "SUSPICIOUS" ? "#f59e0b" : "#10b981";

  // Top alert banner
  ctx.fillStyle = accent;
  ctx.fillRect(0, 0, 1080, 28);

  // Header
  ctx.fillStyle = "#94a3b8";
  ctx.font = "bold 34px system-ui, -apple-system, sans-serif";
  ctx.fillText("SCAMCHECK • FAMILY SHIELD ALERT", 72, 110);

  // Verdict badge
  ctx.fillStyle = accent;
  ctx.font = "900 68px system-ui, -apple-system, sans-serif";
  ctx.fillText(result.label.toUpperCase(), 72, 200);

  ctx.fillStyle = "#e2e8f0";
  ctx.font = "bold 40px system-ui, -apple-system, sans-serif";
  ctx.fillText(`Risk Score: ${result.score}/100`, 72, 268);

  // Message snippet box
  ctx.fillStyle = "rgba(15, 23, 42, 0.85)";
  ctx.strokeStyle = "rgba(148, 163, 184, 0.35)";
  ctx.lineWidth = 3;
  ctx.beginPath();
  ctx.roundRect(72, 315, 936, 230, 24);
  ctx.fill();
  ctx.stroke();

  ctx.fillStyle = "#94a3b8";
  ctx.font = "bold 26px system-ui, -apple-system, sans-serif";
  ctx.fillText("CHECKED MESSAGE / LINK:", 104, 365);

  ctx.fillStyle = "#f8fafc";
  ctx.font = "30px system-ui, -apple-system, sans-serif";
  wrapText(ctx, originalText.replace(/\s+/g, " "), 104, 415, 872, 40, 3);

  // Signals
  ctx.fillStyle = "#94a3b8";
  ctx.font = "bold 28px system-ui, -apple-system, sans-serif";
  ctx.fillText("WHY IT WAS FLAGGED:", 72, 610);

  let y = 665;
  const topSignals = result.signals.slice(0, 3);
  if (topSignals.length === 0) {
    ctx.fillStyle = "#cbd5e1";
    ctx.font = "32px system-ui, -apple-system, sans-serif";
    ctx.fillText("• No obvious scam patterns detected.", 72, y);
  } else {
    for (const sig of topSignals) {
      ctx.fillStyle = accent;
      ctx.font = "bold 32px system-ui, -apple-system, sans-serif";
      y = wrapText(ctx, `• ${sig.title}`, 72, y, 936, 42, 2) + 12;
    }
  }

  // Footer
  ctx.fillStyle = "#64748b";
  ctx.font = "28px system-ui, -apple-system, sans-serif";
  ctx.fillText("Do NOT click links or send money. Checked 100% offline with ScamCheck.", 72, 995);

  return new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
}
