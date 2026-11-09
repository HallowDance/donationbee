// Small shared helpers. ES module; loaded from 'self' so the strict CSP stays as it is.

export const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

export const enc = new TextEncoder();

export function hex(bytes) {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

export function fromB64(s) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Animate a hash changing: characters roll before settling (instant with reduced motion). */
export async function rollText(el, finalText, ms = 420) {
  if (reducedMotion() || !el) { if (el) el.textContent = finalText; return; }
  const chars = "0123456789abcdef";
  const start = performance.now();
  return new Promise((resolve) => {
    const tick = (t) => {
      const p = Math.min(1, (t - start) / ms);
      const settled = Math.floor(p * finalText.length);
      el.textContent = finalText.slice(0, settled) +
        [...finalText.slice(settled)].map(() => chars[(Math.random() * 16) | 0]).join("");
      if (p < 1) requestAnimationFrame(tick); else resolve();
    };
    requestAnimationFrame(tick);
  });
}

/** Count a number up from its current text to `to`. */
export function countTo(el, to, ms = 600) {
  const from = parseInt(el.textContent, 10) || 0;
  if (reducedMotion() || from === to) { el.textContent = String(to); return; }
  const start = performance.now();
  const tick = (t) => {
    const p = Math.min(1, (t - start) / ms);
    el.textContent = String(Math.round(from + (to - from) * (1 - (1 - p) ** 3)));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

/** The bee flies a lap across the top of the screen (skipped with reduced motion). */
export function beeLap() {
  if (reducedMotion()) return;
  const logo = document.querySelector(".site-header .bee");
  if (!logo) return;
  const bee = logo.cloneNode(true);
  bee.classList.add("bee-lap");
  bee.setAttribute("aria-hidden", "true");
  document.body.appendChild(bee);
  bee.addEventListener("animationend", () => bee.remove());
}
