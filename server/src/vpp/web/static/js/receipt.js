// Receipt page: a short honey-drop celebration, once per payment (skipped with reduced motion).
import { reducedMotion } from "./lib.js";

const mark = document.querySelector("[data-recorded]");
if (mark && !reducedMotion()) {
  const key = `vpp-celebrated-${mark.dataset.recorded}`;
  let seen = false;
  try { seen = sessionStorage.getItem(key) === "1"; sessionStorage.setItem(key, "1"); } catch { /* private mode */ }
  if (!seen) celebrate();
}

function celebrate() {
  const canvas = document.createElement("canvas");
  canvas.className = "honey-rain";
  canvas.setAttribute("aria-hidden", "true");
  document.body.appendChild(canvas);
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const resize = () => { canvas.width = innerWidth * dpr; canvas.height = innerHeight * dpr; };
  resize();
  const colors = ["#ffc93c", "#e9a100", "#ffe27a", "#1b1408"];
  const drops = Array.from({ length: 70 }, () => ({
    x: Math.random() * innerWidth, y: -20 - Math.random() * innerHeight * 0.6,
    vy: 2 + Math.random() * 3, vx: -1 + Math.random() * 2,
    r: 5 + Math.random() * 7, rot: Math.random() * 6, vr: -0.05 + Math.random() * 0.1,
    c: colors[(Math.random() * colors.length) | 0],
  }));
  const hex = (x, y, r, rot) => {
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
      const a = rot + (Math.PI / 3) * i;
      ctx[i ? "lineTo" : "moveTo"](x + r * Math.cos(a), y + r * Math.sin(a));
    }
    ctx.closePath();
  };
  const start = performance.now();
  const frame = (t) => {
    const age = t - start;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, innerWidth, innerHeight);
    ctx.globalAlpha = age > 2200 ? Math.max(0, 1 - (age - 2200) / 600) : 1;
    for (const d of drops) {
      d.vy += 0.06; d.x += d.vx; d.y += d.vy; d.rot += d.vr;
      hex(d.x, d.y, d.r, d.rot);
      ctx.fillStyle = d.c;
      ctx.fill();
    }
    if (age < 2800) requestAnimationFrame(frame); else canvas.remove();
  };
  requestAnimationFrame(frame);
}
