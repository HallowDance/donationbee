// Tamper playground: a toy ledger hashed with real SHA-256. Change an amount and watch the chain
// break; "cover it up" re-hashes everything, and the witness catches the new head anyway.
import { t } from "./i18n.js";
import { enc, concat, hex, sha256, rollText, reducedMotion } from "./lib.js";

const root = document.querySelector("[data-playground]");

const ENTRIES = [
  { who: t("Ledger opens"), to: null, amount: null },
  { who: "Ada", to: "Open Meadow", amount: 50 },
  { who: "Grace", to: "Open Meadow", amount: 25 },
  { who: "Indie Hacker Co.", to: "Open Meadow", amount: 250 },
  { who: "Radia", to: "Lucky Draw", amount: 15 },
];

const short = (h) => h.slice(0, 12);

async function hashEntry(prevHex, e, i) {
  const body = enc.encode(JSON.stringify({ seq: i + 1, who: e.who, to: e.to, amount: e.amount }));
  return hex(await sha256(concat(enc.encode(prevHex), body)));
}

// Toy stand-in for the Merkle tree root: one hash over every entry's hash, in order.
async function rootOf(hashes) {
  return hex(await sha256(enc.encode(hashes.join(""))));
}

async function chain(entries) {
  const out = [];
  let prev = "0".repeat(64);
  for (let i = 0; i < entries.length; i++) {
    const h = await hashEntry(prev, entries[i], i);
    out.push({ prev, hash: h });
    prev = h;
  }
  return out;
}

if (root) init();

async function init() {
  const original = ENTRIES.map((e) => ({ ...e }));
  const published = await chain(original);
  const signedRoot = await rootOf(published.map((p) => p.hash)); // what the witness signed
  let current = original.map((e) => ({ ...e }));
  let stored = published.map((p) => ({ ...p })); // the prev/hash values written in each entry

  root.innerHTML = `
    <div class="pg-chain" role="list"></div>
    <div class="pg-witness">
      <span class="eyebrow">${t("Witness signed the tree root")}</span>
      <code class="pg-witness-hash">${short(signedRoot)}</code>
      <span class="eyebrow">${t("The chain now gives")}</span>
      <code class="pg-current-root">${short(signedRoot)}</code>
      <span class="pg-witness-state tag ok">${t("matches")}</span>
    </div>
    <p class="pg-status" role="status" aria-live="polite"></p>
    <div class="row">
      <button type="button" class="small" data-cover>${t("Cover it up")}</button>
      <button type="button" class="small ghost" data-reset>${t("Reset")}</button>
    </div>`;
  const list = root.querySelector(".pg-chain");
  list.innerHTML = current.map((e, i) => `
    <div class="pg-entry" role="listitem" data-i="${i}">
      <div class="pg-link" aria-hidden="true"></div>
      <span class="seq">#${i + 1}</span>
      <strong class="pg-what">${e.to ? `${e.who} → ${e.to}` : e.who}</strong>
      ${e.amount === null ? `<span class="muted pg-amount-static">${t("genesis")}</span>` : `
        <label class="pg-amount"><span>€</span><input type="number" min="0" max="99999" step="1"
          value="${e.amount}" inputmode="numeric" aria-label="${t("Amount of entry {n}", { n: i + 1 })}" id="pg-amount-${i}"></label>`}
      <span class="pg-label">${t("prev")}</span><code class="pg-prev">${short(stored[i].prev)}</code>
      <span class="pg-label">${t("hash")}</span><code class="pg-hash">${short(stored[i].hash)}</code>
    </div>`).join("");

  const cards = [...list.children];
  const status = root.querySelector(".pg-status");
  const witnessState = root.querySelector(".pg-witness-state");
  status.textContent = t("Every entry's prev matches the hash before it. Try changing an amount.");

  async function render(changedIndex = -1) {
    let firstBad = -1;
    let prevActual = "0".repeat(64);
    const actuals = [];
    for (let i = 0; i < current.length; i++) {
      // Recompute this entry from its *stored* prev, as a verifier would.
      const actual = await hashEntry(stored[i].prev, current[i], i);
      const contentOk = actual === stored[i].hash;
      // The link holds only if this entry's stored prev is what the previous entry really hashes to.
      const linkOk = i === 0 || stored[i].prev === prevActual;
      const card = cards[i];
      card.classList.toggle("pg-bad-hash", !contentOk);
      card.classList.toggle("pg-bad-link", !linkOk);
      if (i === changedIndex) await rollText(card.querySelector(".pg-hash"), short(actual), 360);
      else card.querySelector(".pg-hash").textContent = short(actual);
      card.querySelector(".pg-prev").textContent = short(stored[i].prev);
      if ((!contentOk || !linkOk) && firstBad < 0) firstBad = i;
      prevActual = actual;
      actuals.push(actual);
    }
    const currentRoot = await rootOf(actuals);
    root.querySelector(".pg-current-root").textContent = short(currentRoot);
    const headMatches = currentRoot === signedRoot;
    witnessState.className = `pg-witness-state tag ${headMatches ? "ok" : "bad"}`;
    witnessState.textContent = headMatches ? t("matches") : t("doesn't match");
    return firstBad;
  }

  list.addEventListener("input", async (ev) => {
    const input = ev.target.closest("input");
    if (!input) return;
    const i = Number(input.closest(".pg-entry").dataset.i);
    current[i].amount = Number(input.value || 0);
    const bad = await render(i);
    if (bad < 0) {
      status.textContent = t("Back to the original amount: every link matches again.");
    } else {
      status.textContent = i + 1 < current.length
        ? t("You changed #{n}. Its hash changed, so the link from #{next} is broken. Anyone checking the chain sees it.", { n: i + 1, next: i + 2 })
        : t("You changed #{n}. Its hash changed, so the tree root no longer matches what the witness signed.", { n: i + 1 });
      if (!reducedMotion()) {
        cards[i].animate([{ transform: "translateX(0)" }, { transform: "translateX(-4px)" },
          { transform: "translateX(4px)" }, { transform: "translateX(0)" }], { duration: 260 });
      }
    }
  });

  root.querySelector("[data-cover]").addEventListener("click", async () => {
    stored = await chain(current); // rewrite every prev and hash so the chain is consistent
    for (const [i, c] of cards.entries()) {
      c.classList.remove("pg-bad-hash", "pg-bad-link");
      rollText(c.querySelector(".pg-hash"), short(stored[i].hash), 300 + i * 90);
      rollText(c.querySelector(".pg-prev"), short(stored[i].prev), 300 + i * 90);
    }
    await new Promise((r) => setTimeout(r, reducedMotion() ? 0 : 750));
    await render();
    const same = (await rootOf(stored.map((x) => x.hash))) === signedRoot;
    status.textContent = same
      ? t("Nothing was changed, so there's nothing to cover up.")
      : t("Every link matches again, but the tree root is no longer what the witness signed. Caught anyway.");
    if (!same && !reducedMotion()) {
      root.querySelector(".pg-witness").animate(
        [{ transform: "scale(1)" }, { transform: "scale(1.06)" }, { transform: "scale(1)" }],
        { duration: 420 });
    }
  });

  root.querySelector("[data-reset]").addEventListener("click", async () => {
    current = original.map((e) => ({ ...e }));
    stored = published.map((p) => ({ ...p }));
    cards.forEach((c, i) => {
      const input = c.querySelector("input");
      if (input) input.value = current[i].amount;
    });
    await render();
    status.textContent = t("Reset. Every entry's prev matches the hash before it.");
  });

  await render();
}
