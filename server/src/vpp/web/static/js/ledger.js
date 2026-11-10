// /ledger: live updates and "check it in your browser".
// The in-browser check is a quick check only: this script is served by the operator, so the
// independent check is vpp-verify, which shares no code with this site (see LEDGER_SPEC).
import { t, tn } from "./i18n.js";
import { beeLap, concat, countTo, enc, fromB64, fromHex, hex, reducedMotion, sha256, sleep } from "./lib.js";

const table = document.querySelector("table.ledger");
const countEl = document.querySelector("[data-entry-count]");
const isFirstPage = !new URLSearchParams(location.search).has("before");

// ---------- live updates ----------

const topSeq = () => {
  const first = table?.querySelector("tr[data-seq]");
  return first ? Number(first.dataset.seq) : 0;
};

async function refresh() {
  if (document.hidden) return;
  let head;
  try { head = await (await fetch("/api/v1/head", { cache: "no-store" })).json(); } catch { return; }
  const known = topSeq();
  if (!head.seq || head.seq <= known) return;
  const html = await (await fetch("/ledger", { cache: "no-store" })).text();
  const doc = new DOMParser().parseFromString(html, "text/html");
  const fresh = [...doc.querySelectorAll("table.ledger tr[data-seq]")]
    .filter((tr) => Number(tr.dataset.seq) > known)
    .reverse(); // oldest first, so each one goes on top in order
  const anchorRow = table.querySelector("tr[data-seq]");
  let paid = false;
  for (const tr of fresh) {
    const row = document.importNode(tr, true);
    row.classList.add("row-new");
    table.querySelector("tbody").insertBefore(row, table.querySelector("tr[data-seq]") || anchorRow);
    if (row.dataset.type === "payment") paid = true;
  }
  // Swap in the new state card (count, root, witness status) from the same response.
  const newState = doc.querySelector("[data-state]");
  const oldState = document.querySelector("[data-state]");
  if (newState && oldState) {
    const newCount = Number(newState.querySelector("[data-entry-count]")?.textContent);
    oldState.querySelector("[data-tree]").replaceWith(newState.querySelector("[data-tree]"));
    if (countEl && newCount) countTo(countEl, newCount);
  }
  const live = document.querySelector("[data-live-status]");
  if (live) live.textContent = tn("{n} new entry just arrived.", "{n} new entries just arrived.", fresh.length);
  if (paid) beeLap();
  resetChecks(); // the earlier in-browser check no longer covers everything
}

if (table && isFirstPage) {
  setInterval(refresh, 5000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
}

// ---------- check it in your browser ----------

const DOMAIN = enc.encode("vpp:entry:v1\0");
const panel = document.querySelector("[data-verify]");
const button = document.querySelector("[data-verify-start]");

function step(name, state, text) {
  const li = panel.querySelector(`[data-step="${name}"]`);
  li.dataset.state = state;
  if (text) li.querySelector(".v-text").textContent = text;
}

function resetChecks() {
  table?.querySelectorAll("tr.row-ok").forEach((tr) => tr.classList.remove("row-ok"));
}

async function allEntries() {
  const out = [];
  let after = 0;
  for (;;) {
    const page = await (await fetch(`/api/v1/entries?after=${after}&limit=500`, { cache: "no-store" })).json();
    out.push(...page.entries);
    if (!page.next_after) return out;
    after = page.next_after;
  }
}

async function ed25519Supported() {
  try {
    await crypto.subtle.importKey("raw", new Uint8Array(32), { name: "Ed25519" }, false, ["verify"]);
    return true;
  } catch { return false; }
}

async function verifySig(pub, msg, sig) {
  const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg);
}

async function merkleRoot(leaves) {
  const node = async (l, r) => sha256(concat(Uint8Array.of(1), l, r));
  if (!leaves.length) return sha256(new Uint8Array());
  const stack = [];
  for (const leaf of leaves) {
    let h = 0, cur = leaf;
    while (stack.length && stack.at(-1)[0] === h) { cur = await node(stack.pop()[1], cur); h++; }
    stack.push([h, cur]);
  }
  let acc = stack.pop()[1];
  while (stack.length) acc = await node(stack.pop()[1], acc);
  return acc;
}

async function runCheck() {
  button.disabled = true;
  panel.hidden = false;
  resetChecks();
  for (const s of ["download", "hashes", "links", "sigs", "tree", "checkpoint"]) step(s, "pending");
  const fail = (s, msg) => { step(s, "bad", msg); button.disabled = false; return false; };
  const delay = reducedMotion() ? 0 : 25;

  step("download", "running");
  const [entries, note] = await Promise.all([
    allEntries(),
    (await fetch("/api/v1/checkpoint", { cache: "no-store" })).text(),
  ]);
  step("download", "ok", t("Downloaded {n} entries and the signed checkpoint.", { n: entries.length }));

  const canSig = await ed25519Supported();
  step("hashes", "running"); step("links", "running"); step("sigs", canSig ? "running" : "skip");
  let prev = new Uint8Array(32), key = null;
  const leaves = [], signerAt = [];
  for (const [i, e] of entries.entries()) {
    if (e.seq !== i + 1) return fail("links", t("Entry #{seq} is missing.", { seq: i + 1 }));
    const envelope = fromB64(e.envelope);
    const h = await sha256(concat(DOMAIN, fromHex(e.prev_hash), envelope));
    if (hex(h) !== e.hash) return fail("hashes", t("Entry #{seq}: its contents don't match its hash.", { seq: e.seq }));
    if (e.prev_hash !== hex(prev)) return fail("links", t("Entry #{seq} doesn't link to #{prev}.", { seq: e.seq, prev: e.seq - 1 }));
    const env = JSON.parse(new TextDecoder().decode(envelope));
    if (env.type === "genesis") key = fromHex(env.body.online_key);
    if (env.type === "key_rotation") key = fromHex(env.body.new_online_key); // signed by the new key
    if (canSig && !(await verifySig(key, h, fromHex(e.sig)))) {
      return fail("sigs", t("Entry #{seq}: the signature doesn't verify.", { seq: e.seq }));
    }
    signerAt.push(key);
    leaves.push(await sha256(concat(Uint8Array.of(0), h)));
    prev = h;
    table?.querySelector(`tr[data-seq="${e.seq}"]`)?.classList.add("row-ok");
    if (delay) await sleep(delay);
  }
  step("hashes", "ok", t("All {n} hashes recompute from the entries' contents.", { n: entries.length }));
  step("links", "ok", t("Every entry links to the one before it, with no gaps."));
  if (canSig) step("sigs", "ok", t("Every entry is signed by the key in charge at that point."));
  else step("sigs", "skip", t("This browser can't check Ed25519 signatures. vpp-verify can."));

  step("tree", "running");
  const [text, sigBlock] = [note.slice(0, note.lastIndexOf("\n\n") + 1), note.slice(note.lastIndexOf("\n\n") + 2)];
  const [, sizeStr, rootB64] = text.split("\n");
  const size = Number(sizeStr);
  const root = await merkleRoot(leaves.slice(0, size));
  if (hex(root) !== hex(fromB64(rootB64))) return fail("tree", t("The tree root doesn't match the signed checkpoint."));
  step("tree", "ok", t("The Merkle tree of the first {n} entries matches the signed checkpoint.", { n: size }));

  step("checkpoint", canSig ? "running" : "skip");
  const lines = sigBlock.trim().split("\n");
  const logSig = fromB64(lines[0].split(" ")[2]).slice(4); // 4-byte key id, then the signature
  const cosigs = lines.length - 1;
  if (canSig) {
    if (!(await verifySig(signerAt[size - 1], enc.encode(text), logSig))) {
      return fail("checkpoint", t("The checkpoint's signature doesn't verify."));
    }
    step("checkpoint", "ok", tn(
      "The checkpoint is signed by the ledger, and carries {n} witness cosignature.",
      "The checkpoint is signed by the ledger, and carries {n} witness cosignatures.", cosigs));
  }
  button.disabled = false;
  button.textContent = t("Check again");
  return true;
}

button?.addEventListener("click", () => {
  runCheck().catch((err) => {
    const box = panel.querySelector("[data-verify-error]");
    box.textContent = t("The check stopped: {error}", { error: err.message });
    box.hidden = false;
    button.disabled = false;
  });
});
