// Recipient passkey flows. Served from 'self' so the page CSP can forbid inline scripts.
const b64u = {
  decode: (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)).buffer,
  encode: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
};

async function post(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || data.detail || `HTTP ${r.status}`);
  return data;
}

function creationOptions(o) {
  return { ...o, challenge: b64u.decode(o.challenge), user: { ...o.user, id: b64u.decode(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64u.decode(c.id) })) };
}
function requestOptions(o) {
  return { ...o, challenge: b64u.decode(o.challenge),
    allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b64u.decode(c.id) })) };
}
function credentialJSON(c) {
  const r = c.response, out = { id: c.id, rawId: b64u.encode(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults(), response: { clientDataJSON: b64u.encode(r.clientDataJSON) } };
  if (r.attestationObject) out.response.attestationObject = b64u.encode(r.attestationObject);
  if (r.authenticatorData) {
    out.response.authenticatorData = b64u.encode(r.authenticatorData);
    out.response.signature = b64u.encode(r.signature);
    out.response.userHandle = r.userHandle ? b64u.encode(r.userHandle) : null;
  }
  return out;
}

async function assert(optionsUrl, verifyUrl, body) {
  const { challenge_id, options } = await post(optionsUrl, body);
  const cred = await navigator.credentials.get({ publicKey: requestOptions(options) });
  return post(verifyUrl, { challenge_id, credential: credentialJSON(cred) });
}

function status(msg, bad) {
  const el = document.getElementById("status");
  if (el) { el.textContent = msg; el.className = "notice " + (bad ? "bad" : "ok"); el.hidden = false; }
}

async function run(fn) {
  try { await fn(); } catch (e) { status(e.message, true); }
}

document.addEventListener("click", (ev) => {
  const t = ev.target.closest("[data-action]");
  if (!t) return;
  ev.preventDefault();
  const action = t.dataset.action;
  if (action === "register") run(async () => {
    const { challenge_id, options } = await post("/api/recipient/register/options");
    const cred = await navigator.credentials.create({ publicKey: creationOptions(options) });
    await post("/api/recipient/register/verify", { challenge_id, credential: credentialJSON(cred) });
    location.reload();
  });
  if (action === "login") run(async () => {
    await assert("/api/recipient/login/options", "/api/recipient/login/verify");
    location.href = "/recipient";
  });
  if (action === "publish") run(async () => {
    const domain = document.getElementById("domain-" + t.dataset.cred).value;
    await post("/api/recipient/publish", { credential_id: t.dataset.cred, domain });
    location.reload();
  });
  if (action === "confirm") run(async () => {
    const ref_seqs = [...document.querySelectorAll("input[name=ref]:checked")].map((i) => Number(i.value));
    if (!ref_seqs.length) throw new Error("Select at least one payment.");
    const { seq } = await assert("/api/recipient/confirm/options", "/api/recipient/confirm/verify", { ref_seqs });
    status(`Confirmed in ledger entry #${seq}.`);
    setTimeout(() => location.reload(), 1200);
  });
});
