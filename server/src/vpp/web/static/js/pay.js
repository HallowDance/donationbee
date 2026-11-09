// Pay page: one-tap amounts and a live preview of exactly what the public ledger will show.
const form = document.querySelector("[data-pay-form]");
if (form) {
  const amount = form.querySelector("#amount");
  const name = form.querySelector("#payer_name");
  const note = form.querySelector("#note");
  const preview = document.querySelector("[data-preview]");
  const chips = [...form.querySelectorAll("[data-amount]")];

  const tipCents = () => Number(form.querySelector('input[name="tip"]:checked')?.value || 0);
  const fmt = (raw) => {
    const n = Number(String(raw).replace(",", "."));
    return Number.isFinite(n) && n > 0 ? `${n.toFixed(2)} EUR` : "…";
  };

  function update() {
    preview.querySelector("[data-p-amount]").textContent = fmt(amount.value);
    preview.querySelector("[data-p-from]").textContent = name.value.trim() || "anonymous";
    const n = note.value.trim();
    preview.querySelector("[data-p-note]").hidden = !n;
    preview.querySelector("[data-p-note-text]").textContent = n;
    for (const c of chips) c.setAttribute("aria-pressed", String(fmt(c.dataset.amount) === fmt(amount.value)));
    const tip = tipCents();
    const donation = Number(String(amount.value).replace(",", "."));
    preview.querySelector("[data-p-tip]").hidden = !tip;
    preview.querySelector("[data-p-tip-amount]").textContent = `${(tip / 100).toFixed(2)} EUR`;
    preview.querySelector("[data-p-total]").textContent =
      Number.isFinite(donation) && donation > 0 ? `${(donation + tip / 100).toFixed(2)} EUR` : "…";
  }

  for (const c of chips) {
    c.addEventListener("click", () => { amount.value = c.dataset.amount; update(); amount.focus(); });
  }
  form.addEventListener("input", update);
  update();
}
