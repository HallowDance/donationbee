// Text for the scripts, in the page's language (<html lang>). English is the key; a missing
// translation falls back to it. {name} placeholders are filled from the second argument.
// The server-rendered pages are translated separately (web/locale/*/messages.po).
import BG from "./i18n-bg.js";

const lang = document.documentElement.lang;
const CATALOGS = { bg: BG };

export function t(text, vars = {}) {
  const out = CATALOGS[lang]?.[text] ?? text;
  return out.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}

/** Plural: pick the singular or plural key by n (English and Bulgarian both have two forms). */
export const tn = (one, many, n, vars = {}) => t(n === 1 ? one : many, { n, ...vars });

/** A euro amount the way the page's language writes it: "12.50 EUR" or "12,50 €". */
export function euros(amount) {
  return lang === "bg" ? `${amount.toFixed(2).replace(".", ",")}\u00a0€` : `${amount.toFixed(2)} EUR`;
}
