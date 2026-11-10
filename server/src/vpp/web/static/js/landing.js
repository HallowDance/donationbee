// Landing page: tap the bee for a loop-the-loop and a fact about how the ledger works.
import { reducedMotion } from "./lib.js";

const bee = document.querySelector("[data-bee]");
const bubble = document.querySelector("[data-bubble]");

const FACTS = [
  "Bzz! I'm Barnaby. Tap me again and I'll tell you how the ledger works.",
  "Change one byte of an entry and its hash changes completely.",
  "Every entry carries the hash of the one before it. That's the chain.",
  "Witnesses only sign a ledger that extends the one they saw last. No secret rewrites.",
  "The recipient signs for payments with their own passkey. We can't do it for them.",
  "We never hold the money. It goes straight to the recipient's Stripe account.",
  "Names are stored as salted hashes, so they can be erased without breaking the chain.",
  "Payers get a receipt that proves their payment is in the ledger. Keep it!",
  "Every hour, the ledger's fingerprint is timestamped into Bitcoin. Nobody can backdate it.",
  "Don't trust me, I'm just a bee. Run vpp-verify.",
];

if (bee && bubble) {
  let i = 0;
  let hideTimer;
  bee.addEventListener("click", () => {
    bubble.textContent = FACTS[i % FACTS.length];
    i += 1;
    bubble.hidden = false;
    bubble.classList.remove("pop");
    void bubble.offsetWidth; // restart the pop animation
    bubble.classList.add("pop");
    if (!reducedMotion()) {
      bee.classList.remove("loop");
      void bee.offsetWidth;
      bee.classList.add("loop");
    }
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => { bubble.hidden = true; }, 6000);
  });
  bee.addEventListener("animationend", () => bee.classList.remove("loop"));
}
