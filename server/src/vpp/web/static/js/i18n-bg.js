// Bulgarian text for the scripts (see i18n.js). Keys are the English text in the scripts;
// tests/test_i18n.py checks that every key used there is here, with the same {placeholders}.
export default {
  // pay.js
  "anonymous": "анонимен",

  // ledger.js
  "{n} new entry just arrived.": "Току-що пристигна {n} нов запис.",
  "{n} new entries just arrived.": "Току-що пристигнаха {n} нови записа.",
  "Downloaded {n} entries and the signed checkpoint.": "Изтеглени са {n} записа и подписаната контролна точка.",
  "Entry #{seq} is missing.": "Запис #{seq} липсва.",
  "Entry #{seq}: its contents don't match its hash.": "Запис #{seq}: съдържанието му не съвпада с хеша.",
  "Entry #{seq} doesn't link to #{prev}.": "Запис #{seq} не сочи към #{prev}.",
  "Entry #{seq}: the signature doesn't verify.": "Запис #{seq}: подписът не е валиден.",
  "All {n} hashes recompute from the entries' contents.": "Всички {n} хеша се изчисляват наново от съдържанието на записите.",
  "Every entry links to the one before it, with no gaps.": "Всеки запис сочи към предишния, без пропуски.",
  "Every entry is signed by the key in charge at that point.": "Всеки запис е подписан с ключа, който е бил в сила в този момент.",
  "This browser can't check Ed25519 signatures. vpp-verify can.": "Този браузър не може да проверява Ed25519 подписи. vpp-verify може.",
  "The tree root doesn't match the signed checkpoint.": "Коренът на дървото не съвпада с подписаната контролна точка.",
  "The Merkle tree of the first {n} entries matches the signed checkpoint.": "Дървото на Меркъл от първите {n} записа съвпада с подписаната контролна точка.",
  "The checkpoint's signature doesn't verify.": "Подписът на контролната точка не е валиден.",
  "The checkpoint is signed by the ledger, and carries {n} witness cosignature.": "Контролната точка е подписана от регистъра и носи {n} съподпис от свидетел.",
  "The checkpoint is signed by the ledger, and carries {n} witness cosignatures.": "Контролната точка е подписана от регистъра и носи {n} съподписа от свидетели.",
  "Check again": "Провери отново",
  "The check stopped: {error}": "Проверката спря: {error}",

  // playground.js
  "Ledger opens": "Регистърът се отваря",
  "Witness signed the tree root": "Свидетелят подписа корена на дървото",
  "The chain now gives": "Веригата сега дава",
  "matches": "съвпада",
  "doesn't match": "не съвпада",
  "Cover it up": "Прикрий го",
  "Reset": "Отначало",
  "genesis": "начало",
  "Amount of entry {n}": "Сума на запис {n}",
  "prev": "предишен",
  "hash": "хеш",
  "Every entry's prev matches the hash before it. Try changing an amount.": "Полето „предишен“ на всеки запис съвпада с хеша преди него. Опитайте да промените сума.",
  "Back to the original amount: every link matches again.": "Обратно на първоначалната сума: всяка връзка отново съвпада.",
  "You changed #{n}. Its hash changed, so the link from #{next} is broken. Anyone checking the chain sees it.": "Променихте #{n}. Хешът му се промени, така че връзката от #{next} е скъсана. Всеки, който проверява веригата, го вижда.",
  "You changed #{n}. Its hash changed, so the tree root no longer matches what the witness signed.": "Променихте #{n}. Хешът му се промени, така че коренът на дървото вече не съвпада с подписаното от свидетеля.",
  "Nothing was changed, so there's nothing to cover up.": "Нищо не е променено, така че няма какво да се прикрива.",
  "Every link matches again, but the tree root is no longer what the witness signed. Caught anyway.": "Всички връзки отново съвпадат, но коренът на дървото вече не е това, което свидетелят подписа. Хванати сте все пак.",
  "Reset. Every entry's prev matches the hash before it.": "Отначало. Полето „предишен“ на всеки запис съвпада с хеша преди него.",

  // landing.js (Barnaby's facts)
  "Bzz! I'm Barnaby. Tap me again and I'll tell you how the ledger works.": "Бзз! Аз съм Барнаби. Докосни ме пак и ще ти разкажа как работи регистърът.",
  "Change one byte of an entry and its hash changes completely.": "Промени един байт от запис и хешът му се променя изцяло.",
  "Every entry carries the hash of the one before it. That's the chain.": "Всеки запис носи хеша на предишния. Това е веригата.",
  "Witnesses only sign a ledger that extends the one they saw last. No secret rewrites.": "Свидетелите подписват само регистър, който продължава последния, който са видели. Никакви тайни пренаписвания.",
  "The recipient signs for payments with their own passkey. We can't do it for them.": "Получателят потвърждава плащанията със собствения си ключ за достъп. Ние не можем да го направим вместо него.",
  "We never hold the money. It goes straight to the recipient's Stripe account.": "Никога не държим парите. Те отиват директно в сметката на получателя в Stripe.",
  "Names are stored as salted hashes, so they can be erased without breaking the chain.": "Имената се пазят като осолени хешове, затова могат да бъдат изтрити, без да се развали веригата.",
  "Payers get a receipt that proves their payment is in the ledger. Keep it!": "Платците получават разписка, която доказва, че плащането им е в регистъра. Пази я!",
  "Every hour, the ledger's fingerprint is timestamped in Bitcoin. Just the fingerprint: no coins change hands.": "Всеки час отпечатъкът на регистъра получава времеви печат в Bitcoin. Само отпечатъкът: никакви монети не сменят собственика си.",
  "Don't trust me, I'm just a bee. Run vpp-verify.": "Не ми вярвай, аз съм само пчела. Пусни vpp-verify.",

  // passkey.js
  "Select at least one payment.": "Изберете поне едно плащане.",
  "Confirmed in ledger entry #{seq}.": "Потвърдено в запис #{seq} от регистъра.",
};
