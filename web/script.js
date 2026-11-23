// Phrasia website – language switch, latest release info, small touches. No trackers, no cookies.
(() => {
  const REPO = "LUKICSLA/Phrasia";

  /* ---------- Translations (EN is in the HTML, SK lives here) ---------- */
  const SK = {
    "nav.features": "Funkcie",
    "nav.security": "Bezpečnosť",
    "nav.download": "Stiahnuť",
    "hero.eyebrow": "Zadarmo a open source · Windows 10 / 11",
    "hero.title": "Pamätaj si menej.<br><span class=\"grad\">Chráň sa viac.</span>",
    "hero.lead": "Phrasia vytvára silné heslá zo skutočných slov a ukladá ich do šifrovaného trezoru vo tvojom PC. Žiadny cloud, žiadny účet, nič neodchádza z počítača.",
    "hero.download": "Stiahnuť pre Windows",
    "hero.more": "Čo to vie?",
    "hero.meta": "jeden .exe súbor, bez inštalácie",
    "demo.title": "Generátor",
    "demo.label": "Tvoja nová fráza",
    "demo.strength": "Veľmi silné",
    "demo.crack": "≈ stáročia na prelomenie",
    "demo.words": "slová",
    "why": "Heslá ako <code>Tr0ub4dor&amp;3</code> si ťažko zapamätáš ty, ale počítač ich ľahko uhádne. Pár náhodných slov funguje presne naopak. Phrasia ich vygeneruje poriadne a bezpečne uschová.",
    "feat.title": "Čo v nej nájdeš",
    "feat.gen.t": "Generátor fráz",
    "feat.gen.l": "<li>Slovenské, české a anglické slová – alebo vlastný zoznam</li><li>Mix jazykov, oddeľovače, čísla a veľké písmená</li><li>Sila a „čas na prelomenie“ pri každom hesle</li><li>Predvoľby a viac variantov naraz</li>",
    "feat.vault.t": "Trezor hesiel",
    "feat.vault.l": "<li>Názov, meno, heslo, URL a poznámky</li><li>Kontrola zdravia: opakované, slabé a staré heslá</li><li>Schránka, ktorá sa sama vymaže, automatické zamknutie</li><li>Zálohy a záloha / obnova hlavičky</li>",
    "feat.priv.t": "Súkromie od základu",
    "feat.priv.l": "<li>Funguje úplne offline</li><li>Žiadny účet, synchronizácia ani telemetria</li><li>Voliteľná ochrana pred snímaním obrazovky</li><li>Svetlá a tmavá téma podľa Windows</li>",
    "sec.title": "Bezpečnosť v skratke",
    "sec.argon": "odvodenie kľúča, vyladené na tvoje PC",
    "sec.aead": "dve vrstvy autentizovaného šifrovania",
    "sec.pim": "tajné číslo navyše k hlavnému heslu",
    "sec.bind.t": "Viazané na zariadenie",
    "sec.bind": "trezor je spätý s tvojím PC a účtom Windows",
    "sec.note": "Trezor je taký silný ako tvoje hlavné heslo a PIM. Nevieš si rady? Nechaj si jedno navrhnúť.",
    "know.title": "Dobré vedieť",
    "know.key.t": "Exportuj kľúč zariadenia",
    "know.key": "Hneď po vytvorení trezoru použi <em>Export device key…</em> a súbor si bezpečne odlož. Bez neho trezor neotvoríš na inom PC ani po preinštalovaní Windows.",
    "know.pw.t": "Heslo sa nedá obnoviť",
    "know.pw": "Zabudneš hlavné heslo alebo PIM a trezor je preč. Žiadne zadné dvierka – o to ide.",
    "know.audit.t": "Bez auditu",
    "know.audit": "Phrasia je osobný projekt bez nezávislého bezpečnostného auditu. Rob si zálohy a používaj ju na počítači, ktorému veríš.",
    "dl.title": "Stiahni si Phrasiu",
    "dl.sub": "Windows 10 (1607+) alebo 11, 64-bit. Bez inštalácie, .NET netreba.",
    "dl.btn": "Stiahnuť Phrasia.exe",
    "dl.all": "Všetky verzie a zmeny",
    "dl.ss": "Súbor nie je digitálne podpísaný, takže Windows môže zobraziť varovanie. Klikni na <em>Ďalšie informácie → Spustiť aj tak</em>.",
    "dl.verify.t": "Over si súbor",
    "dl.verify": "Porovnaj SHA-256 s hodnotou pri vydaní:",
    "copy": "Kopírovať",
    "copied": "Skopírované",
    "foot.src": "Zdrojový kód",
    "foot.kofi": "Kúp mi kávu ☕"
  };
  const EN = {};
  document.querySelectorAll("[data-i18n]").forEach(el => { EN[el.dataset.i18n] = el.innerHTML; });
  EN.copied = "Copied";

  const store = {
    get: k => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* ignore */ } }
  };

  let lang = store.get("lang") || (/^(sk|cs)/i.test(navigator.language) ? "sk" : "en");
  const btn = document.getElementById("lang");

  function applyLang() {
    const dict = lang === "sk" ? SK : EN;
    document.querySelectorAll("[data-i18n]").forEach(el => {
      const v = dict[el.dataset.i18n];
      if (v !== undefined) el.innerHTML = v;
    });
    document.documentElement.lang = lang;
    btn.textContent = lang === "sk" ? "EN" : "SK";
    phrases = lang === "sk" ? PHRASES_SK : PHRASES_EN;
  }
  btn.addEventListener("click", () => {
    lang = lang === "sk" ? "en" : "sk";
    store.set("lang", lang);
    applyLang();
  });

  /* ---------- Demo phrases (illustration only – the real ones come from the app) ---------- */
  const PHRASES_EN = ["Lantern.Mango7.Orbit.Velvet", "Cactus-Harbor-Nine4-Ripple", "Pebble_Tundra_Lilac3_Rocket", "Violin.Ember2.Saddle.Fjord"];
  const PHRASES_SK = ["Hora.Kava7.Lampa.Vietor", "Ruksak-Sneh-Gombik4-Mlyn", "Javor_Pecivo_Struna3_Most", "Oblak.Pero2.Kolac.Rieka"];
  let phrases = PHRASES_EN, i = 0;
  const phraseEl = document.getElementById("phrase");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  applyLang();
  phraseEl.textContent = phrases[0];

  if (!reduced) {
    setInterval(() => {
      phraseEl.classList.add("fade");
      setTimeout(() => {
        i = (i + 1) % phrases.length;
        phraseEl.textContent = phrases[i];
        phraseEl.classList.remove("fade");
      }, 300);
    }, 3200);
  }

  /* ---------- Latest release: version, size and direct .exe link ---------- */
  fetch(`https://api.github.com/repos/${REPO}/releases/latest`, { headers: { Accept: "application/vnd.github+json" } })
    .then(r => (r.ok ? r.json() : Promise.reject()))
    .then(rel => {
      if (rel.tag_name) document.getElementById("ver").textContent = rel.tag_name.startsWith("v") ? rel.tag_name : "v" + rel.tag_name;
      const exe = (rel.assets || []).find(a => /\.exe$/i.test(a.name));
      if (!exe) return;
      document.querySelectorAll("[data-dl]").forEach(a => { a.href = exe.browser_download_url; });
      document.getElementById("size").textContent = `· ${(exe.size / 1048576).toFixed(0)} MB`;
    })
    .catch(() => { /* offline or rate-limited – links still point to the Releases page */ });

  /* ---------- Copy button ---------- */
  document.querySelectorAll("[data-copy]").forEach(b => {
    b.addEventListener("click", async () => {
      const text = document.getElementById(b.dataset.copy).textContent;
      try { await navigator.clipboard.writeText(text); } catch { return; }
      const dict = lang === "sk" ? SK : EN;
      b.textContent = dict.copied;
      setTimeout(() => { b.textContent = dict.copy; }, 1500);
    });
  });

  /* ---------- Reveal sections on scroll ---------- */
  if (!reduced && "IntersectionObserver" in window) {
    const io = new IntersectionObserver(entries => {
      entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } });
    }, { threshold: .12 });
    document.querySelectorAll("main > section:not(.hero)").forEach(s => { s.classList.add("reveal"); io.observe(s); });
  }
})();
