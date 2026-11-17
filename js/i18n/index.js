/**
 * Lightweight static-host i18n runtime for Valkyrie Control.
 * Supports browser auto-detection, localStorage persistence, dynamic ES module locale loading,
 * DOM binding updates, and reactive subscriber notification.
 */

import en from './locales/en.js';

export const STORAGE_KEY = 'valkyrie-control-lang';

export const SUPPORTED_LOCALES = [
  { code: 'en', nativeName: 'English' },
  { code: 'zh-CN', nativeName: '简体中文' },
  { code: 'zh-TW', nativeName: '繁體中文' },
  { code: 'ja', nativeName: '日本語' },
  { code: 'ko', nativeName: '한국어' },
  { code: 'es', nativeName: 'Español' },
  { code: 'de', nativeName: 'Deutsch' },
  { code: 'fr', nativeName: 'Français' },
  { code: 'pt-BR', nativeName: 'Português (BR)' },
  { code: 'ru', nativeName: 'Русский' },
];

const SUPPORTED_SET = new Set(SUPPORTED_LOCALES.map(l => l.code));

export function detectBrowserLocale(languages) {
  let candidates = languages;
  if (!candidates) {
    if (typeof navigator !== 'undefined') {
      candidates = Array.isArray(navigator.languages) && navigator.languages.length > 0
        ? navigator.languages
        : navigator.language
          ? [navigator.language]
          : [];
    } else {
      candidates = [];
    }
  }
  if (typeof candidates === 'string') candidates = [candidates];

  for (const raw of candidates) {
    if (!raw || typeof raw !== 'string') continue;
    const tag = raw.trim().replace(/_/g, '-');
    const lower = tag.toLowerCase();

    if (lower === 'zh-tw' || lower === 'zh-hk' || lower === 'zh-mo' || lower.startsWith('zh-hant')) {
      return 'zh-TW';
    }
    if (lower === 'zh' || lower === 'zh-cn' || lower === 'zh-sg' || lower.startsWith('zh-hans')) {
      return 'zh-CN';
    }
    if (lower === 'pt-br' || lower.startsWith('pt-br') || lower === 'pt') {
      return 'pt-BR';
    }

    const exact = SUPPORTED_LOCALES.find(l => l.code.toLowerCase() === lower);
    if (exact) return exact.code;

    const base = lower.split('-')[0];
    if (base === 'pt') return 'pt-BR';
    const byBase = SUPPORTED_LOCALES.find(l => l.code.toLowerCase() === base);
    if (byBase) return byBase.code;
  }

  return 'en';
}

export function interpolate(template, params) {
  if (!params || typeof template !== 'string') return template;
  return template.replace(/\{\{(\w+)\}\}/g, (_, key) =>
    Object.prototype.hasOwnProperty.call(params, key) && params[key] !== undefined ? String(params[key]) : ''
  );
}

class I18nManager {
  constructor() {
    this.preference = 'auto';
    this.locale = 'en';
    this._cache = { en };
    this._listeners = new Set();
    this._loadStorage();
  }

  _loadStorage() {
    try {
      if (typeof localStorage !== 'undefined') {
        const saved = localStorage.getItem(STORAGE_KEY);
        if (saved && (saved === 'auto' || SUPPORTED_SET.has(saved))) {
          this.preference = saved;
        }
      }
    } catch (_) {}
  }

  _saveStorage(pref) {
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(STORAGE_KEY, pref);
      }
    } catch (_) {}
  }

  resolveLocale(pref = this.preference) {
    if (pref === 'auto' || !SUPPORTED_SET.has(pref)) {
      return detectBrowserLocale();
    }
    return pref;
  }

  async loadLocale(code) {
    if (this._cache[code]) return this._cache[code];
    if (!SUPPORTED_SET.has(code)) return en;
    const mod = await import(`./locales/${code}.js`);
    this._cache[code] = mod.default || en;
    return this._cache[code];
  }

  async init() {
    const resolved = this.resolveLocale(this.preference);
    await this.loadLocale(resolved);
    this.locale = resolved;
    this.applyDom();
    return this.locale;
  }

  async setPreference(pref) {
    const normalized = pref === 'auto' || SUPPORTED_SET.has(pref) ? pref : 'auto';
    this.preference = normalized;
    this._saveStorage(normalized);

    const resolved = this.resolveLocale(normalized);
    await this.loadLocale(resolved);
    this.locale = resolved;
    this.applyDom();

    for (const cb of this._listeners) {
      try {
        cb(this.locale, this.preference);
      } catch (err) {
        console.warn('i18n listener error:', err);
      }
    }
    return this.locale;
  }

  onChange(cb) {
    this._listeners.add(cb);
    return () => this._listeners.delete(cb);
  }

  getNativeName(code = this.locale) {
    return SUPPORTED_LOCALES.find(l => l.code === code)?.nativeName || code;
  }

  t(key, params = null) {
    const dict = this._cache[this.locale] || en;
    const raw = Object.prototype.hasOwnProperty.call(dict, key)
      ? dict[key]
      : Object.prototype.hasOwnProperty.call(en, key)
        ? en[key]
        : key;
    return interpolate(raw, params);
  }

  formatNumber(value) {
    try {
      return new Intl.NumberFormat(this.locale).format(value);
    } catch (_) {
      return Number(value).toLocaleString();
    }
  }

  applyDom(root = typeof document !== 'undefined' ? document : null) {
    if (!root) return;

    const isDoc = (typeof document !== 'undefined' && root === document) || Boolean(root.documentElement);
    if (isDoc) {
      if (root.documentElement) root.documentElement.lang = this.locale;
      if ('title' in root) root.title = this.t('meta.title');
      const descMeta = root.querySelector ? root.querySelector('meta[name="description"]') : null;
      if (descMeta) descMeta.setAttribute('content', this.t('meta.description'));
    }

    const qsa = selector => (root.querySelectorAll ? root.querySelectorAll(selector) : []);

    qsa('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      if (key) el.textContent = this.t(key);
    });

    qsa('[data-i18n-title]').forEach(el => {
      const key = el.getAttribute('data-i18n-title');
      if (key) el.setAttribute('title', this.t(key));
    });

    qsa('[data-i18n-aria]').forEach(el => {
      const key = el.getAttribute('data-i18n-aria');
      if (key) el.setAttribute('aria-label', this.t(key));
    });

    qsa('[data-i18n-placeholder]').forEach(el => {
      const key = el.getAttribute('data-i18n-placeholder');
      if (key) el.setAttribute('placeholder', this.t(key));
    });

    qsa('[data-i18n-alt]').forEach(el => {
      const key = el.getAttribute('data-i18n-alt');
      if (key) el.setAttribute('alt', this.t(key));
    });

    const detectedLang = this.getNativeName(detectBrowserLocale());
    const autoText = this.t('topbar.langAuto', { lang: detectedLang });

    const btnLang = root.getElementById
      ? root.getElementById('btnLanguage')
      : root.querySelector
        ? root.querySelector('#btnLanguage')
        : null;
    if (btnLang) {
      const currentName = this.getNativeName(this.locale);
      const label = `${this.t('topbar.langAria')}: ${currentName}`;
      btnLang.setAttribute('title', label);
      btnLang.setAttribute('aria-label', label);
    }

    const langMenu = root.getElementById
      ? root.getElementById('langMenu')
      : root.querySelector
        ? root.querySelector('#langMenu')
        : null;
    if (langMenu) {
      langMenu.querySelectorAll('[data-lang]').forEach(opt => {
        const lang = opt.getAttribute('data-lang');
        if (lang === 'auto') {
          opt.textContent = autoText;
        }
        const isActive = lang === this.preference;
        opt.classList?.toggle('active', isActive);
        opt.setAttribute('aria-checked', String(isActive));
      });
    }

    const selLang = root.getElementById
      ? root.getElementById('selLanguage')
      : root.querySelector
        ? root.querySelector('#selLanguage')
        : null;
    if (selLang) {
      const autoOpt = selLang.querySelector ? selLang.querySelector('option[value="auto"]') : null;
      if (autoOpt) {
        autoOpt.textContent = autoText;
      }
      if (selLang.value !== this.preference) {
        selLang.value = this.preference;
      }
    }
  }
}

export const i18n = new I18nManager();
export const t = (key, params) => i18n.t(key, params);
export default i18n;
