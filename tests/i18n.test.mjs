import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  STORAGE_KEY,
  SUPPORTED_LOCALES,
  detectBrowserLocale,
  interpolate,
  i18n,
  t,
} from '../js/i18n/index.js';
import en from '../js/i18n/locales/en.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const EXPECTED_LOCALES = ['en', 'zh-CN', 'zh-TW', 'ja', 'ko', 'es', 'de', 'fr', 'pt-BR', 'ru'];
const REQUIRED_NAMESPACES = [
  'meta',
  'sidebar',
  'nav',
  'topbar',
  'models.opt',
  'perf',
  'buttons',
  'media',
  'lighting',
  'macros',
  'inspector',
  'firmware',
  'diagnostics',
  'compat',
  'errors',
  'toast',
];

function extractPlaceholders(str) {
  const matches = str.match(/\{\{(\w+)\}\}/g) || [];
  return [...new Set(matches)].sort();
}

function createMockElement(attrs = {}) {
  const attributes = new Map(Object.entries(attrs));
  const classes = new Set();
  return {
    textContent: '',
    value: attrs.value ?? '',
    classList: {
      toggle(name, force) {
        if (force === undefined) {
          if (classes.has(name)) classes.delete(name);
          else classes.add(name);
        } else if (force) {
          classes.add(name);
        } else {
          classes.delete(name);
        }
      },
      contains(name) {
        return classes.has(name);
      },
    },
    getAttribute(name) {
      return attributes.has(name) ? attributes.get(name) : null;
    },
    setAttribute(name, val) {
      attributes.set(name, String(val));
    },
  };
}

test('exports expected STORAGE_KEY and all 10 SUPPORTED_LOCALES', () => {
  assert.equal(STORAGE_KEY, 'valkyrie-control-lang');
  assert.equal(SUPPORTED_LOCALES.length, 10);
  assert.deepEqual(
    SUPPORTED_LOCALES.map(l => l.code),
    EXPECTED_LOCALES
  );
  for (const loc of SUPPORTED_LOCALES) {
    assert.ok(loc.nativeName && loc.nativeName.trim().length > 0);
  }
});

test('all 10 locales have identical key sets, placeholders, and clean Valkyrie unslop copy', async () => {
  const enKeys = Object.keys(en).sort();
  assert.ok(enKeys.length >= 160, `Expected full translation catalog, got ${enKeys.length} keys`);

  for (const ns of REQUIRED_NAMESPACES) {
    assert.ok(
      enKeys.some(k => k.startsWith(`${ns}.`)),
      `Expected namespace "${ns}.*" in en catalog`
    );
  }

  const dynamicFamilies = [
    ...[0, 1, 2, 3, 4, 5].map(n => `buttons.btn${n}`),
    ...[1, 2, 3, 4, 5].map(n => `buttons.mouse${n}`),
    ...[0, 1, 2, 3, 4, 5].map(n => `lighting.mode${n}`),
    'perf.lod1',
    'perf.lod2',
    'perf.lod3',
    'macros.badgeKeyDown',
    'macros.badgeKeyUp',
    'macros.badgeMouseDown',
    'macros.badgeMouseUp',
    'macros.badgeDelay',
  ];
  for (const key of dynamicFamilies) {
    assert.ok(Object.prototype.hasOwnProperty.call(en, key), `Missing dynamic key "${key}"`);
  }

  const emojiRegex = /[\p{Extended_Pictographic}\uFE0F]/u;
  const dareuRegex = /\bdareu\b|达尔优|達爾優/i;
  const labelOrButtonPrefixes = [
    'meta.brandName',
    'meta.brandSub',
    'sidebar.',
    'nav.',
    'topbar.',
    'models.opt.',
    'macros.badge',
    'media.',
  ];
  const labelOrButtonExact = new Set([
    'perf.addStage',
    'perf.removeStage',
    'perf.lockXY',
    'perf.unlock26k',
    'perf.factoryResetBtn',
    'buttons.refresh',
    'buttons.resetDefault',
    'buttons.clear',
    'buttons.applyHardware',
    'lighting.applyBtn',
    'macros.startRecording',
    'macros.stopRecording',
    'macros.clear',
    'macros.saveToMouse',
    'macros.export',
    'macros.import',
    'macros.addKey',
    'macros.addMouse',
    'macros.addDelay',
    'macros.removeStep',
    'inspector.refreshDump',
    'inspector.exportSnapshot',
    'inspector.importBaseline',
    'inspector.rollbackSafe',
    'inspector.rawSend',
    'inspector.clearConsole',
    'inspector.exportConsole',
    'firmware.specTransport',
    'firmware.transportWebHid',
    'firmware.transportLocalHelper',
    'firmware.transportTauri',
    'diagnostics.winCardTitle',
    'diagnostics.winCardBadge',
    'diagnostics.connectHelperBtn',
    'diagnostics.connectingHelperBtn',
    'diagnostics.openGuideBtn',
    'diagnostics.dismissAria',
    'diagnostics.wirelessWarnTitle',
    'compat.title',
    'compat.subtitle',
    'compat.desktopBtn',
    'compat.optionATitle',
    'compat.closeAria',
    'compat.whyTitle',
    'compat.osMatrixTitle',
    'compat.osWinHelper',
    'compat.osMacLinux',
    'compat.methodExeTitle',
    'compat.methodPyTitle',
    'compat.safetyTitle',
    'compat.connectBtn',
    'compat.closeBtn',
  ]);

  for (const { code } of SUPPORTED_LOCALES) {
    const mod = await import(`../js/i18n/locales/${code}.js`);
    const dict = mod.default;
    assert.ok(dict && typeof dict === 'object', `Locale ${code} must export default object`);

    const keys = Object.keys(dict).sort();
    const missing = enKeys.filter(k => !Object.prototype.hasOwnProperty.call(dict, k));
    const extra = keys.filter(k => !Object.prototype.hasOwnProperty.call(en, k));

    assert.deepEqual(missing, [], `Locale ${code} missing keys: ${missing.join(', ')}`);
    assert.deepEqual(extra, [], `Locale ${code} extra keys: ${extra.join(', ')}`);

    assert.ok(
      dict['models.opt.VK_M3_LITE'].includes('PAW3311'),
      `${code}[models.opt.VK_M3_LITE] must reference PAW3311`
    );
    assert.equal(
      dict['models.opt.VK_M3_LITE'].includes('PAW3395'),
      false,
      `${code}[models.opt.VK_M3_LITE] must not reference PAW3395`
    );
    assert.ok(
      dict['perf.unlock26k'].includes('PAW3311') && dict['perf.unlock26k'].includes('0x11'),
      `${code}[perf.unlock26k] must reference PAW3311 and curve 0x11`
    );

    for (const key of enKeys) {
      const val = dict[key];
      assert.equal(typeof val, 'string', `${code}[${key}] must be string`);
      assert.ok(val.trim().length > 0, `${code}[${key}] must not be empty`);
      assert.deepEqual(
        extractPlaceholders(val),
        extractPlaceholders(en[key]),
        `Placeholder mismatch in ${code}[${key}]: "${val}" vs "${en[key]}"`
      );
      assert.equal(emojiRegex.test(val), false, `Emoji not allowed in ${code}[${key}]: "${val}"`);
      assert.equal(val.includes('!'), false, `Exclamation mark not allowed in ${code}[${key}]: "${val}"`);
      assert.equal(dareuRegex.test(val), false, `Dareu reference found in ${code}[${key}]: "${val}"`);
      assert.equal(
        /chromium\s*151/i.test(val),
        false,
        `Stale Chromium 151 workaround reference found in ${code}[${key}]: "${val}"`
      );

      if (
        labelOrButtonExact.has(key) ||
        labelOrButtonPrefixes.some(prefix => key.startsWith(prefix))
      ) {
        assert.equal(
          /[.。]$/.test(val.trim()),
          false,
          `Label/button ${code}[${key}] must not have trailing period: "${val}"`
        );
      }
    }
  }
});

test('detectBrowserLocale handles exact tags, regional variants, strings, and fallbacks', () => {
  assert.equal(detectBrowserLocale(['zh-TW', 'en-US']), 'zh-TW');
  assert.equal(detectBrowserLocale(['zh-HK']), 'zh-TW');
  assert.equal(detectBrowserLocale(['zh-MO']), 'zh-TW');
  assert.equal(detectBrowserLocale(['zh-Hant-TW']), 'zh-TW');
  assert.equal(detectBrowserLocale(['zh-CN']), 'zh-CN');
  assert.equal(detectBrowserLocale(['zh-SG']), 'zh-CN');
  assert.equal(detectBrowserLocale(['zh-Hans-CN']), 'zh-CN');
  assert.equal(detectBrowserLocale(['zh']), 'zh-CN');
  assert.equal(detectBrowserLocale(['ja-JP']), 'ja');
  assert.equal(detectBrowserLocale(['ko_KR']), 'ko');
  assert.equal(detectBrowserLocale(['es-419']), 'es');
  assert.equal(detectBrowserLocale(['de-DE']), 'de');
  assert.equal(detectBrowserLocale(['fr-FR']), 'fr');
  assert.equal(detectBrowserLocale(['pt-BR']), 'pt-BR');
  assert.equal(detectBrowserLocale(['pt-PT']), 'pt-BR');
  assert.equal(detectBrowserLocale(['pt']), 'pt-BR');
  assert.equal(detectBrowserLocale(['ru-RU']), 'ru');
  assert.equal(detectBrowserLocale(['en-GB']), 'en');
  assert.equal(detectBrowserLocale(['nl-NL']), 'en');
  assert.equal(detectBrowserLocale(['fr-FR', 'en-US']), 'fr');
  assert.equal(detectBrowserLocale('ko-KR'), 'ko');
  assert.equal(detectBrowserLocale([]), 'en');
});

test('interpolate replaces known placeholders and blanks missing ones', () => {
  assert.equal(interpolate('Stage {{n}} · {{hz}} Hz', { n: 2, hz: 4000 }), 'Stage 2 · 4000 Hz');
  assert.equal(interpolate('Missing {{x}}!', {}), 'Missing !');
  assert.equal(interpolate(null, { x: 1 }), null);
});

test('i18n runtime handles preferences, fallbacks, listeners, and t()', async () => {
  const events = [];
  const unsub = i18n.onChange((loc, pref) => events.push({ loc, pref }));

  await i18n.setPreference('ja');
  assert.equal(i18n.locale, 'ja');
  assert.equal(i18n.preference, 'ja');
  assert.notEqual(t('nav.performance'), 'Performance');
  assert.equal(t('toast.connected', { name: 'VK M3 Lite' }), '接続しました: VK M3 Lite');

  // Fallback to en if a key exists only in en, and return key if missing everywhere
  assert.equal(t('nonexistent.translation.key'), 'nonexistent.translation.key');
  const prevCache = i18n._cache.ja;
  i18n._cache.ja = { 'nav.performance': prevCache['nav.performance'] };
  assert.equal(t('nav.buttons'), en['nav.buttons']);
  i18n._cache.ja = prevCache;

  // Invalid preference normalizes to 'auto'
  await i18n.setPreference('xx-INVALID');
  assert.equal(i18n.preference, 'auto');

  await i18n.setPreference('de');
  assert.equal(i18n.locale, 'de');
  assert.equal(i18n.getNativeName('pt-BR'), 'Português (BR)');
  assert.ok(i18n.formatNumber(26000).length > 0);

  unsub();
  const countAfterUnsub = events.length;
  await i18n.setPreference('en');
  assert.equal(events.length, countAfterUnsub);
  assert.equal(i18n.locale, 'en');
});

test('applyDom updates document metadata, data-i18n attributes, and language controls', async () => {
  const metaDesc = createMockElement();
  const textEl = createMockElement({ 'data-i18n': 'nav.inspector' });
  const titleEl = createMockElement({ 'data-i18n-title': 'topbar.batteryTitle' });
  const ariaEl = createMockElement({ 'data-i18n-aria': 'topbar.menuAria' });
  const placeholderEl = createMockElement({ 'data-i18n-placeholder': 'buttons.capturePlaceholder' });
  const altEl = createMockElement({ 'data-i18n-alt': 'buttons.schematicAlt' });
  const btnLanguage = createMockElement();

  const optAuto = createMockElement({ 'data-lang': 'auto' });
  const optEn = createMockElement({ 'data-lang': 'en' });
  const optKo = createMockElement({ 'data-lang': 'ko' });
  const langMenu = {
    querySelectorAll(sel) {
      return sel === '[data-lang]' ? [optAuto, optEn, optKo] : [];
    },
  };

  const selAutoOpt = createMockElement({ value: 'auto' });
  const selLanguage = {
    value: 'auto',
    querySelector(sel) {
      return sel === 'option[value="auto"]' ? selAutoOpt : null;
    },
  };

  const mockRoot = {
    documentElement: { lang: 'en' },
    title: '',
    querySelector(sel) {
      if (sel === 'meta[name="description"]') return metaDesc;
      return null;
    },
    querySelectorAll(sel) {
      switch (sel) {
        case '[data-i18n]':
          return [textEl];
        case '[data-i18n-title]':
          return [titleEl];
        case '[data-i18n-aria]':
          return [ariaEl];
        case '[data-i18n-placeholder]':
          return [placeholderEl];
        case '[data-i18n-alt]':
          return [altEl];
        default:
          return [];
      }
    },
    getElementById(id) {
      if (id === 'btnLanguage') return btnLanguage;
      if (id === 'langMenu') return langMenu;
      if (id === 'selLanguage') return selLanguage;
      return null;
    },
  };

  await i18n.setPreference('ko');
  i18n.applyDom(mockRoot);

  assert.equal(mockRoot.documentElement.lang, 'ko');
  assert.equal(mockRoot.title, t('meta.title'));
  assert.equal(metaDesc.getAttribute('content'), t('meta.description'));
  assert.equal(textEl.textContent, t('nav.inspector'));
  assert.equal(titleEl.getAttribute('title'), t('topbar.batteryTitle'));
  assert.equal(ariaEl.getAttribute('aria-label'), t('topbar.menuAria'));
  assert.equal(placeholderEl.getAttribute('placeholder'), t('buttons.capturePlaceholder'));
  assert.equal(altEl.getAttribute('alt'), t('buttons.schematicAlt'));
  assert.equal(btnLanguage.getAttribute('aria-label'), `${t('topbar.langAria')}: 한국어`);
  assert.equal(optKo.classList.contains('active'), true);
  assert.equal(optKo.getAttribute('aria-checked'), 'true');
  assert.equal(optEn.classList.contains('active'), false);
  assert.equal(optEn.getAttribute('aria-checked'), 'false');
  assert.equal(selLanguage.value, 'ko');
  const detectedNative = i18n.getNativeName(detectBrowserLocale());
  assert.ok(selAutoOpt.textContent.includes(detectedNative));
  assert.equal(optAuto.textContent, t('topbar.langAuto', { lang: detectedNative }));

  await i18n.setPreference('en');
});

test('validate HTML and JS key references if UI modules are present', async () => {
  const candidates = ['index.html', 'js/app.js', 'js/hid/webhid-manager.js'];
  for (const rel of candidates) {
    const full = path.join(ROOT, rel);
    let content;
    try {
      content = await fs.readFile(full, 'utf8');
    } catch {
      continue;
    }

    if (rel.endsWith('.html')) {
      const htmlRegex = /data-i18n(?:-(?:title|aria|placeholder|alt))?="([^"]+)"/g;
      let match;
      while ((match = htmlRegex.exec(content)) !== null) {
        const key = match[1];
        assert.ok(
          Object.prototype.hasOwnProperty.call(en, key),
          `${rel} references missing i18n key "${key}"`
        );
      }
    } else {
      const tRegex = /\bt\(\s*'([^']+)'/g;
      let match;
      while ((match = tRegex.exec(content)) !== null) {
        const key = match[1];
        assert.ok(
          Object.prototype.hasOwnProperty.call(en, key),
          `${rel} references missing i18n key "${key}"`
        );
      }
    }
  }
});
