/**
 * Valkyrie M220 / E023 Macro Compiler, Keycode Tables & Button Action Codecs
 *
 * Implements:
 * - Windows VK / DOM KeyboardEvent.code / HID Usage conversion matching
 *   `ProtocolData::GetFlashKeyCode` and `ProtocolData::GetSysKeyCode`
 * - 4-byte hardware macro stream encoding `[op, delayLo, delayHi, code]` with
 *   1-byte prepended `keyIdx`, little-endian inter-event delay stored on the
 *   PREVIOUS event (minimum/default `1` ms), trailing delay on final event, and
 *   fixed Win-key (`0x5B`/`0x5D`) release opcode (`0xA0` instead of buggy `0x20`)
 * - 27-byte `0x08` multi-chunk framing `[0x08, 0x00, (idx << 4) | total, chunkLen, ...data]`
 * - Button action descriptor `[b0, b1, b2]` encode/decode for `0x11` / `0x09`
 */

export const MACRO_OPS = {
  MOUSE_DOWN: 0x10,
  MOUSE_UP: 0x90,
  MOD_DOWN: 0x20,
  MOD_UP: 0xA0,
  KEY_DOWN: 0x30,
  KEY_UP: 0xB0,
};

export const MOUSE_BUTTON_MASKS = {
  left: 0x01,
  right: 0x02,
  middle: 0x04,
  back: 0x08,
  forward: 0x10,
};

export const BUTTON_ID_TO_MASK = {
  1: 0x01, // Left
  2: 0x02, // Right
  3: 0x04, // Middle
  4: 0x08, // Back
  5: 0x10, // Forward
};

export const MASK_TO_BUTTON_ID = {
  0x01: 1,
  0x02: 2,
  0x04: 3,
  0x08: 4,
  0x10: 5,
};

/**
 * Standard USB HID Keyboard/Keypad usage table (Page 0x07), matching
 * `ProtocolData::GetFlashKeyCode` output.
 */
export const USB_HID_KEYMAP = {
  // Letters (0x04 - 0x1D)
  KeyA: 0x04, KeyB: 0x05, KeyC: 0x06, KeyD: 0x07, KeyE: 0x08, KeyF: 0x09,
  KeyG: 0x0A, KeyH: 0x0B, KeyI: 0x0C, KeyJ: 0x0D, KeyK: 0x0E, KeyL: 0x0F,
  KeyM: 0x10, KeyN: 0x11, KeyO: 0x12, KeyP: 0x13, KeyQ: 0x14, KeyR: 0x15,
  KeyS: 0x16, KeyT: 0x17, KeyU: 0x18, KeyV: 0x19, KeyW: 0x1A, KeyX: 0x1B,
  KeyY: 0x1C, KeyZ: 0x1D,

  // Digits (0x1E - 0x27)
  Digit1: 0x1E, Digit2: 0x1F, Digit3: 0x20, Digit4: 0x21, Digit5: 0x22,
  Digit6: 0x23, Digit7: 0x24, Digit8: 0x25, Digit9: 0x26, Digit0: 0x27,

  // Controls & punctuation (0x28 - 0x38)
  Enter: 0x28, Escape: 0x29, Backspace: 0x2A, Tab: 0x2B, Space: 0x2C,
  Minus: 0x2D, Equal: 0x2E, BracketLeft: 0x2F, BracketRight: 0x30,
  Backslash: 0x31, NonUsHash: 0x32, Semicolon: 0x33, Quote: 0x34,
  Backquote: 0x35, Comma: 0x36, Period: 0x37, Slash: 0x38, CapsLock: 0x39,

  // Function keys F1-F12 (0x3A - 0x45)
  F1: 0x3A, F2: 0x3B, F3: 0x3C, F4: 0x3D, F5: 0x3E, F6: 0x3F,
  F7: 0x40, F8: 0x41, F9: 0x42, F10: 0x43, F11: 0x44, F12: 0x45,

  // Navigation & System (0x46 - 0x52)
  PrintScreen: 0x46, ScrollLock: 0x47, Pause: 0x48, Insert: 0x49,
  Home: 0x4A, PageUp: 0x4B, Delete: 0x4C, End: 0x4D, PageDown: 0x4E,
  ArrowRight: 0x4F, ArrowLeft: 0x50, ArrowDown: 0x51, ArrowUp: 0x52,

  // Numpad (0x53 - 0x63)
  NumLock: 0x53, NumpadDivide: 0x54, NumpadMultiply: 0x55,
  NumpadSubtract: 0x56, NumpadAdd: 0x57, NumpadEnter: 0x58,
  Numpad1: 0x59, Numpad2: 0x5A, Numpad3: 0x5B, Numpad4: 0x5C,
  Numpad5: 0x5D, Numpad6: 0x5E, Numpad7: 0x5F, Numpad8: 0x60,
  Numpad9: 0x61, Numpad0: 0x62, NumpadDecimal: 0x63,
  IntlBackslash: 0x64, ContextMenu: 0x65, Power: 0x66, NumpadEqual: 0x67,
  F13: 0x68, F14: 0x69, F15: 0x6A, F16: 0x6B, F17: 0x6C, F18: 0x6D,
  F19: 0x6E, F20: 0x6F, F21: 0x70, F22: 0x71, F23: 0x72, F24: 0x73,

  // Modifiers (0xE0 - 0xE7)
  ControlLeft: 0xE0,
  ShiftLeft: 0xE1,
  AltLeft: 0xE2,
  MetaLeft: 0xE3,
  OSLeft: 0xE3,
  ControlRight: 0xE4,
  ShiftRight: 0xE5,
  AltRight: 0xE6,
  MetaRight: 0xE7,
  OSRight: 0xE7,
};

export const CODE_TO_HID = USB_HID_KEYMAP;

/**
 * Legacy DOM `KeyboardEvent.keyCode` -> USB HID usage fallback map.
 */
export const JS_KEY_TO_HID = {
  8: 0x2A, 9: 0x2B, 13: 0x28, 16: 0xE1, 17: 0xE0, 18: 0xE2,
  19: 0x48, 20: 0x39, 27: 0x29, 32: 0x2C, 33: 0x4B, 34: 0x4E,
  35: 0x4D, 36: 0x4A, 37: 0x50, 38: 0x52, 39: 0x4F, 40: 0x51,
  45: 0x49, 46: 0x4C,
  48: 0x27, 49: 0x1E, 50: 0x1F, 51: 0x20, 52: 0x21, 53: 0x22,
  54: 0x23, 55: 0x24, 56: 0x25, 57: 0x26,
  65: 0x04, 66: 0x05, 67: 0x06, 68: 0x07, 69: 0x08, 70: 0x09,
  71: 0x0A, 72: 0x0B, 73: 0x0C, 74: 0x0D, 75: 0x0E, 76: 0x0F,
  77: 0x10, 78: 0x11, 79: 0x12, 80: 0x13, 81: 0x14, 82: 0x15,
  83: 0x16, 84: 0x17, 85: 0x18, 86: 0x19, 87: 0x1A, 88: 0x1B,
  89: 0x1C, 90: 0x1D,
  91: 0xE3, 92: 0xE7, 93: 0x65,
  96: 0x62, 97: 0x59, 98: 0x5A, 99: 0x5B, 100: 0x5C, 101: 0x5D,
  102: 0x5E, 103: 0x5F, 104: 0x60, 105: 0x61, 106: 0x55, 107: 0x57,
  109: 0x56, 110: 0x63, 111: 0x54,
  112: 0x3A, 113: 0x3B, 114: 0x3C, 115: 0x3D, 116: 0x3E, 117: 0x3F,
  118: 0x40, 119: 0x41, 120: 0x42, 121: 0x43, 122: 0x44, 123: 0x45,
  144: 0x53, 145: 0x47,
  160: 0xE1, 161: 0xE5, 162: 0xE0, 163: 0xE4, 164: 0xE2, 165: 0xE6,
  186: 0x33, 187: 0x2E, 188: 0x36, 189: 0x2D, 190: 0x37, 191: 0x38,
  192: 0x35, 219: 0x2F, 220: 0x31, 221: 0x30, 222: 0x34,
};

/**
 * Windows Virtual-Key (VK) modifier codes -> HID modifier bitmap (`0x01..0x80`),
 * matching `ProtocolData::GetSysKeyCode`.
 */
export const VK_TO_MOD_MASK = {
  0xA2: 0x01, // VK_LCONTROL
  0x11: 0x01, // VK_CONTROL (generic -> LCtrl)
  0xA0: 0x02, // VK_LSHIFT
  0x10: 0x02, // VK_SHIFT (generic -> LShift)
  0xA4: 0x04, // VK_LMENU (LAlt)
  0x12: 0x04, // VK_MENU (generic -> LAlt)
  0x5B: 0x08, // VK_LWIN
  0xA3: 0x10, // VK_RCONTROL
  0xA1: 0x20, // VK_RSHIFT
  0xA5: 0x40, // VK_RMENU (RAlt)
  0x5D: 0x80, // VK_RWIN (also VK_APPS in some contexts; handled carefully below)
  0x5C: 0x80, // VK_RWIN standard Win32 VK
};

export const HID_TO_MOD_MASK = {
  0xE0: 0x01,
  0xE1: 0x02,
  0xE2: 0x04,
  0xE3: 0x08,
  0xE4: 0x10,
  0xE5: 0x20,
  0xE6: 0x40,
  0xE7: 0x80,
};

export const MOD_MASK_TO_HID = {
  0x01: 0xE0,
  0x02: 0xE1,
  0x04: 0xE2,
  0x08: 0xE3,
  0x10: 0xE4,
  0x20: 0xE5,
  0x40: 0xE6,
  0x80: 0xE7,
};

export const VK_TO_FLASH_HID = {
  ...JS_KEY_TO_HID,
  0x5B: 0xE3, // VK_LWIN
  0x5C: 0xE7, // VK_RWIN (Win32)
  0x5D: 0xE7, // VK_RWIN / RWin in VK M3 Series disassembly (0x5B/0x5D check)
  0xA0: 0xE1, // VK_LSHIFT
  0xA1: 0xE5, // VK_RSHIFT
  0xA2: 0xE0, // VK_LCONTROL
  0xA3: 0xE4, // VK_RCONTROL
  0xA4: 0xE2, // VK_LMENU
  0xA5: 0xE6, // VK_RMENU
};

/**
 * Consumer Media HID usages (Page 0x0C) mapped to `[0x80, lo, hi]`, matching
 * `SetMouseKeyMacroData` `func_type=3` and `func_type=8` items 1..6.
 */
export const MEDIA_KEYS = {
  player: 0x0183,
  play_pause: 0x00CD,
  stop_media: 0x00B7,
  prev_track: 0x00B6,
  next_track: 0x00B5,
  vol_up: 0x00E9,
  vol_down: 0x00EA,
  mute: 0x00E2,
  brightness_up: 0x006F,
  brightness_down: 0x0070,
  calculator: 0x0192,
  my_computer: 0x0194,
  browser_home: 0x0223,
  email: 0x018A,
  browser_back: 0x0224,
  browser_forward: 0x0225,
  browser_refresh: 0x0227,
};

export const MEDIA_USAGE_TO_NAME = Object.fromEntries(
  Object.entries(MEDIA_KEYS).map(([name, usage]) => [usage, name]),
);

/**
 * Reverse lookup HID usage -> canonical DOM `code`.
 */
export const HID_TO_CODE = (() => {
  const map = {};
  for (const [code, hid] of Object.entries(USB_HID_KEYMAP)) {
    if (map[hid] === undefined) {
      map[hid] = code;
    }
  }
  return map;
})();

/**
 * Determine whether a Win32 VK code is one of the modifier VKs checked in
 * `GetMouseMacroData` (`0xA0..0xA7`, `0x5B`, `0x5D`).
 * @param {number} vk
 * @returns {boolean}
 */
export function isModifierVk(vk) {
  return (vk >= 0xA0 && vk <= 0xA7) || vk === 0x5B || vk === 0x5C || vk === 0x5D || vk === 0x10 || vk === 0x11 || vk === 0x12;
}

/**
 * Determine whether a USB HID usage is a modifier (`0xE0..0xE7`).
 * @param {number} hid
 * @returns {boolean}
 */
export function isModifierHid(hid) {
  return hid >= 0xE0 && hid <= 0xE7;
}

/**
 * Convert a Win32 Virtual-Key code, DOM `event.code`, or HID usage to the
 * 1-byte Flash HID keycode (`ProtocolData::GetFlashKeyCode`).
 * @param {number|string} input
 * @returns {number}
 */
export function getFlashKeyCode(input) {
  if (typeof input === 'string') {
    if (USB_HID_KEYMAP[input] !== undefined) return USB_HID_KEYMAP[input];
    const trimmed = input.trim();
    if (USB_HID_KEYMAP[trimmed] !== undefined) return USB_HID_KEYMAP[trimmed];
    if (/^[a-zA-Z]$/.test(trimmed)) {
      return USB_HID_KEYMAP[`Key${trimmed.toUpperCase()}`] || 0;
    }
    if (/^[0-9]$/.test(trimmed)) {
      return USB_HID_KEYMAP[`Digit${trimmed}`] || 0;
    }
    const numeric = Number(trimmed);
    if (Number.isFinite(numeric) && numeric > 0) return getFlashKeyCode(numeric);
    return 0;
  }
  const n = Number(input);
  if (!Number.isFinite(n) || n <= 0) return 0;
  if (VK_TO_FLASH_HID[n] !== undefined) return VK_TO_FLASH_HID[n];
  return n & 0xFF;
}

/**
 * Convert a Win32 modifier VK (`0xA0..0xA5`, `0x5B`, `0x5C`, `0x5D`) or HID
 * modifier (`0xE0..0xE7`) or DOM modifier code (`ControlLeft`..`MetaRight`)
 * into its 8-bit modifier bitmap (`0x01..0x80`, matching `ProtocolData::GetSysKeyCode`).
 * @param {number|string} input
 * @returns {number}
 */
export function getSysKeyCode(input) {
  if (typeof input === 'string') {
    const hid = USB_HID_KEYMAP[input.trim()];
    if (hid !== undefined && HID_TO_MOD_MASK[hid] !== undefined) {
      return HID_TO_MOD_MASK[hid];
    }
    return 0;
  }
  const n = Number(input);
  if (!Number.isFinite(n)) return 0;
  if (VK_TO_MOD_MASK[n] !== undefined) return VK_TO_MOD_MASK[n];
  if (HID_TO_MOD_MASK[n] !== undefined) return HID_TO_MOD_MASK[n];
  if (n >= 0xA6 && n <= 0xA7) return 0x40;
  return 0;
}

/**
 * Resolve a DOM `KeyboardEvent`-like object or key spec into `{ hid, isModifier, modMask, vk, label }`.
 * @param {object|number|string} keyInput
 * @returns {{hid: number, isModifier: boolean, modMask: number, code: string|null, label: string}}
 */
export function resolveKeySpec(keyInput) {
  if (keyInput && typeof keyInput === 'object') {
    if (Number.isInteger(keyInput.vk) && keyInput.vk > 0) {
      const modMask = getSysKeyCode(keyInput.vk);
      if (modMask && isModifierVk(keyInput.vk)) {
        const hid = MOD_MASK_TO_HID[modMask] || getFlashKeyCode(keyInput.vk);
        return {
          hid,
          isModifier: true,
          modMask,
          code: HID_TO_CODE[hid] || null,
          label: HID_TO_CODE[hid] || `0x${hid.toString(16).toUpperCase()}`,
        };
      }
      const hid = getFlashKeyCode(keyInput.vk);
      return {
        hid,
        isModifier: isModifierHid(hid),
        modMask: isModifierHid(hid) ? getSysKeyCode(hid) : 0,
        code: HID_TO_CODE[hid] || null,
        label: HID_TO_CODE[hid] || `0x${hid.toString(16).toUpperCase()}`,
      };
    }

    if (typeof keyInput.code === 'string' && USB_HID_KEYMAP[keyInput.code] !== undefined) {
      const hid = USB_HID_KEYMAP[keyInput.code];
      const modMask = HID_TO_MOD_MASK[hid] || 0;
      return {
        hid,
        isModifier: modMask !== 0,
        modMask,
        code: keyInput.code,
        label: keyInput.code,
      };
    }

    if (Number.isInteger(keyInput.hid) && keyInput.hid > 0) {
      const hid = keyInput.hid & 0xFF;
      const modMask = HID_TO_MOD_MASK[hid] || 0;
      return {
        hid,
        isModifier: modMask !== 0,
        modMask,
        code: HID_TO_CODE[hid] || null,
        label: HID_TO_CODE[hid] || `0x${hid.toString(16).toUpperCase()}`,
      };
    }

    if (Number.isInteger(keyInput.modMask) && keyInput.modMask > 0) {
      const modMask = keyInput.modMask & 0xFF;
      const hid = MOD_MASK_TO_HID[modMask] || 0;
      return {
        hid,
        isModifier: true,
        modMask,
        code: HID_TO_CODE[hid] || null,
        label: HID_TO_CODE[hid] || `Mod 0x${modMask.toString(16).toUpperCase()}`,
      };
    }

    if (Number.isInteger(keyInput.keyCode) && JS_KEY_TO_HID[keyInput.keyCode]) {
      const hid = JS_KEY_TO_HID[keyInput.keyCode];
      const modMask = HID_TO_MOD_MASK[hid] || 0;
      return {
        hid,
        isModifier: modMask !== 0,
        modMask,
        code: HID_TO_CODE[hid] || null,
        label: HID_TO_CODE[hid] || `0x${hid.toString(16).toUpperCase()}`,
      };
    }
  }

  if (typeof keyInput === 'string') {
    const trimmed = keyInput.trim();
    if (USB_HID_KEYMAP[trimmed] !== undefined) {
      const hid = USB_HID_KEYMAP[trimmed];
      const modMask = HID_TO_MOD_MASK[hid] || 0;
      return { hid, isModifier: modMask !== 0, modMask, code: trimmed, label: trimmed };
    }
    const hid = getFlashKeyCode(trimmed);
    const modMask = HID_TO_MOD_MASK[hid] || 0;
    return {
      hid,
      isModifier: modMask !== 0,
      modMask,
      code: HID_TO_CODE[hid] || null,
      label: HID_TO_CODE[hid] || trimmed,
    };
  }

  if (Number.isInteger(keyInput) && keyInput > 0) {
    const modMask = HID_TO_MOD_MASK[keyInput] || 0;
    return {
      hid: keyInput & 0xFF,
      isModifier: modMask !== 0,
      modMask,
      code: HID_TO_CODE[keyInput] || null,
      label: HID_TO_CODE[keyInput] || `0x${keyInput.toString(16).toUpperCase()}`,
    };
  }

  return { hid: 0, isModifier: false, modMask: 0, code: null, label: '' };
}

/**
 * Compile high-level macro events into the raw firmware byte stream:
 *   `[keyIdx, op0, delayLo0, delayHi0, code0, ...]`
 *
 * Delay semantics match `GetMouseMacroData` (`disasm_macro_dpi.txt`):
 * - Each hardware event defaults its trailing inter-event delay to `1` ms (`0x01, 0x00`).
 * - Delay steps (`type: 'delay'`) or explicit `delayMs` accumulate and overwrite the
 *   PREVIOUS hardware event's `[delayLo, delayHi]` (little-endian uint16, clamped `1..65535`).
 * - Trailing delay steps after the final hardware event are written to the final event.
 * - Modifier keys (`VK_LWIN=0x5B`, `VK_RWIN=0x5D`/`0x5C`, `VK_LCONTROL`..`VK_RMENU`, `0xE0..0xE7`)
 *   use `0x20` (`MOD_DOWN`) on press and **`0xA0` (`MOD_UP`) on release**, fixing the official
 *   driver's `0x5B`/`0x5D` release jump bug.
 *
 * Supported input event shapes:
 * - `{ type: 'delay', delayMs: 50 }` (or `ms` / `duration`)
 * - `{ type: 'keyDown' | 'keyUp', code?, hid?, vk?, modMask?, delayMs? }`
 * - `{ type: 'mouseDown' | 'mouseUp', button: 1..5 | 'left'|'right'|'middle'|'back'|'forward', mask?, delayMs? }`
 *
 * @param {Array<object>} events
 * @param {number} [keyIdx=0]
 * @returns {Uint8Array}
 */
export function compileMacroStream(events, keyIdx = 0) {
  if (!Array.isArray(events)) {
    throw new TypeError('Macro events must be an array');
  }

  const encoded = [];
  let pendingDelay = 0;

  const commitDelayToPrevious = (delayValue) => {
    if (encoded.length === 0) return;
    const clamped = Math.max(1, Math.min(0xFFFF, Math.round(delayValue || 1)));
    const prevIdx = encoded.length - 1;
    encoded[prevIdx][1] = clamped & 0xFF;
    encoded[prevIdx][2] = (clamped >> 8) & 0xFF;
  };

  for (const ev of events) {
    if (!ev || typeof ev !== 'object') continue;
    const kind = ev.type;

    if (kind === 'delay') {
      const ms = Number(ev.delayMs ?? ev.ms ?? ev.duration ?? ev.value ?? 0);
      if (Number.isFinite(ms) && ms > 0) {
        pendingDelay += ms;
      }
      continue;
    }

    let op = 0;
    let code = 0;

    if (kind === 'keyDown' || kind === 'keyUp') {
      const isDown = kind === 'keyDown';
      const resolved = resolveKeySpec(ev);
      if (resolved.isModifier && resolved.modMask > 0) {
        op = isDown ? MACRO_OPS.MOD_DOWN : MACRO_OPS.MOD_UP;
        code = resolved.modMask & 0xFF;
      } else {
        if (!resolved.hid) {
          throw new Error(`Unable to resolve HID keycode for macro step: ${JSON.stringify(ev)}`);
        }
        op = isDown ? MACRO_OPS.KEY_DOWN : MACRO_OPS.KEY_UP;
        code = resolved.hid & 0xFF;
      }
    } else if (kind === 'mouseDown' || kind === 'mouseUp') {
      const isDown = kind === 'mouseDown';
      op = isDown ? MACRO_OPS.MOUSE_DOWN : MACRO_OPS.MOUSE_UP;
      if (Number.isInteger(ev.mask) && ev.mask > 0) {
        code = ev.mask & 0xFF;
      } else if (typeof ev.button === 'string' && MOUSE_BUTTON_MASKS[ev.button.toLowerCase()]) {
        code = MOUSE_BUTTON_MASKS[ev.button.toLowerCase()];
      } else if (BUTTON_ID_TO_MASK[ev.button]) {
        code = BUTTON_ID_TO_MASK[ev.button];
      } else {
        code = Number(ev.button || 1) & 0xFF;
      }
    } else {
      throw new Error(`Unsupported macro event type: ${String(kind)}`);
    }

    if (encoded.length > 0 && pendingDelay > 0) {
      commitDelayToPrevious(pendingDelay);
    }
    pendingDelay = 0;

    const inlineDelay = Number(ev.delayMs ?? ev.delay ?? 1);
    const clampedInline = Math.max(1, Math.min(0xFFFF, Math.round(Number.isFinite(inlineDelay) ? inlineDelay : 1)));
    encoded.push([op, clampedInline & 0xFF, (clampedInline >> 8) & 0xFF, code]);
  }

  if (encoded.length > 0 && pendingDelay > 0) {
    commitDelayToPrevious(pendingDelay);
  }

  const out = new Uint8Array(1 + encoded.length * 4);
  out[0] = keyIdx & 0xFF;
  for (let i = 0; i < encoded.length; i += 1) {
    const base = 1 + i * 4;
    out[base] = encoded[i][0];
    out[base + 1] = encoded[i][1];
    out[base + 2] = encoded[i][2];
    out[base + 3] = encoded[i][3];
  }
  return out;
}

/**
 * Frame a compiled macro stream (or raw events array) into 32-byte `0x08` write
 * packets with 27-byte chunks:
 *   `[0x08, 0x00, (chunkIdx << 4) | totalChunks, chunkLen, ...data, checksum]`
 *
 * @param {number} keyIdx
 * @param {Array<object>|Uint8Array} eventsOrStream
 * @returns {Array<Uint8Array>}
 */
export function frameMacroChunks(keyIdx, eventsOrStream) {
  const stream = eventsOrStream instanceof Uint8Array
    ? eventsOrStream
    : compileMacroStream(eventsOrStream, keyIdx);

  const totalChunks = Math.max(1, Math.ceil(stream.length / 27));
  if (totalChunks > 15) {
    throw new RangeError(
      `Macro byte stream (${stream.length} B, ${totalChunks} chunks) exceeds 4-bit chunk limit (max 15 chunks / 405 B)`
    );
  }

  const packets = [];
  for (let idx = 0; idx < totalChunks; idx += 1) {
    const start = idx * 27;
    const slice = stream.subarray(start, Math.min(start + 27, stream.length));
    const pkt = new Uint8Array(32);
    pkt[0] = 0x08;
    pkt[1] = 0x00;
    pkt[2] = ((idx & 0x0F) << 4) | (totalChunks & 0x0F);
    pkt[3] = slice.length;
    pkt.set(slice, 4);

    let sum = 0;
    for (let b = 4; b <= 30; b += 1) {
      sum = (sum + pkt[b]) & 0xFF;
    }
    pkt[31] = sum;
    packets.push(pkt);
  }
  return packets;
}

/**
 * Alias matching UI/inspector naming.
 */
export const compileMacroPackets = frameMacroChunks;

/**
 * Decode a raw macro byte stream `[keyIdx, ...4B events]` back into structured events.
 * @param {Uint8Array|Array<number>} streamBytes
 * @returns {{ keyIdx: number, events: Array<object> }}
 */
export function decompileMacroStream(streamBytes) {
  const bytes = streamBytes instanceof Uint8Array ? streamBytes : Uint8Array.from(streamBytes);
  if (bytes.length === 0) {
    return { keyIdx: 0, events: [] };
  }
  const keyIdx = bytes[0];
  const events = [];

  for (let i = 1; i + 3 < bytes.length; i += 4) {
    const op = bytes[i];
    const delayMs = bytes[i + 1] | (bytes[i + 2] << 8);
    const code = bytes[i + 3];

    if (op === MACRO_OPS.KEY_DOWN || op === MACRO_OPS.KEY_UP) {
      events.push({
        type: op === MACRO_OPS.KEY_DOWN ? 'keyDown' : 'keyUp',
        hid: code,
        code: HID_TO_CODE[code] || `HID_0x${code.toString(16).toUpperCase()}`,
        delayMs,
      });
    } else if (op === MACRO_OPS.MOD_DOWN || op === MACRO_OPS.MOD_UP) {
      const hid = MOD_MASK_TO_HID[code] ?? (isModifierHid(code) ? code : 0);
      events.push({
        type: op === MACRO_OPS.MOD_DOWN ? 'keyDown' : 'keyUp',
        isModifier: true,
        modMask: HID_TO_MOD_MASK[code] ? HID_TO_MOD_MASK[code] : code,
        hid,
        code: HID_TO_CODE[hid] || `MOD_0x${code.toString(16).toUpperCase()}`,
        delayMs,
      });
    } else if (op === MACRO_OPS.MOUSE_DOWN || op === MACRO_OPS.MOUSE_UP) {
      events.push({
        type: op === MACRO_OPS.MOUSE_DOWN ? 'mouseDown' : 'mouseUp',
        mask: code,
        button: MASK_TO_BUTTON_ID[code] || code,
        delayMs,
      });
    }

    if (delayMs > 1) {
      events.push({ type: 'delay', delayMs });
    }
  }

  return { keyIdx, events };
}

/**
 * Reassemble and decompile `0x08` 32-byte packet frames.
 * @param {Array<Uint8Array>} packets
 * @returns {{ keyIdx: number, events: Array<object>, stream: Uint8Array }}
 */
export function decompileMacroPackets(packets) {
  const parts = [];
  let totalLen = 0;
  for (const pkt of packets) {
    const len = pkt[3] || 0;
    const chunk = pkt.subarray(4, 4 + len);
    parts.push(chunk);
    totalLen += chunk.length;
  }
  const stream = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    stream.set(part, offset);
    offset += part.length;
  }
  return { ...decompileMacroStream(stream), stream };
}

/**
 * Encode a structured UI button action descriptor into `[b0, b1, b2]` for
 * `0x09` / `0x11` button binding packets.
 *
 * Supported types:
 * - `{ type: 'mouse', button: 1..5 }` or `{ type: 'mouse', action: 'scroll_up'|'scroll_down'|'scroll_left'|'scroll_right'|'double_click' }`
 * - `{ type: 'keyboard', modifiers: 0..0xFF, hid?: number, code?: string, vk?: number }`
 * - `{ type: 'media', usage?: number, keyName?: string }`
 * - `{ type: 'fire', repeatCount?: number, interval?: number }`
 * - `{ type: 'macro', macroId?: number, loopMode?: 'toggle'|'loop'|'hold'|'count', loopCount?: number }`
 * - `{ type: 'dpi', mode: 'cycle'|'up'|'down' }`
 * - `{ type: 'reportRate', step?: 1|2 }`
 * - `{ type: 'disabled' }`
 *
 * @param {object} action
 * @param {number} [slotIndex=0]
 * @returns {[number, number, number]}
 */
export function encodeButtonDescriptor(action, slotIndex = 0) {
  if (!action || typeof action !== 'object') {
    return [0x10, BUTTON_ID_TO_MASK[slotIndex + 1] || 0x01, 0x00];
  }

  if (Array.isArray(action.raw) && action.raw.length === 3) {
    return [action.raw[0] & 0xFF, action.raw[1] & 0xFF, action.raw[2] & 0xFF];
  }

  switch (action.type) {
    case 'disabled':
      return [0x60, 0x00, 0x00];

    case 'mouse': {
      if (action.action === 'scroll_up') return [0x20, 0x01, 0x00];
      if (action.action === 'scroll_down') return [0x20, 0xFF, 0x00];
      if (action.action === 'scroll_left') return [0x10, 0x00, 0xF5];
      if (action.action === 'scroll_right') return [0x10, 0x00, 0xF6];
      if (action.action === 'double_click') return [0x30, 0x32, 0x03];
      const mask = Number.isInteger(action.mask)
        ? action.mask & 0xFF
        : (BUTTON_ID_TO_MASK[action.button] || MOUSE_BUTTON_MASKS[action.button] || 0x01);
      return [0x10, mask, 0x00];
    }

    case 'keyboard': {
      const modMask = (Number(action.modifiers) || 0) & 0xFF;
      const spec = resolveKeySpec(action);
      if (modMask === 0 && spec.isModifier && spec.modMask > 0) {
        return [0x70, spec.modMask & 0xFF, 0x00];
      }
      return [0x70, modMask, spec.hid & 0xFF];
    }

    case 'media': {
      const usage = Number.isInteger(action.usage)
        ? action.usage
        : (MEDIA_KEYS[action.keyName] ?? 0x00CD);
      return [0x80, usage & 0xFF, (usage >> 8) & 0xFF];
    }

    case 'fire': {
      const repeat = Math.max(0, Math.min(255, Math.round(Number(action.repeatCount ?? 3))));
      const interval = Math.max(5, Math.min(255, Math.round(Number(action.interval ?? 50))));
      return [0x30, repeat & 0xFF, interval & 0xFF];
    }

    case 'macro': {
      const macroSlot = (Number.isInteger(action.slotIndex) ? action.slotIndex : (Number(action.macroId ?? slotIndex))) & 0x0F;
      const loopMode = action.loopMode || 'count';
      let modeFlag = 0x10;
      let countByte = 0x00;
      if (loopMode === 'hold') {
        modeFlag = 0x40;
      } else if (loopMode === 'toggle' || loopMode === 'until_any') {
        modeFlag = 0x10;
      } else {
        modeFlag = 0x20;
        countByte = Math.max(1, Math.min(255, Math.round(Number(action.loopCount ?? 1))));
      }
      return [0x90, modeFlag | macroSlot, countByte];
    }

    case 'dpi': {
      if (action.mode === 'up' || action.mode === '+') return [0x40, 0x02, 0x00];
      if (action.mode === 'down' || action.mode === '-') return [0x40, 0x03, 0x00];
      return [0x40, 0x01, 0x00];
    }

    case 'reportRate':
      return [0x60, action.step === 2 ? 0x01 : 0x04, 0x00];

    default:
      return [0x60, 0x00, 0x00];
  }
}

/**
 * Decode a 3-byte `[b0, b1, b2]` button action descriptor read from `0x11`.
 * @param {number} b0
 * @param {number} b1
 * @param {number} b2
 * @returns {object}
 */
export function decodeButtonDescriptor(b0, b1, b2) {
  const raw = [b0 & 0xFF, b1 & 0xFF, b2 & 0xFF];

  if (b0 === 0x10) {
    if (b1 === 0x00 && b2 === 0xF5) return { type: 'mouse', action: 'scroll_left', raw };
    if (b1 === 0x00 && b2 === 0xF6) return { type: 'mouse', action: 'scroll_right', raw };
    const buttonId = MASK_TO_BUTTON_ID[b1] || 1;
    return { type: 'mouse', button: buttonId, mask: b1, raw };
  }

  if (b0 === 0x20) {
    return {
      type: 'mouse',
      action: b1 === 0xFF ? 'scroll_down' : 'scroll_up',
      raw,
    };
  }

  if (b0 === 0x30) {
    if (b1 === 0x32 && b2 === 0x03) {
      return { type: 'mouse', action: 'double_click', raw };
    }
    return { type: 'fire', repeatCount: b1, interval: b2, raw };
  }

  if (b0 === 0x40) {
    const mode = b1 === 0x02 ? 'up' : b1 === 0x03 ? 'down' : 'cycle';
    return { type: 'dpi', mode, raw };
  }

  if (b0 === 0x60) {
    if (b1 === 0x00 && b2 === 0x00) {
      return { type: 'disabled', raw };
    }
    return { type: 'reportRate', step: b1 === 0x01 ? 2 : 1, value: b1, raw };
  }

  if (b0 === 0x70) {
    return {
      type: 'keyboard',
      modifiers: b1,
      hid: b2,
      code: b2 ? (HID_TO_CODE[b2] || `HID_0x${b2.toString(16).toUpperCase()}`) : null,
      raw,
    };
  }

  if (b0 === 0x80) {
    const usage = b1 | (b2 << 8);
    return {
      type: 'media',
      usage,
      keyName: MEDIA_USAGE_TO_NAME[usage] || `0x${usage.toString(16).toUpperCase().padStart(4, '0')}`,
      raw,
    };
  }

  if (b0 === 0x90) {
    const modeNibble = b1 & 0xF0;
    const slotIndex = b1 & 0x0F;
    const loopMode = modeNibble === 0x40 ? 'hold' : (modeNibble === 0x20 ? 'count' : 'toggle');
    return {
      type: 'macro',
      macroId: slotIndex,
      slotIndex,
      loopMode,
      loopCount: loopMode === 'count' ? (b2 || 1) : b2,
      raw,
    };
  }

  return { type: 'disabled', raw };
}
