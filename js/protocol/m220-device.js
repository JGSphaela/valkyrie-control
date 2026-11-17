/**
 * Valkyrie M220 (VK M3 Lite) / E023 (VK M3) 32-Byte WebHID Protocol Driver
 *
 * Implements serialized HID packet transport, strict stall-guard outbound opcode
 * allowlisting, write settle timing (>= 50ms), all 11 sensor DPI curves +
 * PAW3395 26,000 DPI unlock, registers `0x10..0x17, 0x20`, write commands
 * `0x02..0x09, 0x0E, 0x0F`, unsolicited `0xC0`/`0xC2` notifications,
 * snapshot export/import/rollback `[0x02..0x07, 0x09]`, and 256-bit diffing.
 */

import { getDeviceByDevId } from '../devices.js';
import { MODEL_PROFILES } from '../models.js';
import {
  compileMacroStream,
  decodeButtonDescriptor,
  encodeButtonDescriptor,
  frameMacroChunks,
} from './macro-compiler.js';

export const REPORT_SIZE = 32;
export const REPORT_ID = 0x00;
export const WRITE_SETTLE_DELAY_MS = 55;
export const READ_TIMEOUT_MS = 1200;

/**
 * Strict outbound opcode allowlist.
 * Live probes proved opcodes `0x18..0x2A` (aside from `0x20`) stall `MI_02`
 * until physical USB replug. Any opcode outside this set is blocked BEFORE `sendReport`.
 */
export const ALLOWED_OUTBOUND_OPCODES = new Set([
  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x20,
]);

export const SAFE_DUMP_OPCODES = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x20];

export const SAFE_ROLLBACK_WRITE_PAIRS = [
  { readCmd: 0x12, writeCmd: 0x02, forceLen: 0x01 },
  { readCmd: 0x13, writeCmd: 0x03, forceLen: 0x19 },
  { readCmd: 0x14, writeCmd: 0x04, forceLen: 0x12 },
  { readCmd: 0x15, writeCmd: 0x05, forceLen: null },
  { readCmd: 0x16, writeCmd: 0x06, forceLen: 0x05 },
  { readCmd: 0x17, writeCmd: 0x07, forceLen: 0x04 },
  { readCmd: 0x11, writeCmd: 0x09, forceLen: 0x0F },
];

export const POLLING_CODE_TO_HZ = {
  0x08: 125,
  0x04: 250,
  0x02: 500,
  0x01: 1000,
  0x10: 2000,
  0x20: 4000,
  0x40: 8000,
};

export const HZ_TO_POLLING_CODE = {
  125: 0x08,
  250: 0x04,
  500: 0x02,
  1000: 0x01,
  2000: 0x10,
  4000: 0x20,
  8000: 0x40,
};

export const ALL_POLLING_RATES_HZ = [125, 250, 500, 1000, 2000, 4000, 8000];

/**
 * Official per-sensor metadata derived from `GetMouseData` switch table.
 */
export const SENSOR_PROFILES = {
  // Handshake sensorId 0x11 curve: shared by PAW3395 (E023, native 26000) and
  // PAW3311 (M220 VK M3 Lite, native 12000 with firmware-interpolated DPI > 12000).
  0x11: { id: 0x11, curveId: 0x11, name: 'PAW3395', m220Name: 'PAW3311', minDpi: 50, nativeMaxDpi: 26000, m220NativeMaxDpi: 12000, maxDpi: 24000, unlockMaxDpi: 26000, step: 50, sliderMax: 0xE8, unlockSliderMax: 0xEA },
  0x05: { id: 0x05, curveId: 0x05, name: 'Sensor 0x05', minDpi: 50, maxDpi: 12000, unlockMaxDpi: 12000, step: 50, sliderMax: 0xB7 },
  0x19: { id: 0x19, curveId: 0x19, name: 'PAW3950 / 0x19', minDpi: 100, maxDpi: 30000, unlockMaxDpi: 30000, step: 100, sliderMax: 0xAE },
  0x25: { id: 0x25, curveId: 0x25, name: 'Sensor 0x25', minDpi: 100, maxDpi: 10000, unlockMaxDpi: 10000, step: 100, sliderMax: 0x3C },
  0x26: { id: 0x26, curveId: 0x26, name: 'Sensor 0x26', minDpi: 200, maxDpi: 10000, unlockMaxDpi: 10000, step: 200, sliderMax: 0x3B },
  0x04: { id: 0x04, curveId: 0x04, name: 'Sensor 0x04', minDpi: 100, maxDpi: 8000, unlockMaxDpi: 8000, step: 100, sliderMax: 0x2F },
  0x95: { id: 0x95, curveId: 0x95, name: 'Sensor 0x95', minDpi: 100, maxDpi: 26000, unlockMaxDpi: 26000, step: 100, sliderMax: 0x207 },
  0x96: { id: 0x96, curveId: 0x96, name: 'Sensor 0x96', minDpi: 100, maxDpi: 32000, unlockMaxDpi: 32000, step: 100, sliderMax: 0x27F },
  0x10: { id: 0x10, curveId: 0x10, name: 'Sensor 0x10', minDpi: 100, maxDpi: 4800, unlockMaxDpi: 4800, step: 100, sliderMax: 0x30 },
  0x12: { id: 0x12, curveId: 0x12, name: 'Sensor 0x12', minDpi: 100, maxDpi: 4800, unlockMaxDpi: 4800, step: 100, sliderMax: 0x30 },
  0x35: { id: 0x35, curveId: 0x35, name: 'Sensor 0x35', minDpi: 100, maxDpi: 16000, unlockMaxDpi: 16000, step: 100, sliderMax: 0xA0 },
};

export const FALLBACK_SENSOR_PROFILE = {
  id: 0x00,
  name: 'Generic 50 DPI',
  minDpi: 50,
  maxDpi: 26000,
  unlockMaxDpi: 26000,
  step: 50,
  sliderMax: 0x207,
};

/**
 * Resolve sensor metadata & curve limits, mapping curve `0x11` on `M220` / `VK_M3_LITE`
 * to physical sensor `PAW3311` (`nativeMaxDpi: 12000`) while keeping `PAW3395` for
 * `E023` / `VK_M3` or unknown devices.
 *
 * @param {number} sensorId
 * @param {boolean|{ unlockMax?: boolean, devId?: string, modelKey?: string }} [unlockOrOptions=false]
 */
export function getSensorProfile(sensorId, unlockOrOptions = false) {
  const opts = typeof unlockOrOptions === 'object' && unlockOrOptions !== null
    ? unlockOrOptions
    : { unlockMax: Boolean(unlockOrOptions) };
  const unlockMax = Boolean(opts.unlockMax);
  const devId = opts.devId ? String(opts.devId).trim().toUpperCase() : '';
  const modelKey = opts.modelKey ? String(opts.modelKey).trim().toUpperCase() : '';
  const isM220 = devId === 'M220' || modelKey === 'VK_M3_LITE';

  const base = SENSOR_PROFILES[sensorId] || { ...FALLBACK_SENSOR_PROFILE, id: sensorId || 0 };
  const name = (sensorId === 0x11 && isM220) ? (base.m220Name || 'PAW3311') : base.name;
  const nativeMaxDpi = (sensorId === 0x11 && isM220)
    ? (base.m220NativeMaxDpi || 12000)
    : (base.nativeMaxDpi ?? base.unlockMaxDpi ?? base.maxDpi);

  return {
    ...base,
    name,
    sensorCurveId: base.curveId ?? base.id,
    nativeMaxDpi,
    effectiveMaxDpi: unlockMax ? (base.unlockMaxDpi || base.maxDpi) : base.maxDpi,
  };
}

/**
 * Convert DPI to hardware register code (`Protocol` `GetMouseDPIValue` match).
 *
 * All 11 curves (`0x11`, `0x05`, `0x19`, `0x25`, `0x26`, `0x04`, `0x95`,
 * `0x96`, `0x10`, `0x12`, `0x35`) plus the fallback 50-DPI curve are supported.
 * On `0x11` (PAW3395), `unlockMax: true` extends official 24,000 (`0xE8`) to
 * hardware-verified 26,000 (`0xEA`).
 *
 * @param {number} sensorId
 * @param {number} dpi
 * @param {{ unlockMax?: boolean }} [options]
 * @returns {number}
 */
export function encodeDpiCode(sensorId, dpi, { unlockMax = false } = {}) {
  const profile = getSensorProfile(sensorId, unlockMax);
  const clamped = Math.max(profile.minDpi, Math.min(profile.effectiveMaxDpi, Math.round(Number(dpi) || profile.minDpi)));

  switch (sensorId) {
    case 0x11: {
      if (clamped >= 13000) {
        return Math.trunc((clamped - 13000) / 1000) + 0xDD;
      }
      if (clamped > 10000) {
        return Math.trunc((clamped - 10000) / 100) + 0xC8;
      }
      return Math.trunc(clamped / 50);
    }

    case 0x05: {
      if (clamped > 6400) {
        return Math.trunc((clamped - 6400) / 100) + 0x80;
      }
      return Math.trunc(clamped / 50);
    }

    case 0x19: {
      if (clamped > 16000) {
        return Math.trunc((clamped - 16000) / 1000) + 0xA0;
      }
      return Math.trunc(clamped / 100);
    }

    case 0x25: {
      if (clamped > 5000) {
        return Math.trunc((clamped - 5000) / 500) + 0x32;
      }
      return Math.trunc(clamped / 100);
    }

    case 0x26: {
      if (clamped > 5000) {
        return Math.trunc((clamped - 5000) / 500) + 0x32;
      }
      return Math.max(0, Math.trunc(clamped / 100) - 1);
    }

    case 0x04: {
      if (clamped > 4000) {
        return Math.trunc((clamped - 4000) / 500) + 0x27;
      }
      return Math.trunc(clamped / 100);
    }

    case 0x95:
    case 0x96:
      return Math.max(0, Math.trunc(clamped / 50) - 1);

    case 0x10:
    case 0x12:
    case 0x35:
      return Math.trunc(clamped / 100);

    default:
      return Math.max(0, Math.trunc(clamped / 50) - 1);
  }
}

/**
 * Convert raw hardware DPI register code back to DPI (`GetDPIValueByMouseDPI` match).
 * @param {number} sensorId
 * @param {number} rawCode
 * @returns {number}
 */
export function decodeDpiCode(sensorId, rawCode) {
  const code = Math.max(0, Number(rawCode) | 0);

  switch (sensorId) {
    case 0x11: {
      if (code >= 0xDD) {
        return (code - 0xDD) * 1000 + 13000;
      }
      if (code >= 0xC8) {
        return (code - 0xC8) * 100 + 10000;
      }
      return code * 50;
    }

    case 0x05: {
      if (code >= 0x81) {
        return (code - 64) * 100;
      }
      return code * 50;
    }

    case 0x19: {
      if (code >= 0xA0) {
        return (code - 0x90) * 1000;
      }
      return code * 100;
    }

    case 0x25: {
      if (code >= 0x32) {
        return (code - 0x28) * 500;
      }
      return code * 100;
    }

    case 0x26: {
      if (code >= 0x32) {
        return (code - 0x27) * 500;
      }
      return code * 100;
    }

    case 0x04: {
      if (code <= 0x27) {
        return code * 100;
      }
      return (code - 0x1F) * 500;
    }

    case 0x95:
      return (code + 1) * 50;

    case 0x96:
      return code * 50;

    case 0x10:
    case 0x12:
    case 0x35:
      return code * 100;

    default:
      return (code + 1) * 50;
  }
}

/**
 * Create a structured protocol Error with stable `.code` for UI/i18n translation.
 * @param {string} code
 * @param {string} message
 * @param {object} [meta]
 * @returns {Error}
 */
export function createProtocolError(code, message, meta = {}) {
  const err = new Error(message);
  err.code = code;
  Object.assign(err, meta);
  return err;
}

/**
 * Check whether an opcode is inside the stall-safe allowlist `[0x02..0x0F, 0x10..0x17, 0x20]`.
 * @param {number} cmd
 * @returns {boolean}
 */
export function isAllowedOpcode(cmd) {
  return Number.isInteger(cmd) && ALLOWED_OUTBOUND_OPCODES.has(cmd);
}

/**
 * Compute Valkyrie 32-byte packet checksum: `sum(packet[4..30]) & 0xFF`.
 * @param {Uint8Array|Array<number>} packet32
 * @returns {number}
 */
export function computeChecksum(packet32) {
  let sum = 0;
  for (let i = 4; i <= 30; i += 1) {
    sum = (sum + (packet32[i] || 0)) & 0xFF;
  }
  return sum;
}

/**
 * Verify checksum of a received/constructed 32-byte Valkyrie report.
 * @param {Uint8Array|Array<number>} packet32
 * @returns {boolean}
 */
export function verifyPacketChecksum(packet32) {
  if (!packet32 || packet32.length < 32) return false;
  return (packet32[31] & 0xFF) === computeChecksum(packet32);
}

/**
 * Format bytes to lowercase space-separated hex string (matching `virgin_backup.json`).
 * @param {Uint8Array|Array<number>} bytes
 * @param {string} [sep=' ']
 * @returns {string}
 */
export function formatHex(bytes, sep = ' ') {
  return Array.from(bytes, (b) => (b & 0xFF).toString(16).padStart(2, '0')).join(sep);
}

/**
 * Parse a hex string (`"10 00 01 ..."` or `"100001..."`) into a `Uint8Array`.
 * @param {string} hexStr
 * @returns {Uint8Array}
 */
export function parseHex(hexStr) {
  const clean = String(hexStr || '').replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2 !== 0) {
    throw createProtocolError('INVALID_HEX', `Odd number of hex nibbles (${clean.length})`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Build an allowlisted 32-byte Valkyrie command packet with checksum in `byte[31]`.
 * Rejects any disallowed opcode (`0x18..0x2A` except `0x20`, etc.) immediately.
 *
 * @param {number} cmd
 * @param {Uint8Array|Array<number>} [payload=[]]
 * @param {{ seqByte?: number, length?: number, status?: number }} [options]
 * @returns {Uint8Array}
 */
export function buildCommandPacket(cmd, payload = [], options = {}) {
  if (!isAllowedOpcode(cmd)) {
    const cmdHex = `0x${Number(cmd).toString(16).toUpperCase().padStart(2, '0')}`;
    throw createProtocolError(
      'STALL_GUARD_BLOCKED',
      `Stall guard blocked disallowed outbound opcode ${cmdHex}`,
      { cmd }
    );
  }

  const pkt = new Uint8Array(REPORT_SIZE);
  pkt[0] = cmd & 0xFF;
  pkt[1] = (options.status ?? 0x00) & 0xFF;
  pkt[2] = (options.seqByte ?? 0x01) & 0xFF;
  const data = payload instanceof Uint8Array ? payload : Uint8Array.from(payload);
  if (data.length > 27) {
    throw createProtocolError(
      'PAYLOAD_TOO_LARGE',
      `Payload length ${data.length} exceeds 27-byte Valkyrie packet capacity`
    );
  }
  pkt[3] = (options.length ?? data.length) & 0xFF;
  pkt.set(data, 4);
  pkt[31] = computeChecksum(pkt);
  return pkt;
}

export function normalizeHexColor(hex) {
  const clean = String(hex || '').trim().replace(/^#/, '');
  if (/^[0-9a-fA-F]{6}$/.test(clean)) {
    return `#${clean.toUpperCase()}`;
  }
  return '#2563EB';
}

export function hexToRgb(hex) {
  const norm = normalizeHexColor(hex);
  const val = parseInt(norm.slice(1), 16);
  return [(val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF];
}

export function rgbToHex(r, g, b) {
  return `#${[r, g, b].map((v) => (v & 0xFF).toString(16).padStart(2, '0')).join('').toUpperCase()}`;
}

function getPollingMaxHzFromCapByte(capByte) {
  if (capByte & 0x40) return 8000;
  if (capByte & 0x20) return 4000;
  if (capByte & 0x10) return 2000;
  if (capByte === 0x07) return 8000;
  return 1000;
}

function getSupportedPollingRatesFromCapByte(capByte) {
  const maxHz = getPollingMaxHzFromCapByte(capByte);
  const base = [125, 250, 500, 1000];
  if (capByte === 0x07) return [125, 250, 500, 1000, 2000, 4000, 8000];
  if (maxHz >= 2000) base.push(2000);
  if (maxHz >= 4000) base.push(4000);
  if (maxHz >= 8000) base.push(8000);
  return base;
}

function formatFwVersion(minorByte, majorByte) {
  const maj = (majorByte & 0xFF).toString(16);
  const min = (minorByte & 0xFF).toString(16).padStart(2, '0');
  return `v${maj}.${min}`;
}

/**
 * Decode `0x10` Handshake response packet.
 * Verified against `virgin_backup.json` `"0x10"` and `disasm_proto.txt`:
 * `bytes[4..7]` ASCII devId, `[8]` fwMinor, `[9]` fwMajor (`0317 -> v3.17`),
 * `[10]` sensorId (`0x11`), `[11]` pollingCaps, `[12]` charging, `[13]` batteryPct, `[14]` online.
 *
 * @param {Uint8Array} pkt
 * @returns {object}
 */
export function decodeHandshakePacket(pkt) {
  let devId = '';
  for (let i = 4; i <= 7; i += 1) {
    const ch = pkt[i];
    if (ch >= 0x20 && ch <= 0x7E) {
      devId += String.fromCharCode(ch);
    }
  }
  const fwMinor = pkt[8] & 0xFF;
  const fwMajor = pkt[9] & 0xFF;
  const fwRaw = (fwMajor << 8) | fwMinor;
  const sensorId = pkt[10] & 0xFF;
  const pollingCapsByte = pkt[11] & 0xFF;
  const charging = pkt[12] !== 0;
  const batteryPct = Math.max(0, Math.min(100, pkt[13] & 0xFF));
  const online = pkt[14] !== 0;
  const sensor = getSensorProfile(sensorId, { devId });

  return {
    cmd: 0x10,
    devId: devId || 'M220',
    deviceInfo: getDeviceByDevId(devId),
    fwMinor,
    fwMajor,
    fwRaw,
    fwVersion: formatFwVersion(fwMinor, fwMajor),
    sensorId,
    sensorCurveId: sensor.sensorCurveId,
    sensorName: sensor.name,
    nativeMaxDpi: sensor.nativeMaxDpi,
    maxDpiOfficial: sensor.maxDpi,
    maxDpiUnlocked: sensor.unlockMaxDpi,
    pollingCapsByte,
    maxPollingHz: getPollingMaxHzFromCapByte(pollingCapsByte),
    supportedPollingRates: getSupportedPollingRatesFromCapByte(pollingCapsByte),
    charging,
    batteryPct,
    online,
  };
}

/**
 * Decode `0x11` Button bindings (`bytes[4..21]` = 6 x 3-byte action descriptors).
 * @param {Uint8Array} pkt
 * @returns {Array<object>}
 */
export function decodeButtonsPacket(pkt) {
  const buttons = [];
  for (let i = 0; i < 6; i += 1) {
    const base = 4 + i * 3;
    const decoded = decodeButtonDescriptor(pkt[base], pkt[base + 1], pkt[base + 2]);
    buttons.push({ slot: i, ...decoded });
  }
  return buttons;
}

/**
 * Decode `0x12` Polling Rate response (`byte[4]`).
 * @param {Uint8Array} pkt
 * @returns {{ code: number, pollingHz: number }}
 */
export function decodePollingPacket(pkt) {
  const code = pkt[4] & 0xFF;
  return {
    code,
    pollingHz: POLLING_CODE_TO_HZ[code] || 1000,
  };
}

/**
 * Decode `0x13` DPI stages (`byte[4]` = `(activeIdx << 4) | stageCount`,
 * followed by 6 x 4-byte LE slots `[xLo, xHi, yLo, yHi]` at `bytes[5..28]`).
 *
 * @param {Uint8Array} pkt
 * @param {number} [sensorId=0x11]
 * @returns {{ activeStage: number, stageCount: number, stages: Array<{x: number, y: number, rawX: number, rawY: number}> }}
 */
export function decodeDpiPacket(pkt, sensorId = 0x11) {
  const header = pkt[4] & 0xFF;
  const activeStage = (header >> 4) & 0x0F;
  const rawCount = header & 0x0F;
  const stageCount = Math.max(1, Math.min(6, rawCount || 6));
  const stages = [];

  for (let i = 0; i < 6; i += 1) {
    const off = 5 + i * 4;
    const rawX = pkt[off] | (pkt[off + 1] << 8);
    const rawY = pkt[off + 2] | (pkt[off + 3] << 8);
    stages.push({
      x: decodeDpiCode(sensorId, rawX),
      y: decodeDpiCode(sensorId, rawY),
      rawX,
      rawY,
    });
  }

  return {
    activeStage: Math.min(activeStage, stageCount - 1),
    stageCount,
    stages: stages.slice(0, stageCount),
    allStages: stages,
  };
}

/**
 * Decode `0x14` DPI Stage RGB Colors (`bytes[4..21]` = 6 x 3B RGB).
 * @param {Uint8Array} pkt
 * @returns {Array<string>}
 */
export function decodeDpiColorsPacket(pkt) {
  const colors = [];
  for (let i = 0; i < 6; i += 1) {
    const off = 4 + i * 3;
    colors.push(rgbToHex(pkt[off], pkt[off + 1], pkt[off + 2]));
  }
  return colors;
}

/**
 * Decode `0x15` Lighting Configuration (`mode`, `brightness`, `speed`, `direction`/`color`).
 * Verified against `virgin_backup.json` `"15 00 01 03 01 42 01 ... 44"`.
 * @param {Uint8Array} pkt
 * @returns {object}
 */
export function decodeLightingPacket(pkt) {
  const len = pkt[3] & 0xFF;
  const mode = Math.max(0, Math.min(5, pkt[4] & 0xFF));
  const packed = pkt[5] & 0xFF;
  const speed = (packed >> 4) & 0x0F;
  const brightness = packed & 0x0F;
  const direction = mode === 1 ? (pkt[6] & 0xFF) : 1;

  let color = '#2563EB';
  if (mode === 3 && len >= 5) {
    color = rgbToHex(pkt[6], pkt[7], pkt[8]);
  }

  let breathingColors = null;
  if (mode === 2 && len >= 24) {
    const count = Math.min(7, pkt[6] || 7);
    breathingColors = [];
    for (let i = 0; i < count; i += 1) {
      const off = 7 + i * 3;
      breathingColors.push(rgbToHex(pkt[off], pkt[off + 1], pkt[off + 2]));
    }
  }

  return {
    mode,
    brightness,
    speed,
    direction,
    color,
    breathingColors: breathingColors || [
      '#FF0000',
      '#00FF00',
      '#0000FF',
      '#FFFF00',
      '#FF00FF',
      '#00FFFF',
      '#FFFFFF',
    ],
  };
}

/**
 * Decode `0x16` Sensor Tuning (`byte[4]=lod`, `byte[5]=angleSnap`, `byte[6]=ripple`, `byte[7]=motionSync`).
 * Verified against `virgin_backup.json` `"16 00 01 05 02 00 00 01 00 ... 03"`,
 * `disasm_load_cfg.txt`, and `1033.lan`.
 * @param {Uint8Array} pkt
 * @returns {{ lod: number, angleSnap: boolean, ripple: boolean, motionSync: boolean }}
 */
export function decodeSensorPacket(pkt) {
  return {
    lod: Math.max(1, Math.min(3, pkt[4] || 1)),
    angleSnap: (pkt[5] & 0x01) === 1,
    ripple: (pkt[6] & 0x01) === 1,
    motionSync: (pkt[7] & 0x01) === 1,
  };
}

/**
 * Decode `0x17` Sleep & Debounce (`byte[4]=sleep_10s`, `byte[5]=moveWake`,
 * `byte[6]=moveCloseLight`, `byte[7]=debounceMs`).
 * Verified against `virgin_backup.json` `"17 00 01 05 1e 01 01 08 00 ... 28"`.
 * @param {Uint8Array} pkt
 * @returns {{ sleep10s: number, sleepSec: number, moveWake: boolean, moveCloseLight: boolean, debounceMs: number }}
 */
export function decodeSleepPacket(pkt) {
  const sleep10s = pkt[4] & 0xFF;
  return {
    sleep10s,
    sleepSec: sleep10s * 10,
    moveWake: (pkt[5] & 0x01) === 1,
    moveCloseLight: (pkt[6] & 0x01) === 1,
    debounceMs: pkt[7] & 0xFF,
  };
}

/**
 * Decode `0x20` Extended Status (2.4G dongle/RF version).
 * @param {Uint8Array} pkt
 * @returns {{ rfMinor: number, rfMajor: number, rfFwRaw: number, rfFwVersion: string }}
 */
export function decodeDonglePacket(pkt) {
  const rfMinor = pkt[4] & 0xFF;
  const rfMajor = pkt[5] & 0xFF;
  return {
    rfMinor,
    rfMajor,
    rfFwRaw: (rfMajor << 8) | rfMinor,
    rfFwVersion: formatFwVersion(rfMinor, rfMajor),
  };
}

/**
 * Decode unsolicited notification packets (`0xC0` battery/online/charge, `0xC2` DPI stage).
 * @param {Uint8Array} pkt
 * @returns {object|null}
 */
export function decodeNotificationPacket(pkt) {
  const cmd = pkt[0] & 0xFF;
  if (cmd === 0xC0) {
    const online = pkt[1] === 0x01;
    const hasBattery = pkt[2] <= 100 && (pkt[2] > 0 || pkt[3] > 0 || online);
    const batteryPct = pkt[2] <= 100 ? pkt[2] : null;
    const charging = pkt[3] <= 1 ? (pkt[3] === 1) : null;
    return {
      kind: 'battery',
      cmd,
      online,
      batteryPct: hasBattery ? batteryPct : null,
      charging,
    };
  }
  if (cmd === 0xC2) {
    const header = pkt[1] & 0xFF;
    const activeStage = (header >> 4) & 0x0F;
    const stageCount = header & 0x0F;
    return {
      kind: 'dpiStage',
      cmd,
      activeStage,
      stageCount,
    };
  }
  return null;
}

/**
 * Normalize snapshot register map (`{ '0x10': hexOrUint8, ... }`) into `Uint8Array(32)` map.
 * Supports both `virgin_backup.json` (`{ device, regs: { '0x10': '...' } }`) and plain reg maps.
 * @param {object} snapshotOrRegs
 * @returns {Record<string, Uint8Array>}
 */
export function normalizeRegisterMap(snapshotOrRegs) {
  const raw = snapshotOrRegs?.regs && typeof snapshotOrRegs.regs === 'object'
    ? snapshotOrRegs.regs
    : (snapshotOrRegs || {});
  const out = {};
  for (const [key, val] of Object.entries(raw)) {
    if (!val) continue;
    const normKey = `0x${parseInt(key, 16).toString(16).toUpperCase().padStart(2, '0')}`;
    if (val instanceof Uint8Array) {
      out[normKey] = val.slice(0, 32);
    } else if (Array.isArray(val)) {
      out[normKey] = Uint8Array.from(val.slice(0, 32));
    } else if (typeof val === 'string') {
      out[normKey] = parseHex(val).slice(0, 32);
    }
  }
  return out;
}

/**
 * Compute byte and **256-bit** (`32 bytes x 8 bits`) diff between a baseline register
 * snapshot (e.g., `virgin_backup.json`) and current registers.
 *
 * @param {object} baselineSnapshotOrRegs
 * @param {object} currentSnapshotOrRegs
 * @returns {{
 *   registers: Record<string, { baselineHex: string, currentHex: string, changedBytes: number, changedBits: number, totalBits: number, byteDiffs: Array<object>, bits: Array<object> }>,
 *   totalChangedBits: number,
 *   totalBits: number,
 *   totalChangedBytes: number,
 *   changedOpcodes: Array<string>
 * }}
 */
export function computeSnapshotDiff(baselineSnapshotOrRegs, currentSnapshotOrRegs) {
  const baseMap = normalizeRegisterMap(baselineSnapshotOrRegs);
  const currMap = normalizeRegisterMap(currentSnapshotOrRegs);
  const keys = Array.from(new Set([...Object.keys(baseMap), ...Object.keys(currMap)])).sort();

  const registers = {};
  let totalChangedBits = 0;
  let totalBits = 0;
  let totalChangedBytes = 0;
  const changedOpcodes = [];

  for (const key of keys) {
    const base = baseMap[key] || new Uint8Array(32);
    const curr = currMap[key] || new Uint8Array(32);
    const byteDiffs = [];
    const bits = [];
    let regChangedBytes = 0;
    let regChangedBits = 0;

    for (let byteIndex = 0; byteIndex < 32; byteIndex += 1) {
      const bVal = base[byteIndex] ?? 0;
      const cVal = curr[byteIndex] ?? 0;
      const byteChanged = bVal !== cVal;
      if (byteChanged) regChangedBytes += 1;
      byteDiffs.push({
        byteIndex,
        baseline: bVal,
        current: cVal,
        xor: bVal ^ cVal,
        changed: byteChanged,
      });

      for (let bitInByte = 7; bitInByte >= 0; bitInByte -= 1) {
        const baselineBit = (bVal >> bitInByte) & 1;
        const currentBit = (cVal >> bitInByte) & 1;
        const changed = baselineBit !== currentBit;
        if (changed) regChangedBits += 1;
        bits.push({
          bitIndex: byteIndex * 8 + (7 - bitInByte),
          byteIndex,
          bitInByte,
          baselineBit,
          currentBit,
          changed,
        });
      }
    }

    if (regChangedBits > 0) changedOpcodes.push(key);
    totalChangedBits += regChangedBits;
    totalBits += 256;
    totalChangedBytes += regChangedBytes;

    registers[key] = {
      opcode: key,
      baselineHex: formatHex(base),
      currentHex: formatHex(curr),
      changedBytes: regChangedBytes,
      changedBits: regChangedBits,
      totalBits: 256,
      byteDiffs,
      bits,
    };
  }

  return {
    registers,
    totalChangedBits,
    totalBits,
    totalChangedBytes,
    changedOpcodes,
  };
}

/**
 * Stateful WebHID protocol controller for Valkyrie M220 / E023 hardware.
 */
export class ValkyrieM220Device {
  /**
   * @param {object} hidDevice Open WebHID `HIDDevice` (must be 32B command interface, NEVER `0xFFEF`)
   * @param {{
   *   isWireless?: boolean,
   *   logger?: (dir: string, cmd: number, bytes: Uint8Array, extra?: object) => void,
   *   onStateChange?: (state: object) => void,
   *   onNotification?: (evt: object) => void,
   *   writeSettleMs?: number,
   *   readTimeoutMs?: number,
   *   unlockMax?: boolean,
   *   modelKey?: string,
   * }} [options]
   */
  constructor(hidDevice, options = {}) {
    if (!hidDevice || typeof hidDevice.sendReport !== 'function') {
      throw createProtocolError('NO_COMMAND_INTERFACE', 'Valid opened WebHID device is required');
    }

    if (Array.isArray(hidDevice.collections) && hidDevice.collections.length > 0) {
      const hasOtaOnly = hidDevice.collections.every(
        (c) => c.usagePage === 0xFFEF && c.usage === 0x0000
      );
      if (hasOtaOnly) {
        throw createProtocolError(
          'OTA_COLLECTION_BLOCKED',
          'Refused 64-byte (0xFFEF, 0x0000) OTA/DFU HID collection for safety'
        );
      }
    }

    this.hid = hidDevice;
    this.isWireless = Boolean(options.isWireless);
    this.logger = typeof options.logger === 'function' ? options.logger : null;
    this.onStateChange = typeof options.onStateChange === 'function' ? options.onStateChange : null;
    this.onNotification = typeof options.onNotification === 'function' ? options.onNotification : null;
    this.writeSettleMs = Math.max(50, Number(options.writeSettleMs ?? WRITE_SETTLE_DELAY_MS));
    this.readTimeoutMs = Number(options.readTimeoutMs ?? READ_TIMEOUT_MS);

    this.#ioChain = Promise.resolve();
    this.#pending = null;
    this.#trace = [];
    this.#rawRegs = {};
    this.#disposed = false;

    const modelKey = options.modelKey || 'VK_M3_LITE';
    const modelProfile = MODEL_PROFILES[modelKey] || MODEL_PROFILES.VK_M3_LITE;
    const defaults = modelProfile.factoryDefaults;
    const initSensor = getSensorProfile(modelProfile.sensorId ?? 0x11, {
      devId: modelProfile.devId,
      modelKey,
      unlockMax: options.unlockMax,
    });

    this.state = {
      connected: Boolean(hidDevice.opened),
      isWireless: this.isWireless,
      vendorId: hidDevice.vendorId ?? 0x248A,
      productId: hidDevice.productId ?? 0x5D2E,
      productName: hidDevice.productName || 'Valkyrie VK M3 Series',
      devId: modelProfile.devId || 'M220',
      modelKey,
      fwRaw: 0,
      fwVersion: '—',
      rfFwRaw: 0,
      rfFwVersion: '—',
      sensorId: modelProfile.sensorId ?? 0x11,
      sensorCurveId: initSensor.sensorCurveId,
      sensorName: initSensor.name,
      nativeMaxDpi: initSensor.nativeMaxDpi,
      unlockMax: Boolean(options.unlockMax),
      maxDpiOfficial: initSensor.maxDpi,
      maxDpiUnlocked: initSensor.unlockMaxDpi,
      pollingCapsByte: 0x01,
      maxPollingHz: 1000,
      supportedPollingRates: [125, 250, 500, 1000],
      batteryPct: 100,
      charging: false,
      online: true,
      pollingHz: defaults.pollingHz,
      activeDpiStage: defaults.activeDpiStage,
      stages: defaults.stages.map((s) => ({ ...s })),
      lighting: { ...defaults.lighting, breathingColors: [...defaults.lighting.breathingColors] },
      lod: defaults.lod,
      angleSnap: defaults.angleSnap,
      ripple: defaults.ripple,
      motionSync: defaults.motionSync,
      motionSyncLocked: false,
      sleep10s: defaults.sleep10s,
      sleepSec: defaults.sleepSec,
      moveWake: defaults.moveWake,
      moveCloseLight: defaults.moveCloseLight,
      debounceMs: defaults.debounceMs,
      buttons: defaults.buttons.map((b, slot) => ({ slot, ...b })),
    };

    this.#onInputReport = (event) => this.#handleInputReport(event);
    if (typeof this.hid.addEventListener === 'function') {
      this.hid.addEventListener('inputreport', this.#onInputReport);
    }
  }

  #ioChain;
  #pending;
  #trace;
  #rawRegs;
  #disposed;
  #onInputReport;

  dispose() {
    this.#disposed = true;
    if (this.#pending) {
      clearTimeout(this.#pending.timer);
      this.#pending.reject(createProtocolError('DEVICE_DISPOSED', 'Device transport disposed'));
      this.#pending = null;
    }
    if (this.hid && typeof this.hid.removeEventListener === 'function') {
      this.hid.removeEventListener('inputreport', this.#onInputReport);
    }
    this.state.connected = false;
  }

  setLogger(fn) {
    this.logger = typeof fn === 'function' ? fn : null;
  }

  getTrace() {
    return [...this.#trace];
  }

  clearTrace() {
    this.#trace = [];
  }

  getRawRegisters() {
    const copy = {};
    for (const [k, v] of Object.entries(this.#rawRegs)) {
      copy[k] = formatHex(v);
    }
    return copy;
  }

  getState() {
    return {
      ...this.state,
      supportedPollingRates: [...this.state.supportedPollingRates],
      stages: this.state.stages.map((s) => ({ ...s })),
      lighting: {
        ...this.state.lighting,
        breathingColors: [...this.state.lighting.breathingColors],
      },
      buttons: this.state.buttons.map((b) => ({ ...b, raw: b.raw ? [...b.raw] : undefined })),
      rawRegs: this.getRawRegisters(),
    };
  }

  #emitTrace(dir, cmd, bytes, meta = {}) {
    const data = bytes instanceof Uint8Array ? new Uint8Array(bytes) : Uint8Array.from(bytes);
    const entry = {
      ts: Date.now(),
      dir,
      cmd,
      hex: formatHex(data),
      bytes: data,
      ...meta,
    };
    this.#trace.push(entry);
    if (this.#trace.length > 500) {
      this.#trace.shift();
    }
    if (this.logger) {
      this.logger(dir, cmd, data, entry);
    }
  }

  #emitStateChange() {
    if (this.onStateChange) {
      this.onStateChange(this.getState());
    }
  }

  #handleInputReport(event) {
    const view = event?.data;
    if (!view) return;
    const raw = view instanceof Uint8Array
      ? view
      : new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    const data = raw.length === 33 && raw[0] === 0x00
      ? raw.subarray(1, 33)
      : raw.subarray(0, 32);
    if (data.length === 0) return;

    const cmd = data[0] & 0xFF;

    // Unsolicited notifications (0xC0 battery/online, 0xC2 DPI stage change)
    if (cmd === 0xC0 || cmd === 0xC2) {
      this.#emitTrace('EVT', cmd, data);
      const evt = decodeNotificationPacket(data);
      if (evt?.kind === 'battery') {
        this.state.online = evt.online;
        if (evt.batteryPct !== null) this.state.batteryPct = evt.batteryPct;
        if (evt.charging !== null) this.state.charging = evt.charging;
        this.#emitStateChange();
      } else if (evt?.kind === 'dpiStage') {
        this.state.activeDpiStage = evt.activeStage;
        this.#emitStateChange();
      }
      if (this.onNotification && evt) {
        this.onNotification(evt);
      }
      return;
    }

    if (this.#pending && cmd === this.#pending.expectedCmd) {
      this.#emitTrace('RX', cmd, data, { status: data[1] });
      const { resolve, timer } = this.#pending;
      clearTimeout(timer);
      this.#pending = null;
      resolve(new Uint8Array(data));
      return;
    }

    this.#emitTrace('RX', cmd, data, { unsolicited: true });
  }

  #enqueue(task) {
    const run = this.#ioChain.then(() => {
      if (this.#disposed) {
        throw createProtocolError('DEVICE_DISPOSED', 'Device transport disposed');
      }
      return task();
    });
    this.#ioChain = run.catch(() => {});
    return run;
  }

  async #sleep(ms) {
    if (ms <= 0) return;
    await new Promise((resolve) => setTimeout(resolve, ms));
  }

  async #sendAndWait(packet, expectedCmd = packet[0], { isWrite = false, allowTimeout = false } = {}) {
    const cmd = packet[0] & 0xFF;
    if (!isAllowedOpcode(cmd)) {
      const cmdHex = `0x${cmd.toString(16).toUpperCase().padStart(2, '0')}`;
      throw createProtocolError(
        'STALL_GUARD_BLOCKED',
        `Stall guard blocked disallowed outbound opcode ${cmdHex}`,
        { cmd }
      );
    }

    this.#emitTrace('TX', cmd, packet);

    const responsePromise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.#pending && this.#pending.expectedCmd === expectedCmd) {
          this.#pending = null;
        }
        if (allowTimeout) {
          resolve(null);
        } else {
          const cmdHex = `0x${expectedCmd.toString(16).toUpperCase().padStart(2, '0')}`;
          reject(createProtocolError('HID_TIMEOUT', `Timed out waiting for response to ${cmdHex}`, { cmd: expectedCmd }));
        }
      }, this.readTimeoutMs);

      this.#pending = { expectedCmd, resolve, reject, timer };
    });
    // Prevent unhandledrejection if dispose() rejects #pending while sendReport is awaiting I/O
    responsePromise.catch(() => {});

    try {
      await this.hid.sendReport(REPORT_ID, packet);
    } catch (err) {
      if (this.#pending) {
        clearTimeout(this.#pending.timer);
        this.#pending = null;
      }
      throw err;
    }

    if (this.#disposed) {
      if (this.#pending) {
        clearTimeout(this.#pending.timer);
        this.#pending = null;
      }
      throw createProtocolError('DEVICE_DISPOSED', 'Device transport disposed');
    }

    const rx = await responsePromise;
    if (isWrite) {
      await this.#sleep(this.writeSettleMs);
    }
    return rx;
  }

  /**
   * Low-level serialized command sender enforcing stall-guard allowlisting.
   * @param {number} cmd
   * @param {Uint8Array|Array<number>} [payload=[]]
   * @param {{ seqByte?: number, length?: number, isWrite?: boolean, allowTimeout?: boolean }} [options]
   * @returns {Promise<{ cmd: number, ok: boolean, rejected: boolean, status: number, tx: Uint8Array, rx: Uint8Array|null }>}
   */
  async sendCommand(cmd, payload = [], options = {}) {
    const pkt = buildCommandPacket(cmd, payload, options);
    const inferredWrite = options.isWrite ?? (cmd >= 0x02 && cmd <= 0x0F);

    return this.#enqueue(async () => {
      const rx = await this.#sendAndWait(pkt, cmd, {
        isWrite: inferredWrite,
        allowTimeout: Boolean(options.allowTimeout),
      });
      const status = rx ? (rx[1] & 0xFF) : 0xFF;
      return {
        cmd,
        ok: Boolean(rx && status === 0x00),
        rejected: Boolean(rx && status === 0x03),
        status,
        tx: pkt,
        rx,
      };
    });
  }

  /**
   * Inspector helper: send an arbitrary allowlisted opcode + payload, rejecting
   * disallowed opcodes before `sendReport`.
   */
  sendAllowlistedRaw(cmd, payload = [], options = {}) {
    return this.sendCommand(cmd, payload, options);
  }

  /**
   * Send write command and throw structured `HARDWARE_REJECTED` if firmware ACKs `status === 0x03`.
   */
  async #writeChecked(cmd, payload = [], options = {}) {
    const res = await this.sendCommand(cmd, payload, { ...options, isWrite: true });
    if (res.rejected) {
      const cmdHex = `0x${cmd.toString(16).toUpperCase().padStart(2, '0')}`;
      throw createProtocolError(
        'HARDWARE_REJECTED',
        `Hardware rejected command ${cmdHex} (status=0x03)`,
        { cmd, status: res.status, tx: res.tx, rx: res.rx }
      );
    }
    return res;
  }

  async #readRegister(cmd) {
    const res = await this.sendCommand(cmd, [], { isWrite: false });
    if (res.rx) {
      const key = `0x${cmd.toString(16).toUpperCase().padStart(2, '0')}`;
      this.#rawRegs[key] = new Uint8Array(res.rx);
    }
    return res.rx;
  }

  /**
   * Query `0x10` handshake and update identity/capability state.
   */
  async readHandshake() {
    const rx = await this.#readRegister(0x10);
    const info = decodeHandshakePacket(rx);
    this.state.devId = info.devId;
    if (info.deviceInfo?.modelKey) {
      this.state.modelKey = info.deviceInfo.modelKey;
    }
    this.state.fwRaw = info.fwRaw;
    this.state.fwVersion = info.fwVersion;
    this.state.sensorId = info.sensorId;
    this.state.sensorCurveId = info.sensorCurveId;
    this.state.sensorName = info.sensorName;
    this.state.nativeMaxDpi = info.nativeMaxDpi;
    this.state.maxDpiOfficial = info.maxDpiOfficial;
    this.state.maxDpiUnlocked = info.maxDpiUnlocked;
    this.state.pollingCapsByte = info.pollingCapsByte;
    this.state.maxPollingHz = info.maxPollingHz;
    this.state.supportedPollingRates = info.supportedPollingRates;
    this.state.batteryPct = info.batteryPct;
    this.state.charging = info.charging;
    this.state.online = info.online;
    this.#emitStateChange();
    return info;
  }

  /**
   * Query `0x20` dongle RF version (used in 2.4 GHz mode or Inspector dump).
   */
  async readDongleStatus() {
    const rx = await this.#readRegister(0x20);
    const info = decodeDonglePacket(rx);
    this.state.rfFwRaw = info.rfFwRaw;
    this.state.rfFwVersion = info.rfFwVersion;
    this.#emitStateChange();
    return info;
  }

  /**
   * Read all core device registers (`0x10..0x17`, plus `0x20` when wireless or `includeDongle: true`)
   * and populate `this.state` and `this.#rawRegs`.
   */
  async syncAll({ includeDongle = this.isWireless } = {}) {
    await this.readHandshake();

    const r11 = await this.#readRegister(0x11);
    this.state.buttons = decodeButtonsPacket(r11);

    const r12 = await this.#readRegister(0x12);
    this.state.pollingHz = decodePollingPacket(r12).pollingHz;

    const r13 = await this.#readRegister(0x13);
    const dpiInfo = decodeDpiPacket(r13, this.state.sensorId);
    this.state.activeDpiStage = dpiInfo.activeStage;

    const r14 = await this.#readRegister(0x14);
    const colors = decodeDpiColorsPacket(r14);
    this.state.stages = dpiInfo.stages.map((s, idx) => ({
      x: s.x,
      y: s.y,
      color: colors[idx] || '#2563EB',
    }));

    const r15 = await this.#readRegister(0x15);
    this.state.lighting = decodeLightingPacket(r15);

    const r16 = await this.#readRegister(0x16);
    const sensor = decodeSensorPacket(r16);
    this.state.lod = sensor.lod;
    this.state.angleSnap = sensor.angleSnap;
    this.state.ripple = sensor.ripple;
    this.state.motionSync = sensor.motionSync;

    const r17 = await this.#readRegister(0x17);
    const sleep = decodeSleepPacket(r17);
    this.state.sleep10s = sleep.sleep10s;
    this.state.sleepSec = sleep.sleepSec;
    this.state.moveWake = sleep.moveWake;
    this.state.moveCloseLight = sleep.moveCloseLight;
    this.state.debounceMs = sleep.debounceMs;

    if (includeDongle) {
      try {
        await this.readDongleStatus();
      } catch {
        // Wired connections may ignore 0x20 if unsupported
      }
    }

    this.state.connected = true;
    this.#emitStateChange();
    return this.getState();
  }

  /**
   * Read-only Inspector dump of all safe query opcodes `[0x10..0x17, 0x20]`.
   */
  async dumpAllRegisters() {
    const out = {};
    for (const cmd of SAFE_DUMP_OPCODES) {
      const key = `0x${cmd.toString(16).toUpperCase().padStart(2, '0')}`;
      try {
        const res = await this.sendCommand(cmd, [], { isWrite: false, allowTimeout: true });
        if (res.rx) {
          this.#rawRegs[key] = new Uint8Array(res.rx);
          out[key] = formatHex(res.rx);
        } else {
          out[key] = null;
        }
      } catch {
        out[key] = null;
      }
    }
    return out;
  }

  /**
   * Set polling rate (`0x02`) and read back `0x12`.
   * Validates rate against handshake `byte[11]` capability flags unless `{ force: true }`.
   */
  async setPollingRate(hz, { force = false } = {}) {
    const code = HZ_TO_POLLING_CODE[hz];
    if (code === undefined) {
      throw createProtocolError('INVALID_POLLING_RATE', `Unsupported polling rate: ${hz} Hz`);
    }

    if (!force && !this.state.supportedPollingRates.includes(hz)) {
      throw createProtocolError(
        'POLLING_UNSUPPORTED',
        `Polling rate ${hz} Hz exceeds handshake capability (max ${this.state.maxPollingHz} Hz)`,
        { hz, maxPollingHz: this.state.maxPollingHz }
      );
    }

    await this.#writeChecked(0x02, [code], { length: 0x01 });
    const rb = await this.#readRegister(0x12);
    this.state.pollingHz = decodePollingPacket(rb).pollingHz;
    this.#emitStateChange();
    return this.state.pollingHz;
  }

  /**
   * Set DPI stages & asymmetric X/Y DPI (`0x03`, optionally writing colors via `0x04`).
   * @param {{
   *   activeIndex?: number,
   *   stages: Array<{ x?: number, y?: number, dpi?: number, color?: string }>,
   *   unlockMax?: boolean,
   *   writeColors?: boolean,
   * }} config
   */
  async setDpiConfig(config) {
    const list = Array.isArray(config?.stages) ? config.stages : [];
    if (list.length < 1 || list.length > 6) {
      throw createProtocolError('INVALID_DPI_STAGES', 'DPI stage count must be between 1 and 6');
    }

    const unlockMax = config.unlockMax ?? this.state.unlockMax;
    this.state.unlockMax = Boolean(unlockMax);

    const activeIdx = Math.max(0, Math.min(list.length - 1, Math.round(config.activeIndex ?? this.state.activeDpiStage ?? 0)));
    const payload = new Uint8Array(25);
    payload[0] = ((activeIdx & 0x0F) << 4) | (list.length & 0x0F);

    for (let i = 0; i < list.length; i += 1) {
      const stage = list[i];
      const targetX = stage.x ?? stage.dpi ?? 800;
      const targetY = stage.y ?? stage.x ?? stage.dpi ?? 800;
      const codeX = encodeDpiCode(this.state.sensorId, targetX, { unlockMax });
      const codeY = encodeDpiCode(this.state.sensorId, targetY, { unlockMax });
      const off = 1 + i * 4;
      payload[off] = codeX & 0xFF;
      payload[off + 1] = (codeX >> 8) & 0xFF;
      payload[off + 2] = codeY & 0xFF;
      payload[off + 3] = (codeY >> 8) & 0xFF;
    }

    await this.#writeChecked(0x03, payload, { length: 0x19 });
    const r13 = await this.#readRegister(0x13);
    const decoded = decodeDpiPacket(r13, this.state.sensorId);
    this.state.activeDpiStage = decoded.activeStage;

    const existingColors = this.state.stages.map((s) => s.color);
    const targetColors = list.map((s, idx) => normalizeHexColor(s.color || existingColors[idx] || '#2563EB'));

    this.state.stages = decoded.stages.map((s, idx) => ({
      x: s.x,
      y: s.y,
      color: targetColors[idx] || '#2563EB',
    }));

    if (config.writeColors !== false && list.some((s) => s.color)) {
      await this.setDpiColors(targetColors);
    }

    this.#emitStateChange();
    return this.getState();
  }

  /**
   * Write 6-stage DPI indicator RGB colors (`0x04`) and verify via `0x14`.
   * @param {Array<string>} colors Hex strings `#RRGGBB`
   */
  async setDpiColors(colors) {
    const payload = new Uint8Array(18);
    for (let i = 0; i < 6; i += 1) {
      const [r, g, b] = hexToRgb(colors[i] || this.state.stages[i]?.color || '#2563EB');
      const off = i * 3;
      payload[off] = r;
      payload[off + 1] = g;
      payload[off + 2] = b;
    }
    await this.#writeChecked(0x04, payload, { length: 0x12 });
    const r14 = await this.#readRegister(0x14);
    const readColors = decodeDpiColorsPacket(r14);
    this.state.stages = this.state.stages.map((s, idx) => ({
      ...s,
      color: readColors[idx] || s.color,
    }));
    this.#emitStateChange();
    return readColors;
  }

  /**
   * Write lighting mode (`0x05`) supporting modes `0..5` and verify via `0x15`.
   */
  async setLighting(opts = {}) {
    const mode = Math.max(0, Math.min(5, Math.round(Number(opts.mode ?? this.state.lighting.mode ?? 0))));
    const brightness = Math.max(0, Math.min(5, Math.round(Number(opts.brightness ?? this.state.lighting.brightness ?? 2))));
    const speed = Math.max(0, Math.min(5, Math.round(Number(opts.speed ?? this.state.lighting.speed ?? 4))));
    const direction = Math.max(0, Math.min(255, Math.round(Number(opts.direction ?? this.state.lighting.direction ?? 1))));
    const packed = ((speed & 0x0F) << 4) | (brightness & 0x0F);

    let payload;
    let len;

    if (mode === 1) {
      len = 3;
      payload = [mode, packed, direction];
    } else if (mode === 2) {
      len = 0x18;
      const brColors = Array.isArray(opts.breathingColors) && opts.breathingColors.length >= 7
        ? opts.breathingColors
        : this.state.lighting.breathingColors;
      payload = [mode, packed, 0x07];
      for (let i = 0; i < 7; i += 1) {
        const [r, g, b] = hexToRgb(brColors[i] || '#FFFFFF');
        payload.push(r, g, b);
      }
    } else if (mode === 3) {
      len = 5;
      const [r, g, b] = hexToRgb(opts.color || this.state.lighting.color || '#2563EB');
      payload = [mode, packed, r, g, b];
    } else {
      len = 2;
      payload = [mode, packed];
    }

    await this.#writeChecked(0x05, payload, { length: len });
    const r15 = await this.#readRegister(0x15);
    this.state.lighting = decodeLightingPacket(r15);
    this.#emitStateChange();
    return { ...this.state.lighting };
  }

  /**
   * Write sensor tuning (`0x06`: LOD, Angle Snap, Ripple Control, Motion Sync) and verify via `0x16`.
   * Note: On live M220 v3.17, firmware may lock `MotionSync` to `0x01` even when `false` is written;
   * this method reads back `0x16` and records `state.motionSyncLocked = true` when mismatch occurs.
   */
  async setSensorSettings(opts = {}) {
    const lod = Math.max(1, Math.min(3, Math.round(Number(opts.lod ?? this.state.lod ?? 1))));
    const angleSnap = Boolean(opts.angleSnap ?? this.state.angleSnap);
    const ripple = Boolean(opts.ripple ?? this.state.ripple);
    const requestedMotionSync = Boolean(opts.motionSync ?? this.state.motionSync);

    const payload = [
      lod,
      angleSnap ? 1 : 0,
      ripple ? 1 : 0,
      requestedMotionSync ? 1 : 0,
      0x00,
    ];

    await this.#writeChecked(0x06, payload, { length: 0x05 });
    const r16 = await this.#readRegister(0x16);
    const actual = decodeSensorPacket(r16);

    this.state.lod = actual.lod;
    this.state.angleSnap = actual.angleSnap;
    this.state.ripple = actual.ripple;
    this.state.motionSync = actual.motionSync;
    this.state.motionSyncLocked = opts.motionSync !== undefined && actual.motionSync !== requestedMotionSync;

    this.#emitStateChange();
    return {
      lod: this.state.lod,
      angleSnap: this.state.angleSnap,
      ripple: this.state.ripple,
      motionSync: this.state.motionSync,
      motionSyncLocked: this.state.motionSyncLocked,
    };
  }

  /**
   * Write Sleep & Debounce (`0x07`) and read back `0x17`.
   * Debounce empirically supports `0..30 ms` on live M220 firmware (`len=4`).
   */
  async setSleepAndDebounce(opts = {}) {
    const sleep10s = opts.sleep10s !== undefined
      ? Math.max(1, Math.min(255, Math.round(Number(opts.sleep10s))))
      : opts.sleepSec !== undefined
        ? Math.max(1, Math.min(255, Math.round(Number(opts.sleepSec) / 10)))
        : this.state.sleep10s;
    const moveWake = Boolean(opts.moveWake ?? this.state.moveWake);
    const moveCloseLight = Boolean(opts.moveCloseLight ?? this.state.moveCloseLight);
    const debounceMs = Math.max(0, Math.min(30, Math.round(Number(opts.debounceMs ?? this.state.debounceMs ?? 8))));

    const payload = [
      sleep10s & 0xFF,
      moveWake ? 1 : 0,
      moveCloseLight ? 1 : 0,
      debounceMs & 0xFF,
    ];

    await this.#writeChecked(0x07, payload, { length: 0x04 });
    const r17 = await this.#readRegister(0x17);
    const actual = decodeSleepPacket(r17);
    this.state.sleep10s = actual.sleep10s;
    this.state.sleepSec = actual.sleepSec;
    this.state.moveWake = actual.moveWake;
    this.state.moveCloseLight = actual.moveCloseLight;
    this.state.debounceMs = actual.debounceMs;
    this.#emitStateChange();
    return actual;
  }

  /**
   * Write all 6 button descriptors (`0x09`) and verify via `0x11`.
   * Matches official `SetMouseKeyMacroData` (`len = 0x0F` with all 6x3B populated in `[4..21]`).
   */
  async setButtons(buttons) {
    const payload = new Uint8Array(18);
    for (let i = 0; i < 6; i += 1) {
      const action = buttons[i] || this.state.buttons[i];
      const [b0, b1, b2] = encodeButtonDescriptor(action, i);
      const off = i * 3;
      payload[off] = b0;
      payload[off + 1] = b1;
      payload[off + 2] = b2;
    }
    await this.#writeChecked(0x09, payload, { length: 0x0F });
    const r11 = await this.#readRegister(0x11);
    this.state.buttons = decodeButtonsPacket(r11);
    this.#emitStateChange();
    return this.state.buttons;
  }

  /**
   * Update a single button slot `0..5` while preserving all other slots.
   */
  async setButtonAction(slotIndex, actionSpec) {
    const slot = Math.max(0, Math.min(5, Math.round(Number(slotIndex))));
    const updated = this.state.buttons.map((b, i) => (i === slot ? actionSpec : b));
    return this.setButtons(updated);
  }

  /**
   * Compile and transmit a macro for `keyIdx` (`0..5`) using 27-byte `0x08` chunks.
   */
  async writeMacro(keyIdx, events, bindOptions = null) {
    if (!Array.isArray(events)) {
      throw createProtocolError('MISSING_EVENTS_ARRAY', 'Macro events must be an array');
    }
    const slot = Math.max(0, Math.min(5, Math.round(Number(keyIdx))));
    const stream = compileMacroStream(events, slot);
    const packets = frameMacroChunks(slot, stream);

    const acks = [];
    await this.#enqueue(async () => {
      for (const pkt of packets) {
        const rx = await this.#sendAndWait(pkt, 0x08, { isWrite: true });
        const status = rx ? (rx[1] & 0xFF) : 0xFF;
        if (rx && status === 0x03) {
          throw createProtocolError(
            'HARDWARE_REJECTED',
            'Hardware rejected macro chunk (0x08, status=0x03)',
            { cmd: 0x08, status, tx: pkt, rx }
          );
        }
        acks.push({ ok: Boolean(rx && status === 0), status, tx: pkt, rx });
      }
    });

    if (bindOptions && bindOptions.bindButton !== false) {
      await this.setButtonAction(slot, {
        type: 'macro',
        slotIndex: slot,
        loopMode: bindOptions.loopMode || 'count',
        loopCount: bindOptions.loopCount ?? 1,
      });
    }

    return {
      keyIdx: slot,
      chunks: packets.length,
      byteLength: stream.length,
      packets,
      acks,
    };
  }

  /**
   * Send `0x0E` light/factory-preview helper (`SetMouseResetLight`).
   */
  async sendLightReset(value = 0x01) {
    return this.#writeChecked(0x0E, [value & 0xFF], { length: 0x01 });
  }

  /**
   * Issue hardware `0x0F` Factory Reset (`[0x0F, 0x00, 0x01, 0x01, 0xFF]`), then re-sync registers.
   */
  async factoryResetDevice() {
    await this.#writeChecked(0x0F, [0xFF], { length: 0x01 });
    return this.syncAll();
  }

  /**
   * Apply official `config.xml` / `mouse_vk m3*.xml` factory defaults over safe write commands.
   */
  async restoreXmlFactoryDefaults(modelKey = this.state.modelKey) {
    const profile = MODEL_PROFILES[modelKey] || MODEL_PROFILES.VK_M3_LITE;
    const d = profile.factoryDefaults;
    await this.setPollingRate(d.pollingHz, { force: true });
    await this.setDpiConfig({
      activeIndex: d.activeDpiStage,
      stages: d.stages,
      unlockMax: false,
      writeColors: true,
    });
    await this.setLighting(d.lighting);
    await this.setSensorSettings({
      lod: d.lod,
      angleSnap: d.angleSnap,
      ripple: d.ripple,
      motionSync: d.motionSync,
    });
    await this.setSleepAndDebounce({
      sleepSec: d.sleepSec,
      moveWake: d.moveWake,
      moveCloseLight: d.moveCloseLight,
      debounceMs: d.debounceMs,
    });
    await this.setButtons(d.buttons);
    return this.getState();
  }

  /**
   * Export a raw EEPROM register snapshot compatible with `virgin_backup.json`.
   */
  async exportSnapshot({ refresh = true } = {}) {
    if (refresh) {
      await this.dumpAllRegisters();
    }
    return {
      schema: 'valkyrie-snapshot-v1',
      timestamp: new Date().toISOString(),
      device: {
        vid: this.state.vendorId,
        pid: this.state.productId,
        devId: this.state.devId,
        fwVersion: this.state.fwVersion,
        isWireless: this.state.isWireless,
      },
      regs: this.getRawRegisters(),
    };
  }

  /**
   * Validate and normalize an imported baseline snapshot (`virgin_backup.json` or `valkyrie-snapshot-v1`).
   */
  importSnapshot(jsonOrObject) {
    const parsed = typeof jsonOrObject === 'string' ? JSON.parse(jsonOrObject) : jsonOrObject;
    const regs = normalizeRegisterMap(parsed);
    if (Object.keys(regs).length === 0) {
      throw createProtocolError('INVALID_SNAPSHOT', 'Snapshot contains no recognizable registers');
    }
    const hexRegs = {};
    for (const [k, v] of Object.entries(regs)) {
      hexRegs[k] = formatHex(v);
    }
    return {
      device: parsed?.device || null,
      regs: hexRegs,
    };
  }

  /**
   * Safely roll back device settings from a virgin/baseline snapshot using ONLY the
   * verified safe rollback write set `[0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09]`.
   * Read-only and stall-prone opcodes are never written.
   */
  async safeRollback(snapshotOrRegs) {
    const regs = normalizeRegisterMap(snapshotOrRegs);
    const written = [];

    for (const { readCmd, writeCmd, forceLen } of SAFE_ROLLBACK_WRITE_PAIRS) {
      const readKey = `0x${readCmd.toString(16).toUpperCase().padStart(2, '0')}`;
      const rawPkt = regs[readKey];
      if (!rawPkt || rawPkt.length < 32) continue;

      const payload = rawPkt.subarray(4, 31);
      const len = forceLen !== null ? forceLen : (rawPkt[3] & 0xFF);
      await this.#writeChecked(writeCmd, payload, { length: len });
      written.push(`0x${writeCmd.toString(16).toUpperCase().padStart(2, '0')}`);
    }

    await this.syncAll({ includeDongle: this.isWireless || Boolean(regs['0x20']) });
    const diff = computeSnapshotDiff(regs, this.#rawRegs);
    return { written, diff, state: this.getState() };
  }

  /**
   * Compare a baseline snapshot against live cached registers (256-bit diff grid per register).
   */
  diffSnapshot(baselineSnapshotOrRegs) {
    return computeSnapshotDiff(baselineSnapshotOrRegs, this.#rawRegs);
  }
}
