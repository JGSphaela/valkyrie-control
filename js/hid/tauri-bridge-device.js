/**
 * Valkyrie Tauri v2 Native HID Bridge (`HIDDevice`-compatible `EventTarget`)
 *
 * Bridges `ValkyrieM220Device` and `WebHidManager` directly to the Rust `hidapi`
 * commands (`list_valkyrie_devices`, `open_valkyrie_device`, `close_valkyrie_device`,
 * `send_valkyrie_report`) and events (`valkyrie://inputreport`, `valkyrie://disconnect`)
 * inside the Tauri Windows desktop application.
 *
 * Security invariants mirrored from `WebHidManager` and `ValkyrieM220Device`:
 * - Strictly validates `VALKYRIE_VIDS` and 32-byte `ALLOWED_COMMAND_INTERFACES`
 *   (`0xFF01/0x0010` or `0x0001/0x0000`), never accepting `0xFFEF` OTA nodes.
 * - Enforces `reportId === 0`, 32-byte payload length, and `isAllowedOpcode(payload[0])`
 *   BEFORE invoking `send_valkyrie_report`.
 */

import {
  ALLOWED_COMMAND_INTERFACES,
  FORBIDDEN_OTA_INTERFACE,
  VALKYRIE_VIDS,
} from '../devices.js';
import {
  REPORT_ID,
  REPORT_SIZE,
  createProtocolError,
  isAllowedOpcode,
} from '../protocol/m220-device.js';

export const TAURI_EVENT_INPUT_REPORT = 'valkyrie://inputreport';
export const TAURI_EVENT_DISCONNECT = 'valkyrie://disconnect';

/**
 * Resolve `{ invoke, listen }` from an explicit `tauriApi` object or a window global
 * (`window.__TAURI__` / `window.__TAURI_INTERNALS__`). Returns `null` if unavailable.
 *
 * @param {object} [target]
 * @returns {{ invoke: Function, listen: Function }|null}
 */
export function resolveTauriApi(target) {
  const resolved = target ?? (typeof window !== 'undefined' ? window : undefined);
  if (!resolved || typeof resolved !== 'object') return null;

  // Direct injectable mock shape: { invoke, listen }
  if (typeof resolved.invoke === 'function' && typeof resolved.listen === 'function') {
    return {
      invoke: resolved.invoke.bind(resolved),
      listen: resolved.listen.bind(resolved),
    };
  }

  // Nested mock/global shape: { core: { invoke }, event: { listen } }
  if (typeof resolved.core?.invoke === 'function' && typeof resolved.event?.listen === 'function') {
    return {
      invoke: resolved.core.invoke.bind(resolved.core),
      listen: resolved.event.listen.bind(resolved.event),
    };
  }

  const tauri = resolved.__TAURI__;
  const internals = resolved.__TAURI_INTERNALS__;

  const invokeFn = (typeof tauri?.core?.invoke === 'function' && tauri.core.invoke.bind(tauri.core))
    || (typeof tauri?.invoke === 'function' && tauri.invoke.bind(tauri))
    || (typeof internals?.invoke === 'function' && internals.invoke.bind(internals))
    || null;

  const listenFn = (typeof tauri?.event?.listen === 'function' && tauri.event.listen.bind(tauri.event))
    || (typeof internals?.listen === 'function' && internals.listen.bind(internals))
    || null;

  if (invokeFn && listenFn) {
    return { invoke: invokeFn, listen: listenFn };
  }

  return null;
}

/**
 * Detect whether execution is running inside a Tauri runtime with `invoke` + `listen` support.
 * Also supports passing a mock `window` or `tauriApi` object in unit tests.
 *
 * @param {object} [win]
 * @returns {boolean}
 */
export function isTauriRuntime(win = typeof window !== 'undefined' ? window : undefined) {
  return resolveTauriApi(win) !== null;
}

function isValidCommandCollection(usagePage, usage, inputReportBytes, outputReportBytes) {
  if (usagePage === FORBIDDEN_OTA_INTERFACE.usagePage) {
    return false;
  }
  const matchesInterface = ALLOWED_COMMAND_INTERFACES.some(
    (iface) => iface.usagePage === usagePage && iface.usage === usage
  );
  if (!matchesInterface) {
    return false;
  }
  if (inputReportBytes != null && Number(inputReportBytes) !== REPORT_SIZE) {
    return false;
  }
  if (outputReportBytes != null && Number(outputReportBytes) !== REPORT_SIZE) {
    return false;
  }
  return true;
}

function isValidTauriDeviceEntry(entry) {
  if (!entry || typeof entry !== 'object') return false;
  const vendorId = Number(entry.vendorId);
  const productId = Number(entry.productId);
  if (!VALKYRIE_VIDS.includes(vendorId) || !Number.isInteger(productId)) {
    return false;
  }
  return isValidCommandCollection(
    Number(entry.usagePage),
    Number(entry.usage),
    entry.inputReportBytes,
    entry.outputReportBytes
  );
}

function normalizeTauriDeviceEntry(entry) {
  return {
    id: entry.id != null ? String(entry.id) : '',
    vendorId: Number(entry.vendorId),
    productId: Number(entry.productId),
    productName: String(entry.productName || 'Valkyrie VK M3 Series'),
    usagePage: Number(entry.usagePage),
    usage: Number(entry.usage),
    inputReportBytes: entry.inputReportBytes != null ? Number(entry.inputReportBytes) : REPORT_SIZE,
    outputReportBytes: entry.outputReportBytes != null ? Number(entry.outputReportBytes) : REPORT_SIZE,
    isWireless: Boolean(entry.isWireless),
  };
}

function sortTauriDevices(devices) {
  return (devices || [])
    .filter(isValidTauriDeviceEntry)
    .map(normalizeTauriDeviceEntry)
    .sort((a, b) => (a.usagePage === 0xFF01 ? 0 : 1) - (b.usagePage === 0xFF01 ? 0 : 1));
}

/**
 * Validate and pick the preferred Valkyrie 32-byte command interface from a device list.
 * Rejects `0xFFEF` OTA devices and unknown VIDs; prefers `(0xFF01, 0x0010)` before `(0x0001, 0x0000)`.
 *
 * @param {Array<object>} devices
 * @returns {object|null}
 */
export function selectPreferredTauriDevice(devices) {
  const valid = sortTauriDevices(devices);
  return valid[0] || null;
}

function translateTauriError(err, fallbackCode = 'TAURI_HID_ERROR') {
  if (err && typeof err === 'object' && typeof err.code === 'string') {
    return err;
  }
  const rawMessage = typeof err === 'string' ? err : (err?.message || String(err || 'Tauri HID error'));
  const match = /^([A-Z][A-Z0-9_]+):\s*(.*)$/.exec(rawMessage);
  if (match) {
    return createProtocolError(match[1], match[2] || rawMessage);
  }
  return createProtocolError(fallbackCode, rawMessage);
}

/**
 * Query Tauri `list_valkyrie_devices` and return validated, priority-sorted command devices.
 *
 * @param {{ tauriApi?: object }} [options]
 * @returns {Promise<Array<object>>}
 */
export async function listTauriDevices({ tauriApi } = {}) {
  const api = resolveTauriApi(tauriApi);
  if (!api) {
    throw createProtocolError(
      'TAURI_UNAVAILABLE',
      'Tauri native HID bridge is not available in this environment'
    );
  }

  let rawDevices;
  try {
    rawDevices = await api.invoke('list_valkyrie_devices');
  } catch (err) {
    throw translateTauriError(err);
  }

  return sortTauriDevices(Array.isArray(rawDevices) ? rawDevices : []);
}

/**
 * WebHID `HIDDevice`-compatible bridge backed by Tauri v2 native `hidapi` IPC.
 */
export class TauriBridgeHidDevice extends EventTarget {
  /**
   * @param {object} deviceInfo
   * @param {{
   *   tauriApi?: object,
   *   onDisconnect?: (device: TauriBridgeHidDevice) => void,
   * }} [options]
   */
  constructor(deviceInfo = {}, options = {}) {
    super();
    this.vendorId = Number(deviceInfo.vendorId ?? 0x248A);
    this.productId = Number(deviceInfo.productId ?? 0x5D2E);
    this.productName = String(deviceInfo.productName || 'Valkyrie VK M3 Series');
    this.deviceId = deviceInfo.id != null ? String(deviceInfo.id) : '';
    this.isWireless = Boolean(deviceInfo.isWireless);
    this.opened = false;
    this.transport = 'tauri';

    const usagePage = Number(deviceInfo.usagePage ?? 0x0001);
    const usage = Number(deviceInfo.usage ?? 0x0000);
    const inBytes = deviceInfo.inputReportBytes != null ? Number(deviceInfo.inputReportBytes) : REPORT_SIZE;
    const outBytes = deviceInfo.outputReportBytes != null ? Number(deviceInfo.outputReportBytes) : REPORT_SIZE;

    this.usagePage = usagePage;
    this.usage = usage;
    this.collections = [
      {
        usagePage,
        usage,
        inputReports: [{ reportId: REPORT_ID, items: [{ reportSize: 8, reportCount: inBytes }] }],
        outputReports: [{ reportId: REPORT_ID, items: [{ reportSize: 8, reportCount: outBytes }] }],
        featureReports: [],
      },
    ];

    this.#tauriApi = options.tauriApi || null;
    this.#onDisconnect = typeof options.onDisconnect === 'function' ? options.onDisconnect : null;
    this.#unlistenReport = null;
    this.#unlistenDisconnect = null;
    this.#closing = false;
    this.#disconnectNotified = false;
  }

  #tauriApi;
  #onDisconnect;
  #unlistenReport;
  #unlistenDisconnect;
  #closing;
  #disconnectNotified;

  #requireApi() {
    const api = resolveTauriApi(this.#tauriApi);
    if (!api) {
      throw createProtocolError(
        'TAURI_UNAVAILABLE',
        'Tauri native HID bridge is not available in this environment'
      );
    }
    return api;
  }

  #validateInterfaceOrThrow() {
    if (
      this.usagePage === FORBIDDEN_OTA_INTERFACE.usagePage
      && this.usage === FORBIDDEN_OTA_INTERFACE.usage
    ) {
      throw createProtocolError(
        'OTA_COLLECTION_BLOCKED',
        'Blocked attempt to open 64-byte (0xFFEF, 0x0000) OTA/DFU HID interface via Tauri'
      );
    }

    const col = this.collections[0];
    const inBytes = col?.inputReports?.[0]?.items?.[0]?.reportCount;
    const outBytes = col?.outputReports?.[0]?.items?.[0]?.reportCount;

    if (
      !VALKYRIE_VIDS.includes(this.vendorId)
      || !isValidCommandCollection(this.usagePage, this.usage, inBytes, outBytes)
    ) {
      throw createProtocolError(
        'NO_COMMAND_INTERFACE',
        'Tauri HID device does not match a valid 32-byte Valkyrie command interface'
      );
    }
  }

  #cleanupListeners() {
    const unlistenReport = this.#unlistenReport;
    const unlistenDisconnect = this.#unlistenDisconnect;
    this.#unlistenReport = null;
    this.#unlistenDisconnect = null;

    if (typeof unlistenReport === 'function') {
      try {
        const res = unlistenReport();
        if (res && typeof res.catch === 'function') res.catch(() => {});
      } catch {
        // Ignore unlisten error
      }
    }
    if (typeof unlistenDisconnect === 'function') {
      try {
        const res = unlistenDisconnect();
        if (res && typeof res.catch === 'function') res.catch(() => {});
      } catch {
        // Ignore unlisten error
      }
    }
  }

  #triggerUnexpectedDisconnect() {
    if (this.#closing || this.#disconnectNotified || !this.opened) return;
    this.#disconnectNotified = true;
    this.opened = false;
    this.#cleanupListeners();
    if (this.#onDisconnect) {
      this.#onDisconnect(this);
    }
  }

  #handleInputReportEvent(event) {
    const payload = event?.payload;
    if (!payload || !Array.isArray(payload.bytes)) return;
    if (payload.id && this.deviceId && String(payload.id) !== this.deviceId) return;

    const bytes = Uint8Array.from(payload.bytes, (v) => Number(v) & 0xFF);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const ev = new Event('inputreport');
    Object.assign(ev, {
      data: view,
      reportId: Number(payload.reportId ?? REPORT_ID),
      device: this,
    });
    this.dispatchEvent(ev);
  }

  #handleDisconnectEvent(event) {
    const payload = event?.payload;
    if (payload?.id && this.deviceId && String(payload.id) !== this.deviceId) return;
    this.#triggerUnexpectedDisconnect();
  }

  async open() {
    this.#validateInterfaceOrThrow();
    if (this.opened) return;

    const api = this.#requireApi();
    this.#closing = false;
    this.#disconnectNotified = false;

    // Subscribe BEFORE opening so early HID reports or unplug events cannot race
    try {
      this.#unlistenReport = await api.listen(TAURI_EVENT_INPUT_REPORT, (ev) => {
        this.#handleInputReportEvent(ev);
      });
      this.#unlistenDisconnect = await api.listen(TAURI_EVENT_DISCONNECT, (ev) => {
        this.#handleDisconnectEvent(ev);
      });
    } catch (err) {
      this.#cleanupListeners();
      throw translateTauriError(err);
    }

    let openedInfo;
    try {
      openedInfo = await api.invoke('open_valkyrie_device', { deviceId: this.deviceId });
    } catch (err) {
      this.#cleanupListeners();
      throw translateTauriError(err);
    }

    if (this.#closing) {
      this.#cleanupListeners();
      try {
        await api.invoke('close_valkyrie_device');
      } catch {
        // Best-effort cleanup
      }
      return;
    }

    if (openedInfo && typeof openedInfo === 'object') {
      if (Number(openedInfo.usagePage) === FORBIDDEN_OTA_INTERFACE.usagePage) {
        this.#cleanupListeners();
        try {
          await api.invoke('close_valkyrie_device');
        } catch {
          // Best-effort cleanup
        }
        throw createProtocolError(
          'OTA_COLLECTION_BLOCKED',
          'Tauri backend returned forbidden 0xFFEF OTA interface on open'
        );
      }
      if (openedInfo.id != null) this.deviceId = String(openedInfo.id);
      if (openedInfo.productName) this.productName = String(openedInfo.productName);
      if (openedInfo.isWireless != null) this.isWireless = Boolean(openedInfo.isWireless);
    }

    this.opened = true;
  }

  /**
   * Transmit a 32-byte HID output report via `invoke('send_valkyrie_report')`.
   * Strictly enforces `reportId === 0`, 32-byte payload length, and
   * `isAllowedOpcode(payload[0])` BEFORE invoking Tauri IPC.
   *
   * @param {number} reportId
   * @param {Uint8Array|Array<number>|DataView} data
   */
  async sendReport(reportId, data) {
    if (reportId !== REPORT_ID) {
      throw createProtocolError(
        'STALL_GUARD_BLOCKED',
        `Stall guard blocked non-zero reportId (${reportId})`,
        { reportId }
      );
    }

    const raw = data instanceof Uint8Array
      ? data
      : (ArrayBuffer.isView(data)
        ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
        : Uint8Array.from(data || []));

    if (raw.length === 0) {
      throw createProtocolError(
        'STALL_GUARD_BLOCKED',
        'Stall guard blocked empty report payload'
      );
    }

    const cmd = raw[0] & 0xFF;
    if (!isAllowedOpcode(cmd)) {
      const cmdHex = `0x${cmd.toString(16).toUpperCase().padStart(2, '0')}`;
      throw createProtocolError(
        'STALL_GUARD_BLOCKED',
        `Stall guard blocked disallowed outbound opcode ${cmdHex}`,
        { cmd }
      );
    }

    if (raw.length !== REPORT_SIZE) {
      throw createProtocolError(
        'INVALID_REPORT_LENGTH',
        `Expected ${REPORT_SIZE}-byte Valkyrie report payload, got ${raw.length}`,
        { length: raw.length }
      );
    }

    if (!this.opened) {
      throw createProtocolError('DEVICE_DISPOSED', 'Tauri HID device is not open');
    }

    const api = this.#requireApi();
    try {
      await api.invoke('send_valkyrie_report', {
        reportId: REPORT_ID,
        payload: Array.from(raw),
      });
    } catch (err) {
      const mapped = translateTauriError(err);
      if (mapped.code === 'HID_NOT_CONNECTED') {
        this.#triggerUnexpectedDisconnect();
      }
      throw mapped;
    }
  }

  async close() {
    if (this.#closing) {
      this.opened = false;
      this.#cleanupListeners();
      return;
    }
    this.#closing = true;
    const wasOpened = this.opened;
    this.opened = false;
    this.#cleanupListeners();

    if (wasOpened) {
      try {
        const api = resolveTauriApi(this.#tauriApi);
        if (api) {
          await api.invoke('close_valkyrie_device');
        }
      } catch {
        // Best-effort close
      }
    }
  }
}
