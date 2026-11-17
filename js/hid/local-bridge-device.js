/**
 * Valkyrie Local Helper Bridge (`HIDDevice`-compatible `EventTarget`)
 *
 * Connects static browser origins (`http://localhost`, `https://*.github.io`)
 * to the localhost-only Valkyrie Companion Helper (`127.0.0.1:19480`) over
 * HTTP + NDJSON when Windows Chrome/Edge 157+ prunes the `MI_02` HID interface.
 *
 * Security invariants mirrored from `WebHidManager` and `ValkyrieM220Device`:
 * - Zero background localhost polling on load (only called on explicit user action).
 * - Strictly validates `VALKYRIE_VIDS` and 32-byte `ALLOWED_COMMAND_INTERFACES`
 *   (`0xFF01/0x0010` or `0x0001/0x0000`), never accepting `0xFFEF` OTA nodes.
 * - Enforces `reportId === 0` and `isAllowedOpcode(payload[0])` BEFORE `fetch()`.
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

export const DEFAULT_HELPER_BASE_URL = 'http://127.0.0.1:19480';

function normalizeBaseUrl(baseUrl) {
  if (!baseUrl) return DEFAULT_HELPER_BASE_URL;
  return String(baseUrl).trim().replace(/\/+$/, '') || DEFAULT_HELPER_BASE_URL;
}

function resolveFetch(fetchImpl) {
  if (typeof fetchImpl === 'function') return fetchImpl;
  if (typeof globalThis.fetch === 'function') {
    return globalThis.fetch.bind(globalThis);
  }
  throw createProtocolError(
    'LOCAL_HELPER_UNAVAILABLE',
    'Fetch API is unavailable for Local Helper transport'
  );
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

function isValidHelperDeviceEntry(entry) {
  if (!entry || typeof entry !== 'object') return false;
  const vendorId = Number(entry.vendorId);
  const productId = Number(entry.productId);
  if (!VALKYRIE_VIDS.includes(vendorId) || !Number.isInteger(productId)) {
    return false;
  }
  const usagePage = Number(entry.usagePage);
  const usage = Number(entry.usage);
  return isValidCommandCollection(
    usagePage,
    usage,
    entry.inputReportBytes,
    entry.outputReportBytes
  );
}

function normalizeHelperDeviceEntry(entry) {
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

/**
 * Select the highest-priority valid command interface from a helper device list.
 * Preference order matches `WebHidManager`: `(0xFF01, 0x0010)` before `(0x0001, 0x0000)`.
 *
 * @param {Array<object>} devices
 * @returns {object|null}
 */
export function selectPreferredHelperDevice(devices) {
  const valid = [];
  for (const entry of devices || []) {
    if (!isValidHelperDeviceEntry(entry)) continue;
    const normalized = normalizeHelperDeviceEntry(entry);
    const priority = normalized.usagePage === 0xFF01 ? 0 : 1;
    valid.push({ entry: normalized, priority });
  }
  valid.sort((a, b) => a.priority - b.priority);
  return valid[0]?.entry || null;
}

async function translateHelperFetchError(err, baseUrl, hasCustomFetch) {
  if (
    err?.code === 'LOCAL_HELPER_UNAVAILABLE'
    || err?.code === 'LOCAL_HELPER_NO_DEVICE'
    || err?.code === 'LOCAL_HELPER_BLOCKED'
  ) {
    return err;
  }

  if (!hasCustomFetch && typeof navigator !== 'undefined' && navigator.permissions && typeof navigator.permissions.query === 'function') {
    try {
      const status = await navigator.permissions.query({ name: 'local-network-access' });
      if (status?.state === 'denied') {
        return createProtocolError(
          'LOCAL_HELPER_BLOCKED',
          `Browser blocked Local Network Access to ${baseUrl}. Allow Local Network Access and retry.`,
          { baseUrl, cause: err }
        );
      }
    } catch {
      // Browser/runtime does not support 'local-network-access' permission query
    }
  }

  const msg = String(err?.message || '');
  if (err?.name === 'NotAllowedError' || /local network|private network|permission denied/i.test(msg)) {
    return createProtocolError(
      'LOCAL_HELPER_BLOCKED',
      `Browser blocked access to the Valkyrie Local Helper at ${baseUrl}. Allow Local Network Access and retry.`,
      { baseUrl, cause: err }
    );
  }

  return createProtocolError(
    'LOCAL_HELPER_UNAVAILABLE',
    `Could not reach Valkyrie Local Helper at ${baseUrl}: ${msg || 'connection failed'}`,
    { baseUrl, cause: err }
  );
}

async function safeReadJson(res) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * Query `GET /api/devices` on the Local Companion Helper and return validated
 * 32-byte Valkyrie `MI_02` device descriptors sorted by interface priority.
 *
 * @param {{ baseUrl?: string, fetchImpl?: typeof fetch }} [options]
 * @returns {Promise<Array<object>>}
 */
export async function fetchHelperDevices({ baseUrl, fetchImpl } = {}) {
  const base = normalizeBaseUrl(baseUrl);
  const fetchFn = resolveFetch(fetchImpl);
  const hasCustomFetch = typeof fetchImpl === 'function';

  let res;
  try {
    res = await fetchFn(`${base}/api/devices`, {
      method: 'GET',
      cache: 'no-store',
    });
  } catch (err) {
    throw await translateHelperFetchError(err, base, hasCustomFetch);
  }

  const body = await safeReadJson(res);

  if (!res.ok) {
    if (res.status === 404 || body?.error === 'NO_COMMAND_INTERFACE' || body?.error === 'LOCAL_HELPER_NO_DEVICE') {
      throw createProtocolError(
        'LOCAL_HELPER_NO_DEVICE',
        body?.message || 'Local Helper is running, but no supported Valkyrie MI_02 device was found.',
        { baseUrl: base, status: res.status }
      );
    }
    if (res.status === 403) {
      throw createProtocolError(
        'LOCAL_HELPER_BLOCKED',
        body?.message || `Access to Local Helper at ${base} was forbidden`,
        { baseUrl: base, status: res.status }
      );
    }
    throw createProtocolError(
      'LOCAL_HELPER_UNAVAILABLE',
      body?.message || `Local Helper /api/devices failed with HTTP ${res.status}`,
      { baseUrl: base, status: res.status }
    );
  }

  if (!body || body.ok === false || !Array.isArray(body.devices)) {
    if (body?.error === 'NO_COMMAND_INTERFACE' || body?.error === 'LOCAL_HELPER_NO_DEVICE') {
      throw createProtocolError(
        'LOCAL_HELPER_NO_DEVICE',
        body?.message || 'Local Helper reported no matching Valkyrie MI_02 device.',
        { baseUrl: base }
      );
    }
    throw createProtocolError(
      'LOCAL_HELPER_UNAVAILABLE',
      'Local Helper returned an invalid /api/devices payload',
      { baseUrl: base }
    );
  }

  const valid = body.devices
    .filter(isValidHelperDeviceEntry)
    .map(normalizeHelperDeviceEntry)
    .sort((a, b) => (a.usagePage === 0xFF01 ? 0 : 1) - (b.usagePage === 0xFF01 ? 0 : 1));

  if (valid.length === 0) {
    throw createProtocolError(
      'LOCAL_HELPER_NO_DEVICE',
      'Local Helper is running, but no valid 32-byte Valkyrie MI_02 interface (0xFF01/0x0010 or 0x0001/0x0000) was found.',
      { baseUrl: base }
    );
  }

  return valid;
}

/**
 * WebHID `HIDDevice`-compatible bridge backed by the local companion HTTP+NDJSON API.
 */
export class LocalBridgeHidDevice extends EventTarget {
  /**
   * @param {object} deviceInfo
   * @param {{
   *   baseUrl?: string,
   *   fetchImpl?: typeof fetch,
   *   onDisconnect?: (device: LocalBridgeHidDevice) => void,
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
    this.transport = 'local-helper';
    this.helperBaseUrl = normalizeBaseUrl(options.baseUrl ?? deviceInfo.helperBaseUrl);

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

    this.#fetchImpl = typeof options.fetchImpl === 'function' ? options.fetchImpl : null;
    this.#onDisconnect = typeof options.onDisconnect === 'function' ? options.onDisconnect : null;
    this.#streamAbort = null;
    this.#streamReader = null;
    this.#streamTask = null;
    this.#closing = false;
    this.#disconnectNotified = false;
  }

  #fetchImpl;
  #onDisconnect;
  #streamAbort;
  #streamReader;
  #streamTask;
  #closing;
  #disconnectNotified;

  #validateInterfaceOrThrow() {
    if (
      this.usagePage === FORBIDDEN_OTA_INTERFACE.usagePage
      && this.usage === FORBIDDEN_OTA_INTERFACE.usage
    ) {
      throw createProtocolError(
        'OTA_COLLECTION_BLOCKED',
        'Blocked attempt to open 64-byte (0xFFEF, 0x0000) OTA/DFU HID interface via Local Helper'
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
        'Local Helper device does not match a valid 32-byte Valkyrie command interface'
      );
    }
  }

  async #bestEffortRemoteClose() {
    try {
      const fetchFn = resolveFetch(this.#fetchImpl);
      await fetchFn(`${this.helperBaseUrl}/api/close`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
    } catch {
      // Ignore network/close errors during cleanup
    }
  }

  #triggerUnexpectedDisconnect() {
    if (this.#closing || this.#disconnectNotified || !this.opened) return;
    this.#disconnectNotified = true;
    this.opened = false;
    if (this.#streamAbort) {
      this.#streamAbort.abort();
      this.#streamAbort = null;
    }
    if (this.#streamReader) {
      this.#streamReader.cancel().catch(() => {});
      this.#streamReader = null;
    }
    if (this.#onDisconnect) {
      this.#onDisconnect(this);
    }
  }

  #handleNdjsonLine(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    if (!msg || typeof msg !== 'object') return;

    if (msg.type === 'ready' || msg.type === 'ping') {
      return;
    }

    if (msg.type === 'disconnect') {
      this.#triggerUnexpectedDisconnect();
      return;
    }

    if (msg.type === 'inputreport' && Array.isArray(msg.data)) {
      const bytes = Uint8Array.from(msg.data, (v) => Number(v) & 0xFF);
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const ev = new Event('inputreport');
      Object.assign(ev, {
        data: view,
        reportId: Number(msg.reportId ?? REPORT_ID),
        device: this,
      });
      this.dispatchEvent(ev);
    }
  }

  #consumeEventStream(body, controller) {
    const reader = body.getReader();
    this.#streamReader = reader;
    const decoder = new TextDecoder();

    const run = async () => {
      let buffer = '';
      let sawDisconnectEvent = false;
      try {
        while (!this.#closing && !controller.signal.aborted) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value == null) continue;
          buffer += typeof value === 'string'
            ? value
            : decoder.decode(value, { stream: true });

          let nlIdx;
          while ((nlIdx = buffer.indexOf('\n')) !== -1) {
            const line = buffer.slice(0, nlIdx).trim();
            buffer = buffer.slice(nlIdx + 1);
            if (!line) continue;
            this.#handleNdjsonLine(line);
            if (this.#disconnectNotified) {
              sawDisconnectEvent = true;
              break;
            }
          }
          if (sawDisconnectEvent) break;
        }

        if (!this.#closing && !sawDisconnectEvent) {
          buffer += decoder.decode();
          const tail = buffer.trim();
          if (tail) {
            for (const part of tail.split('\n')) {
              const line = part.trim();
              if (line) this.#handleNdjsonLine(line);
            }
          }
        }
      } catch {
        // Stream aborted or dropped; handled in finally
      } finally {
        if (this.#streamReader === reader) {
          this.#streamReader = null;
        }
        try {
          reader.releaseLock();
        } catch {
          // Ignore if already released/cancelled
        }
        if (!this.#closing && !controller.signal.aborted && this.opened) {
          this.#triggerUnexpectedDisconnect();
        }
      }
    };

    return run();
  }

  async open() {
    this.#validateInterfaceOrThrow();
    if (this.opened) return;

    this.#closing = false;
    this.#disconnectNotified = false;

    const fetchFn = resolveFetch(this.#fetchImpl);
    const hasCustomFetch = typeof this.#fetchImpl === 'function';

    let openRes;
    try {
      openRes = await fetchFn(`${this.helperBaseUrl}/api/open`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(this.deviceId ? { deviceId: this.deviceId } : {}),
      });
    } catch (err) {
      throw await translateHelperFetchError(err, this.helperBaseUrl, hasCustomFetch);
    }

    const openBody = await safeReadJson(openRes);
    if (this.#closing) {
      if (openRes.ok && openBody?.ok !== false) {
        await this.#bestEffortRemoteClose();
      }
      return;
    }

    if (!openRes.ok || openBody?.ok === false) {
      if (openBody?.error === 'OTA_COLLECTION_BLOCKED') {
        throw createProtocolError(
          'OTA_COLLECTION_BLOCKED',
          openBody?.message || 'Helper blocked opening 0xFFEF OTA interface'
        );
      }
      if (openRes.status === 404 || openBody?.error === 'NO_COMMAND_INTERFACE' || openBody?.error === 'LOCAL_HELPER_NO_DEVICE') {
        throw createProtocolError(
          'LOCAL_HELPER_NO_DEVICE',
          openBody?.message || 'Local Helper could not find an openable Valkyrie MI_02 interface',
          { status: openRes.status }
        );
      }
      if (openRes.status === 403) {
        throw createProtocolError(
          'LOCAL_HELPER_BLOCKED',
          openBody?.message || 'Local Helper rejected /api/open request',
          { status: openRes.status }
        );
      }
      throw createProtocolError(
        'LOCAL_HELPER_UNAVAILABLE',
        openBody?.message || `Local Helper /api/open failed with HTTP ${openRes.status}`,
        { status: openRes.status }
      );
    }

    if (openBody?.device && typeof openBody.device === 'object') {
      const devMeta = openBody.device;
      if (Number(devMeta.usagePage) === FORBIDDEN_OTA_INTERFACE.usagePage) {
        await this.#bestEffortRemoteClose();
        throw createProtocolError(
          'OTA_COLLECTION_BLOCKED',
          'Helper returned forbidden 0xFFEF OTA interface on /api/open'
        );
      }
      if (devMeta.id != null) this.deviceId = String(devMeta.id);
      if (devMeta.productName) this.productName = String(devMeta.productName);
      if (devMeta.isWireless != null) this.isWireless = Boolean(devMeta.isWireless);
    }

    const controller = new AbortController();
    this.#streamAbort = controller;

    let eventsRes;
    try {
      eventsRes = await fetchFn(`${this.helperBaseUrl}/api/events`, {
        method: 'GET',
        cache: 'no-store',
        signal: controller.signal,
      });
    } catch (err) {
      this.#streamAbort = null;
      await this.#bestEffortRemoteClose();
      if (this.#closing || err?.name === 'AbortError') return;
      throw await translateHelperFetchError(err, this.helperBaseUrl, hasCustomFetch);
    }

    if (!eventsRes || !eventsRes.ok) {
      this.#streamAbort = null;
      await this.#bestEffortRemoteClose();
      throw createProtocolError(
        'LOCAL_HELPER_UNAVAILABLE',
        `Local Helper /api/events failed with HTTP ${eventsRes?.status ?? 'unknown'}`
      );
    }

    if (this.#closing || controller.signal.aborted) {
      this.#streamAbort = null;
      await eventsRes.body?.cancel?.().catch(() => {});
      await this.#bestEffortRemoteClose();
      return;
    }

    this.opened = true;

    if (eventsRes.body && typeof eventsRes.body.getReader === 'function') {
      this.#streamTask = this.#consumeEventStream(eventsRes.body, controller);
    }
  }

  /**
   * Transmit a 32-byte HID output report via `POST /api/report`.
   * Strictly enforces `reportId === 0` and `isAllowedOpcode(payload[0])` BEFORE calling `fetch()`.
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

    if (raw.length > REPORT_SIZE) {
      throw createProtocolError(
        'PAYLOAD_TOO_LARGE',
        `Report length ${raw.length} exceeds ${REPORT_SIZE}-byte Valkyrie packet capacity`
      );
    }

    const payload = new Uint8Array(REPORT_SIZE);
    payload.set(raw);

    const cmd = payload[0] & 0xFF;
    if (!isAllowedOpcode(cmd)) {
      const cmdHex = `0x${cmd.toString(16).toUpperCase().padStart(2, '0')}`;
      throw createProtocolError(
        'STALL_GUARD_BLOCKED',
        `Stall guard blocked disallowed outbound opcode ${cmdHex}`,
        { cmd }
      );
    }

    if (!this.opened) {
      throw createProtocolError('DEVICE_DISPOSED', 'Local Helper HID device is not open');
    }

    const fetchFn = resolveFetch(this.#fetchImpl);
    const hasCustomFetch = typeof this.#fetchImpl === 'function';

    let res;
    try {
      res = await fetchFn(`${this.helperBaseUrl}/api/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reportId: REPORT_ID,
          data: Array.from(payload),
        }),
      });
    } catch (err) {
      throw await translateHelperFetchError(err, this.helperBaseUrl, hasCustomFetch);
    }

    const body = await safeReadJson(res);
    if (!res.ok || body?.ok === false) {
      if (res.status === 403 || body?.error === 'STALL_GUARD_BLOCKED') {
        throw createProtocolError(
          'STALL_GUARD_BLOCKED',
          body?.message || 'Local Helper blocked disallowed outbound opcode',
          { cmd }
        );
      }
      if (
        res.status === 404
        || res.status === 409
        || body?.error === 'NO_COMMAND_INTERFACE'
        || body?.error === 'DEVICE_NOT_OPEN'
      ) {
        this.#triggerUnexpectedDisconnect();
        throw createProtocolError(
          'LOCAL_HELPER_NO_DEVICE',
          body?.message || 'Local Helper device is closed or disconnected'
        );
      }
      throw createProtocolError(
        'LOCAL_HELPER_UNAVAILABLE',
        body?.message || `Local Helper /api/report failed with HTTP ${res.status}`,
        { status: res.status }
      );
    }
  }

  async close() {
    if (this.#closing) {
      this.opened = false;
      return;
    }
    this.#closing = true;
    const wasOpened = this.opened;
    this.opened = false;

    if (this.#streamAbort) {
      this.#streamAbort.abort();
      this.#streamAbort = null;
    }
    if (this.#streamReader) {
      try {
        await this.#streamReader.cancel();
      } catch {
        // Ignore stream cancellation error
      }
      this.#streamReader = null;
    }

    if (wasOpened) {
      await this.#bestEffortRemoteClose();
    }

    if (this.#streamTask) {
      try {
        await this.#streamTask;
      } catch {
        // Ignore background stream close errors
      }
      this.#streamTask = null;
    }
  }
}
