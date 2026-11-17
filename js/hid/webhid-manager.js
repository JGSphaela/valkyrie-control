/**
 * Valkyrie WebHID Connection & Collection Manager
 *
 * Enforces `DriverComm::EnumerateDevice` interface rules:
 * - Accepts ONLY `(usagePage === 0xFF01 && usage === 0x0010)` or
 *   `(usagePage === 0x0001 && usage === 0x0000)` with 32-byte reports (`reportId = 0x00`).
 * - Strictly excludes and NEVER opens/writes the 64-byte
 *   `(usagePage === 0xFFEF && usage === 0x0000)` DFU/OTA collection.
 */

import {
  VALKYRIE_VIDS,
  buildWebHidFilters,
  getDeviceByPid,
} from '../devices.js';
import {
  ValkyrieM220Device,
  createProtocolError,
} from '../protocol/m220-device.js';
import {
  DEFAULT_HELPER_BASE_URL,
  LocalBridgeHidDevice,
  fetchHelperDevices,
  selectPreferredHelperDevice,
} from './local-bridge-device.js';

function getReportByteLength(reports, targetReportId = 0x00) {
  if (!Array.isArray(reports) || reports.length === 0) return null;
  const matching = reports.find((r) => (r.reportId ?? 0) === targetReportId) || reports[0];
  if (!matching || !Array.isArray(matching.items) || matching.items.length === 0) {
    return null;
  }
  const bits = matching.items.reduce(
    (sum, item) => sum + ((item.reportSize || 0) * (item.reportCount || 0)),
    0
  );
  return bits > 0 ? Math.ceil(bits / 8) : null;
}

/**
 * Find the valid 32-byte command collection inside a `HIDDevice`, or `null` if invalid.
 * Strictly ignores `(0xFFEF, 0x0000)` OTA collections and any 64-byte collections.
 *
 * Preference order:
 * 1. `(0xFF01, 0x0010)` 32-byte vendor command collection
 * 2. `(0x0001, 0x0000)` 32-byte generic desktop command collection
 *
 * @param {HIDDevice} hidDevice
 * @returns {{ usagePage: number, usage: number, inputBytes: number|null, outputBytes: number|null }|null}
 */
export function selectCommandCollection(hidDevice) {
  if (!hidDevice || !Array.isArray(hidDevice.collections)) return null;

  const isValidReportLength = (col) => {
    const inLen = getReportByteLength(col.inputReports, 0x00);
    const outLen = getReportByteLength(col.outputReports, 0x00);
    // Reject explicit non-32-byte interfaces (e.g. 64-byte OTA or 8-byte boot mouse)
    if (outLen !== null && outLen !== 32) return false;
    if (inLen !== null && inLen !== 32) return false;
    return true;
  };

  for (const [page, usage] of [
    [0xFF01, 0x0010],
    [0x0001, 0x0000],
  ]) {
    const match = hidDevice.collections.find(
      (col) => col.usagePage === page && col.usage === usage && isValidReportLength(col)
    );
    if (match) {
      return {
        usagePage: match.usagePage,
        usage: match.usage,
        inputBytes: getReportByteLength(match.inputReports, 0x00) ?? 32,
        outputBytes: getReportByteLength(match.outputReports, 0x00) ?? 32,
      };
    }
  }

  return null;
}

/**
 * Determine whether a `HIDDevice` is exclusively an excluded OTA `(0xFFEF, 0x0000)` node.
 * @param {HIDDevice} hidDevice
 * @returns {boolean}
 */
export function isOtaOnlyDevice(hidDevice) {
  if (!hidDevice || !Array.isArray(hidDevice.collections) || hidDevice.collections.length === 0) {
    return false;
  }
  const hasOta = hidDevice.collections.some(
    (col) => col.usagePage === 0xFFEF && col.usage === 0x0000
  );
  return hasOta && !selectCommandCollection(hidDevice);
}

/**
 * Manages WebHID connection lifecycle, interface filtering, and device ownership.
 */
export class WebHidManager {
  /**
   * @param {{
   *   logger?: (dir: string, cmd: number, bytes: Uint8Array, extra?: object) => void,
   *   onStatusChange?: (status: string, data?: object) => void,
   *   onDeviceDisconnect?: () => void,
   *   onStateChange?: (state: object) => void,
   *   onNotification?: (evt: object) => void,
   *   writeSettleMs?: number,
   *   hidApi?: object,
   *   fetchImpl?: typeof fetch,
   *   helperBaseUrl?: string,
   * }} [options]
   */
  constructor(options = {}) {
    this.logger = typeof options.logger === 'function' ? options.logger : null;
    this.onStatusChange = typeof options.onStatusChange === 'function' ? options.onStatusChange : null;
    this.onDeviceDisconnect = typeof options.onDeviceDisconnect === 'function' ? options.onDeviceDisconnect : null;
    this.onStateChange = typeof options.onStateChange === 'function' ? options.onStateChange : null;
    this.onNotification = typeof options.onNotification === 'function' ? options.onNotification : null;
    this.writeSettleMs = options.writeSettleMs;
    this.#hidApi = options.hidApi || null;
    this.#fetchImpl = typeof options.fetchImpl === 'function' ? options.fetchImpl : null;
    this.helperBaseUrl = options.helperBaseUrl || DEFAULT_HELPER_BASE_URL;

    this.hidDevice = null;
    this.device = null;
    this.deviceDescriptor = null;
    this.activeCollection = null;
    this.transportType = null;
    this.#onDisconnectBound = (ev) => {
      if (this.hidDevice && ev?.device === this.hidDevice) {
        this.disconnect(true);
      }
    };
  }

  #hidApi;
  #fetchImpl;
  #onDisconnectBound;

  #getHid() {
    if (this.#hidApi) return this.#hidApi;
    return typeof navigator !== 'undefined' ? navigator.hid : null;
  }

  isSupported() {
    const hid = this.#getHid();
    return Boolean(hid && typeof hid.requestDevice === 'function');
  }

  setLogger(fn) {
    this.logger = typeof fn === 'function' ? fn : null;
    if (this.device) {
      this.device.setLogger(this.logger);
    }
  }

  /**
   * Search a list of `HIDDevice` objects for a permitted 32-byte command interface.
   * Never returns an OTA `(0xFFEF, 0x0000)` device.
   *
   * @param {Array<HIDDevice>} devices
   * @returns {HIDDevice|null}
   */
  findCommandDevice(devices) {
    const candidates = [];
    for (const d of devices || []) {
      if (!d || !VALKYRIE_VIDS.includes(d.vendorId)) continue;
      if (isOtaOnlyDevice(d)) continue;
      const col = selectCommandCollection(d);
      if (!col) continue;
      const priority = col.usagePage === 0xFF01 ? 0 : 1;
      candidates.push({ d, priority });
    }
    candidates.sort((a, b) => a.priority - b.priority);
    return candidates[0]?.d || null;
  }

  /**
   * Prompt user via Chrome WebHID chooser, then connect ONLY to the valid 32-byte
   * command interface (never opening `0xFFEF`).
   * @returns {Promise<{ device: ValkyrieM220Device, state: object, descriptor: object, collection: object }|null>}
   */
  async requestAndConnect() {
    const hid = this.#getHid();
    if (!hid) {
      throw createProtocolError('WEBHID_UNSUPPORTED', 'WebHID is not supported in this browser');
    }

    const picked = await hid.requestDevice({ filters: buildWebHidFilters() });
    if (!picked || picked.length === 0) {
      return null;
    }

    let target = this.findCommandDevice(picked);

    if (!target) {
      const existing = typeof hid.getDevices === 'function' ? await hid.getDevices() : [];
      target = this.findCommandDevice(existing);
    }

    if (!target) {
      const otaPicked = picked.some((d) => isOtaOnlyDevice(d));
      if (otaPicked) {
        throw createProtocolError(
          'OTA_COLLECTION_BLOCKED',
          'Blocked 64-byte (0xFFEF, 0x0000) OTA collection; please select the 32-byte command interface'
        );
      }
      throw createProtocolError(
        'NO_COMMAND_INTERFACE',
        'No 32-byte Valkyrie WebHID command interface (0xFF01/0x0010 or 0x0001/0x0000) found'
      );
    }

    return this.connectDevice(target);
  }

  /**
   * Attempt silent auto-reconnection to previously authorized command interface.
   */
  async autoConnectExisting() {
    const hid = this.#getHid();
    if (!hid || typeof hid.getDevices !== 'function') return null;

    const devices = await hid.getDevices();
    const target = this.findCommandDevice(devices);
    if (!target) return null;

    return this.connectDevice(target);
  }

  /**
   * Connect via the localhost-only Companion Helper (`127.0.0.1:19480`) when
   * Windows Chrome/Edge hides the `MI_02` HID interface. Must only be triggered
   * explicitly by user action (never called automatically on page load).
   *
   * @param {{ baseUrl?: string, fetchImpl?: typeof fetch, deviceId?: string }} [options]
   * @returns {Promise<{ device: ValkyrieM220Device, state: object, descriptor: object, collection: object, transportType: 'local-helper', helperBaseUrl: string }>}
   */
  async connectViaLocalHelper({ baseUrl, fetchImpl, deviceId } = {}) {
    const resolvedBaseUrl = baseUrl || this.helperBaseUrl || DEFAULT_HELPER_BASE_URL;
    const resolvedFetch = typeof fetchImpl === 'function' ? fetchImpl : this.#fetchImpl;
    const devices = await fetchHelperDevices({
      baseUrl: resolvedBaseUrl,
      fetchImpl: resolvedFetch,
    });

    const targetInfo = (deviceId
      ? devices.find((d) => d.id === deviceId)
      : null) || selectPreferredHelperDevice(devices);

    if (!targetInfo) {
      throw createProtocolError(
        'LOCAL_HELPER_NO_DEVICE',
        'No supported 32-byte Valkyrie MI_02 interface found via Local Helper'
      );
    }

    const helperDevice = new LocalBridgeHidDevice(targetInfo, {
      baseUrl: resolvedBaseUrl,
      fetchImpl: resolvedFetch,
      onDisconnect: () => {
        if (this.hidDevice === helperDevice) {
          this.disconnect(true).catch(() => {});
        }
      },
    });

    return this.connectDevice(helperDevice);
  }

  /**
   * Open and sync a validated command `HIDDevice` (WebHID or `LocalBridgeHidDevice`).
   * Refuses `0xFFEF` OTA devices before calling `.open()`.
   *
   * @param {HIDDevice|LocalBridgeHidDevice} hidDevice
   * @returns {Promise<{ device: ValkyrieM220Device, state: object, descriptor: object, collection: object, transportType: 'webhid'|'local-helper', helperBaseUrl: string|null }>}
   */
  async connectDevice(hidDevice) {
    if (isOtaOnlyDevice(hidDevice)) {
      throw createProtocolError(
        'OTA_COLLECTION_BLOCKED',
        'Blocked attempt to open 64-byte (0xFFEF, 0x0000) OTA/DFU HID interface'
      );
    }

    const collection = selectCommandCollection(hidDevice);
    if (!collection) {
      throw createProtocolError(
        'NO_COMMAND_INTERFACE',
        'Selected HID interface does not match 32-byte (0xFF01/0x0010 or 0x0001/0x0000)'
      );
    }

    await this.disconnect(false);

    const isLocalHelper = hidDevice?.transport === 'local-helper' || hidDevice instanceof LocalBridgeHidDevice;
    const transportType = isLocalHelper ? 'local-helper' : 'webhid';
    const helperBaseUrl = isLocalHelper ? (hidDevice.helperBaseUrl || this.helperBaseUrl) : null;

    if (!hidDevice.opened) {
      await hidDevice.open();
    }

    const descriptor = getDeviceByPid(hidDevice.productId);
    const isWireless = Boolean(descriptor.isWireless || (isLocalHelper && hidDevice.isWireless));
    const device = new ValkyrieM220Device(hidDevice, {
      isWireless,
      logger: this.logger,
      onStateChange: this.onStateChange,
      onNotification: this.onNotification,
      writeSettleMs: this.writeSettleMs,
      modelKey: descriptor.modelId,
    });

    this.hidDevice = hidDevice;
    this.device = device;
    this.deviceDescriptor = descriptor;
    this.activeCollection = collection;
    this.transportType = transportType;

    if (!isLocalHelper) {
      const hid = this.#getHid();
      if (hid && typeof hid.addEventListener === 'function') {
        hid.addEventListener('disconnect', this.#onDisconnectBound);
      }
    }

    try {
      const state = await device.syncAll({ includeDongle: isWireless });
      const statusData = {
        state,
        descriptor,
        collection,
        transportType,
        helperBaseUrl,
      };
      if (this.onStatusChange) {
        this.onStatusChange('connected', statusData);
      }
      return { device, state, descriptor, collection, transportType, helperBaseUrl };
    } catch (err) {
      await this.disconnect(false);
      throw err;
    }
  }

  async disconnect(notify = true) {
    const hid = this.#getHid();
    if (hid && typeof hid.removeEventListener === 'function') {
      hid.removeEventListener('disconnect', this.#onDisconnectBound);
    }

    if (this.device) {
      this.device.dispose();
      this.device = null;
    }

    const currentHidDevice = this.hidDevice;
    this.hidDevice = null;
    this.deviceDescriptor = null;
    this.activeCollection = null;
    this.transportType = null;

    if (currentHidDevice) {
      try {
        if (currentHidDevice.opened && typeof currentHidDevice.close === 'function') {
          await currentHidDevice.close();
        }
      } catch {
        // Ignore close error if device already unplugged
      }
    }

    if (notify) {
      if (this.onStatusChange) this.onStatusChange('disconnected');
      if (this.onDeviceDisconnect) this.onDeviceDisconnect();
    }
  }
}
