/**
 * Valkyrie Hardware Registry
 *
 * Official USB and 2.4 GHz dongle hardware identifiers and factory defaults
 * derived from `config.xml` and `device/mouse_vk m3*.xml`.
 *
 * Note: The 64-byte DFU/OTA HID collection `(usagePage: 0xFFEF, usage: 0x0000)`
 * must never be opened or written by WebHID transport.
 */

export const USB_VID = 0x248A;
export const DONGLE_ALT_VID = 0x249A;
export const VALKYRIE_VIDS = [USB_VID, DONGLE_ALT_VID];

export const PID_M3_WIRED_1 = 0x5C2E;
export const PID_M3_WIRED_2 = 0x5D2E;
export const PID_M3_WIRED_3 = 0x5E2E;
export const PID_M3_DONGLE = 0x5C2F;

export const ALLOWED_COMMAND_INTERFACES = [
  { usagePage: 0xFF01, usage: 0x0010, reportByteLength: 32 },
  { usagePage: 0x0001, usage: 0x0000, reportByteLength: 32 },
];

export const FORBIDDEN_OTA_INTERFACE = {
  usagePage: 0xFFEF,
  usage: 0x0000,
  reportByteLength: 64,
};

/**
 * Hardware specifications keyed by firmware ASCII `devId` (`M220`, `E023`).
 * Both devices share several USB/2.4G PIDs, so runtime `0x10` handshake `devId`
 * is authoritative once connected.
 */
export const DEVICE_BY_DEVID = {
  M220: {
    devId: 'M220',
    deviceType: 101,
    modelKey: 'VK_M3_LITE',
    name: 'VK M3 Lite',
    subtitle: 'Ultra-lightweight wireless gaming mouse',
    usbVids: [USB_VID],
    usbPids: [PID_M3_WIRED_1, PID_M3_WIRED_2],
    dongleVids: [DONGLE_ALT_VID, USB_VID],
    donglePids: [PID_M3_DONGLE],
    buttonCount: 6,
    factoryDpis: [800, 1200, 2000, 5000, 8000, 12000],
    factoryColors: ['#FFFF00', '#00FFFF', '#00FF00', '#800080', '#0000FF', '#FF0000'],
    defaultDpiIndex: 0,
    defaultPollingHz: 1000,
    maxOfficialPollingHz: 1000,
    defaultSleepSec: 60,
    defaultLod: 1,
    defaultDebounceMs: 8,
    lightEnabledInXml: false,
    defaultLightMode: 2,
  },
  E023: {
    devId: 'E023',
    deviceType: 102,
    modelKey: 'VK_M3',
    name: 'VK M3',
    subtitle: 'Wireless gaming mouse',
    usbVids: [USB_VID],
    usbPids: [PID_M3_WIRED_1, PID_M3_WIRED_2, PID_M3_WIRED_3],
    dongleVids: [DONGLE_ALT_VID, USB_VID],
    donglePids: [PID_M3_DONGLE],
    buttonCount: 6,
    factoryDpis: [400, 800, 1200, 1600, 3200, 5200],
    factoryColors: ['#FF0000', '#00FF00', '#0000FF', '#00FFFF', '#FFFF00', '#800080'],
    defaultDpiIndex: 0,
    defaultPollingHz: 1000,
    maxOfficialPollingHz: 1000,
    defaultSleepSec: 60,
    defaultLod: 1,
    defaultDebounceMs: 8,
    lightEnabledInXml: false,
    defaultLightMode: 2,
  },
};

/**
 * PID-indexed descriptor registry used during WebHID enumeration before `0x10`
 * handshake identifies whether the MCU is `M220` or `E023`.
 */
export const SUPPORTED_DEVICES = {
  [PID_M3_WIRED_1]: {
    vid: USB_VID,
    vids: [USB_VID],
    pid: PID_M3_WIRED_1,
    name: 'Valkyrie VK M3 / M3 Lite (USB)',
    modelId: 'VK_M3_LITE',
    devIds: ['M220', 'E023'],
    isWireless: false,
    buttonCount: 6,
    maxPollingHz: 8000,
  },
  [PID_M3_WIRED_2]: {
    vid: USB_VID,
    vids: [USB_VID],
    pid: PID_M3_WIRED_2,
    name: 'Valkyrie VK M3 / M3 Lite (USB)',
    modelId: 'VK_M3_LITE',
    devIds: ['M220', 'E023'],
    isWireless: false,
    buttonCount: 6,
    maxPollingHz: 8000,
  },
  [PID_M3_WIRED_3]: {
    vid: USB_VID,
    vids: [USB_VID],
    pid: PID_M3_WIRED_3,
    name: 'Valkyrie VK M3 (USB)',
    modelId: 'VK_M3',
    devIds: ['E023'],
    isWireless: false,
    buttonCount: 6,
    maxPollingHz: 8000,
  },
  [PID_M3_DONGLE]: {
    vid: DONGLE_ALT_VID,
    vids: [DONGLE_ALT_VID, USB_VID],
    pid: PID_M3_DONGLE,
    name: 'Valkyrie VK M3 Series (2.4 GHz)',
    modelId: 'VK_M3_LITE',
    devIds: ['M220', 'E023'],
    isWireless: true,
    buttonCount: 6,
    maxPollingHz: 8000,
  },
};

export const DEFAULT_DEVICE_FALLBACK = {
  vid: USB_VID,
  vids: VALKYRIE_VIDS,
  pid: PID_M3_WIRED_2,
  name: 'Valkyrie VK M3 Lite (Demo)',
  modelId: 'VK_M3_LITE',
  devIds: ['M220', 'E023'],
  isWireless: false,
  buttonCount: 6,
  maxPollingHz: 8000,
};

/**
 * Look up a device descriptor by USB/dongle Product ID.
 * @param {number} pid
 * @returns {object}
 */
export function getDeviceByPid(pid) {
  return SUPPORTED_DEVICES[pid] || DEFAULT_DEVICE_FALLBACK;
}

/**
 * Look up hardware specifications by handshake ASCII `devId` (`'M220'` or `'E023'`).
 * @param {string} devId
 * @returns {object|null}
 */
export function getDeviceByDevId(devId) {
  if (!devId) return null;
  const normalized = String(devId).trim().toUpperCase();
  return DEVICE_BY_DEVID[normalized] || null;
}

/**
 * Build WebHID `navigator.hid.requestDevice` filter list covering both
 * wired (`0x248A`) and 2.4 GHz dongle (`0x248A` / `0x249A`) pairs.
 * Note: collection filtering happens after selection in `WebHidManager`
 * so `findCommandDevice()` selects `0xFF01/0x0010` or `0x0001/0x0000` and
 * never opens the forbidden `0xFFEF` OTA collection, while still detecting
 * if Windows browsers stripped `MI_02`.
 * @returns {Array<{vendorId: number, productId: number}>}
 */
export function buildWebHidFilters() {
  return [
    { vendorId: USB_VID, productId: PID_M3_WIRED_1 },
    { vendorId: USB_VID, productId: PID_M3_WIRED_2 },
    { vendorId: USB_VID, productId: PID_M3_WIRED_3 },
    { vendorId: USB_VID, productId: PID_M3_DONGLE },
    { vendorId: DONGLE_ALT_VID, productId: PID_M3_DONGLE },
  ];
}
