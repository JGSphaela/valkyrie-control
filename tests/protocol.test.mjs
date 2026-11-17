import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ALLOWED_COMMAND_INTERFACES,
  DEVICE_BY_DEVID,
  FORBIDDEN_OTA_INTERFACE,
  SUPPORTED_DEVICES,
  buildWebHidFilters,
  getDeviceByDevId,
  getDeviceByPid,
} from '../js/devices.js';
import {
  MODEL_PROFILES,
  getModelByKey,
  getModelByPid,
  getModelList,
} from '../js/models.js';
import {
  HID_TO_CODE,
  MACRO_OPS,
  MEDIA_KEYS,
  compileMacroPackets,
  compileMacroStream,
  decodeButtonDescriptor,
  decompileMacroPackets,
  decompileMacroStream,
  encodeButtonDescriptor,
  frameMacroChunks,
  getFlashKeyCode,
  getSysKeyCode,
} from '../js/protocol/macro-compiler.js';
import {
  ALLOWED_OUTBOUND_OPCODES,
  SAFE_ROLLBACK_WRITE_PAIRS,
  SENSOR_PROFILES,
  ValkyrieM220Device,
  buildCommandPacket,
  computeChecksum,
  computeSnapshotDiff,
  decodeButtonsPacket,
  decodeDpiColorsPacket,
  decodeDpiCode,
  decodeDpiPacket,
  decodeHandshakePacket,
  decodeLightingPacket,
  decodeNotificationPacket,
  decodePollingPacket,
  decodeSensorPacket,
  decodeSleepPacket,
  encodeDpiCode,
  formatHex,
  isAllowedOpcode,
  parseHex,
  verifyPacketChecksum,
} from '../js/protocol/m220-device.js';
import {
  WebHidManager,
  isOtaOnlyDevice,
  selectCommandCollection,
} from '../js/hid/webhid-manager.js';
import {
  DEFAULT_HELPER_BASE_URL,
  LocalBridgeHidDevice,
  fetchHelperDevices,
} from '../js/hid/local-bridge-device.js';

// Verbatim live hardware capture from M220 (VK M3 Lite, fw v3.17, PAW3395)
const VIRGIN_BACKUP_FIXTURE = {
  device: {
    vid: 9354,
    pid: 23854,
    ver: 791,
    usage_page: 1,
    usage: 0,
    in_len: 33,
    out_len: 33,
  },
  regs: {
    '0x10': '10 00 01 0b 4d 32 32 30 17 03 11 01 02 64 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 74',
    '0x11': '11 00 01 12 10 01 00 10 02 00 10 04 00 10 08 00 10 10 00 40 01 00 00 00 00 00 00 00 00 00 00 b0',
    '0x12': '12 00 01 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01',
    '0x13': '13 00 01 19 06 10 00 10 00 18 00 18 00 28 00 28 00 64 00 64 00 a0 00 a0 00 dc 00 dc 00 00 00 66',
    '0x14': '14 00 01 12 ff ff 00 00 ff ff 00 ff 00 ff 00 ff 00 00 ff ff 00 00 00 00 00 00 00 00 00 00 00 f7',
    '0x15': '15 00 01 03 01 42 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 44',
    '0x16': '16 00 01 05 02 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03',
    '0x17': '17 00 01 05 1e 01 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28',
    '0x20': '20 00 01 02 17 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1a',
  },
};

function makeCollection(usagePage, usage, reportBytes = 32) {
  return {
    usagePage,
    usage,
    inputReports: [{ reportId: 0x00, items: [{ reportSize: 8, reportCount: reportBytes }] }],
    outputReports: [{ reportId: 0x00, items: [{ reportSize: 8, reportCount: reportBytes }] }],
  };
}

class MockHidDevice {
  constructor(initialRegs = VIRGIN_BACKUP_FIXTURE.regs, opts = {}) {
    this.vendorId = opts.vendorId ?? 0x248A;
    this.productId = opts.productId ?? 0x5D2E;
    this.productName = opts.productName ?? 'Valkyrie VK M3 Series';
    this.collections = opts.collections ?? [makeCollection(0x0001, 0x0000, 32)];
    this.opened = opts.opened ?? false;
    this.openCalls = 0;
    this.closeCalls = 0;
    this.sentReports = [];
    this.txTimestamps = [];
    this.listeners = new Map();
    this.regs = new Map();
    this.rejectCommands = new Set(opts.rejectCommands || []);
    this.lockMotionSync = Boolean(opts.lockMotionSync);

    for (const [k, hx] of Object.entries(initialRegs)) {
      this.regs.set(parseInt(k, 16), parseHex(hx));
    }
  }

  async open() {
    this.openCalls += 1;
    this.opened = true;
  }

  async close() {
    this.closeCalls += 1;
    this.opened = false;
  }

  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(fn);
  }

  removeEventListener(type, fn) {
    this.listeners.get(type)?.delete(fn);
  }

  emitInputReport(data32) {
    const view = new DataView(data32.buffer, data32.byteOffset, data32.byteLength);
    for (const fn of this.listeners.get('inputreport') || []) {
      fn({ device: this, reportId: 0, data: view });
    }
  }

  async sendReport(reportId, data) {
    assert.equal(reportId, 0x00);
    const tx = data instanceof Uint8Array ? new Uint8Array(data) : Uint8Array.from(data);
    this.sentReports.push(tx);
    this.txTimestamps.push(performance.now());

    const cmd = tx[0];
    const rx = new Uint8Array(32);

    if (this.rejectCommands.has(cmd)) {
      rx[0] = cmd;
      rx[1] = 0x03; // status rejected
      rx[2] = 0x01;
      rx[31] = computeChecksum(rx);
      queueMicrotask(() => this.emitInputReport(rx));
      return;
    }

    if (this.regs.has(cmd) && (cmd >= 0x10 && cmd <= 0x17 || cmd === 0x20)) {
      const stored = this.regs.get(cmd);
      queueMicrotask(() => this.emitInputReport(new Uint8Array(stored)));
      return;
    }

    // Mutate state on write opcodes
    if (cmd >= 0x02 && cmd <= 0x07 || cmd === 0x09) {
      const readCmd = cmd === 0x09 ? 0x11 : cmd + 0x10;
      const cur = new Uint8Array(this.regs.get(readCmd) || new Uint8Array(32));
      cur[0] = readCmd;
      cur[1] = 0x00;
      cur[2] = 0x01;
      // Live M220 firmware uses fixed readback lengths for 0x11 (0x12), 0x13 (0x19), 0x16 (0x05), 0x17 (0x05)
      if (cmd === 0x09) cur[3] = 0x12;
      else if (cmd === 0x07) cur[3] = 0x05;
      else cur[3] = tx[3];
      for (let i = 4; i <= 30; i += 1) {
        if (cmd === 0x06 && i === 7 && this.lockMotionSync) {
          cur[7] = 0x01; // M220 v3.17 keeps MotionSync locked on
        } else {
          cur[i] = tx[i];
        }
      }
      cur[31] = computeChecksum(cur);
      this.regs.set(readCmd, cur);
    }

    if (cmd === 0x0F && tx[4] === 0xFF) {
      // Simulate reset of 0x12..0x17 back to virgin fixture
      for (const [k, hx] of Object.entries(VIRGIN_BACKUP_FIXTURE.regs)) {
        this.regs.set(parseInt(k, 16), parseHex(hx));
      }
    }

    rx[0] = cmd;
    rx[1] = 0x00;
    rx[2] = tx[2];
    rx[3] = tx[3];
    rx[31] = computeChecksum(rx);
    queueMicrotask(() => this.emitInputReport(rx));
  }
}

test('1. Device & model registries match config.xml and device XMLs', () => {
  assert.equal(DEVICE_BY_DEVID.M220.deviceType, 101);
  assert.equal(DEVICE_BY_DEVID.E023.deviceType, 102);
  assert.deepEqual(DEVICE_BY_DEVID.M220.factoryDpis, [800, 1200, 2000, 5000, 8000, 12000]);
  assert.deepEqual(DEVICE_BY_DEVID.M220.factoryColors, ['#FFFF00', '#00FFFF', '#00FF00', '#800080', '#0000FF', '#FF0000']);
  assert.deepEqual(DEVICE_BY_DEVID.E023.factoryDpis, [400, 800, 1200, 1600, 3200, 5200]);
  assert.deepEqual(DEVICE_BY_DEVID.E023.factoryColors, ['#FF0000', '#00FF00', '#0000FF', '#00FFFF', '#FFFF00', '#800080']);

  assert.equal(getDeviceByDevId('m220').name, 'VK M3 Lite');
  assert.equal(getDeviceByDevId('E023').name, 'VK M3');
  assert.equal(getDeviceByPid(0x5E2E).modelId, 'VK_M3');
  assert.equal(getDeviceByPid(0x5C2F).isWireless, true);
  assert.equal(FORBIDDEN_OTA_INTERFACE.usagePage, 0xFFEF);
  assert.equal(FORBIDDEN_OTA_INTERFACE.reportByteLength, 64);
  assert.equal(ALLOWED_COMMAND_INTERFACES.length, 2);

  const filters = buildWebHidFilters();
  assert.ok(filters.some((f) => f.vendorId === 0x248A && f.productId === 0x5C2F));
  assert.ok(filters.some((f) => f.vendorId === 0x249A && f.productId === 0x5C2F));
  assert.ok(filters.some((f) => f.vendorId === 0x248A && f.productId === 0x5E2E));

  assert.equal(getModelList().length, 2);
  assert.equal(getModelByPid(0x5D2E, 'E023').id, 'VK_M3');
  assert.equal(getModelByKey('M220').id, 'VK_M3_LITE');
  assert.equal(MODEL_PROFILES.VK_M3_LITE.buttons.length, 6);
  assert.equal(MODEL_PROFILES.VK_M3_LITE.buttons[3].pinX, 4);
  assert.equal(MODEL_PROFILES.VK_M3_LITE.buttons[4].pinX, 4);
  assert.equal(MODEL_PROFILES.VK_M3_LITE.buttons[5].dashed, true);
  assert.deepEqual(MODEL_PROFILES.VK_M3_LITE.buttons[0].xmlLocation, [100, 180, 50]);
});

test('2. 32-byte packet checksum matches every virgin_backup.json register capture', () => {
  for (const [opcode, hex] of Object.entries(VIRGIN_BACKUP_FIXTURE.regs)) {
    const bytes = parseHex(hex);
    assert.equal(bytes.length, 32, `${opcode} length`);
    assert.equal(verifyPacketChecksum(bytes), true, `${opcode} checksum failed`);
  }

  const pkt = buildCommandPacket(0x07, [0x1E, 0x01, 0x01, 0x08], { length: 0x04 });
  assert.equal(pkt.length, 32);
  assert.equal(pkt[0], 0x07);
  assert.equal(pkt[2], 0x01);
  assert.equal(pkt[3], 0x04);
  assert.equal(pkt[31], (0x1E + 1 + 1 + 8) & 0xFF);
});

test('3. Stall Guard strictly blocks 0x18..0x2A (except 0x20) and unlisted opcodes before sendReport', async () => {
  const blocked = [];
  for (let op = 0x18; op <= 0x2A; op += 1) {
    if (op !== 0x20) blocked.push(op);
  }
  blocked.push(0x00, 0x01, 0x2B, 0x52, 0x7F, 0xFF);

  for (const op of blocked) {
    assert.equal(isAllowedOpcode(op), false);
    assert.throws(
      () => buildCommandPacket(op),
      (err) => err.code === 'STALL_GUARD_BLOCKED'
    );
  }

  for (const op of ALLOWED_OUTBOUND_OPCODES) {
    assert.equal(isAllowedOpcode(op), true);
  }

  const mockHid = new MockHidDevice();
  mockHid.opened = true;
  const dev = new ValkyrieM220Device(mockHid, { writeSettleMs: 50 });
  for (const stallCmd of [0x18, 0x19, 0x1A, 0x21, 0x2A, 0x52]) {
    await assert.rejects(
      () => dev.sendAllowlistedRaw(stallCmd, [0x00]),
      (err) => err.code === 'STALL_GUARD_BLOCKED'
    );
  }
  assert.equal(mockHid.sentReports.length, 0, 'No sendReport call may ever fire for blocked opcodes');
  dev.dispose();
});

test('4. WebHidManager accepts (0x0001/0x0000) & (0xFF01/0x0010) 32B and strictly excludes 64B (0xFFEF/0x0000)', async () => {
  const otaDevice = new MockHidDevice(VIRGIN_BACKUP_FIXTURE.regs, {
    collections: [makeCollection(0xFFEF, 0x0000, 64)],
  });
  const bootMouse = new MockHidDevice(VIRGIN_BACKUP_FIXTURE.regs, {
    collections: [makeCollection(0x0001, 0x0002, 8)],
  });
  const wrongSizeVendor = new MockHidDevice(VIRGIN_BACKUP_FIXTURE.regs, {
    collections: [makeCollection(0xFF01, 0x0010, 64)],
  });
  const desktopCmd = new MockHidDevice(VIRGIN_BACKUP_FIXTURE.regs, {
    collections: [makeCollection(0x0001, 0x0000, 32)],
  });
  const vendorCmd = new MockHidDevice(VIRGIN_BACKUP_FIXTURE.regs, {
    collections: [makeCollection(0xFF01, 0x0010, 32)],
  });

  assert.equal(isOtaOnlyDevice(otaDevice), true);
  assert.equal(selectCommandCollection(otaDevice), null);
  assert.equal(selectCommandCollection(bootMouse), null);
  assert.equal(selectCommandCollection(wrongSizeVendor), null);
  assert.equal(selectCommandCollection(desktopCmd).usagePage, 0x0001);
  assert.equal(selectCommandCollection(vendorCmd).usagePage, 0xFF01);

  const mgr = new WebHidManager({
    writeSettleMs: 50,
    hidApi: {
      requestDevice: async () => [otaDevice],
      getDevices: async () => [otaDevice, desktopCmd, vendorCmd],
    },
  });

  // Even when otaDevice appears first, findCommandDevice skips it and picks vendor/desktop command collection
  assert.equal(mgr.findCommandDevice([otaDevice, bootMouse]), null);
  assert.equal(mgr.findCommandDevice([otaDevice, desktopCmd, vendorCmd]), vendorCmd);

  // Direct attempt to connect OTA device throws BEFORE calling open()
  await assert.rejects(
    () => mgr.connectDevice(otaDevice),
    (err) => err.code === 'OTA_COLLECTION_BLOCKED'
  );
  assert.equal(otaDevice.openCalls, 0);
  assert.equal(otaDevice.sentReports.length, 0);

  // If requestDevice picked OTA sibling, manager falls back to permitted non-OTA sibling from getDevices()
  const session = await mgr.requestAndConnect();
  assert.equal(otaDevice.openCalls, 0);
  assert.equal(session.collection.usagePage, 0xFF01);
  assert.equal(session.collection.outputBytes, 32);
  await mgr.disconnect();
});

test('5. All 11 sensor DPI curves + fallback + unlockMax (26,000) + asymmetric X/Y', async () => {
  // 0x11 PAW3395: official cap 24000 (0xE8), unlocked 26000 (0xEA), <=10000 uses dpi/50 & code*50
  assert.equal(encodeDpiCode(0x11, 50), 1);
  assert.equal(decodeDpiCode(0x11, 1), 50);
  assert.equal(encodeDpiCode(0x11, 800), 0x10);
  assert.equal(decodeDpiCode(0x11, 0x10), 800);
  assert.equal(encodeDpiCode(0x11, 10000), 0xC8);
  assert.equal(decodeDpiCode(0x11, 0xC8), 10000);
  assert.equal(encodeDpiCode(0x11, 12000), 0xDC);
  assert.equal(decodeDpiCode(0x11, 0xDC), 12000);
  assert.equal(encodeDpiCode(0x11, 13000), 0xDD);
  assert.equal(decodeDpiCode(0x11, 0xDD), 13000);
  assert.equal(encodeDpiCode(0x11, 24000), 0xE8);
  assert.equal(encodeDpiCode(0x11, 26000, { unlockMax: false }), 0xE8);
  assert.equal(encodeDpiCode(0x11, 26000, { unlockMax: true }), 0xEA);
  assert.equal(decodeDpiCode(0x11, 0xEA), 26000);

  // 0x05
  assert.equal(encodeDpiCode(0x05, 800), 16);
  assert.equal(decodeDpiCode(0x05, 16), 800);
  assert.equal(encodeDpiCode(0x05, 6400), 0x80);
  assert.equal(decodeDpiCode(0x05, 0x80), 6400);
  assert.equal(encodeDpiCode(0x05, 6500), 0x81);
  assert.equal(decodeDpiCode(0x05, 0x81), 6500);
  assert.equal(encodeDpiCode(0x05, 12000), 0xB8);

  // 0x19
  assert.equal(encodeDpiCode(0x19, 1600), 16);
  assert.equal(decodeDpiCode(0x19, 16), 1600);
  assert.equal(encodeDpiCode(0x19, 16000), 0xA0);
  assert.equal(encodeDpiCode(0x19, 30000), 0xAE);
  assert.equal(decodeDpiCode(0x19, 0xAE), 30000);

  // 0x25
  assert.equal(encodeDpiCode(0x25, 1200), 12);
  assert.equal(decodeDpiCode(0x25, 12), 1200);
  assert.equal(encodeDpiCode(0x25, 10000), 0x3C);
  assert.equal(decodeDpiCode(0x25, 0x3C), 10000);

  // 0x26
  assert.equal(encodeDpiCode(0x26, 200), 1);
  assert.equal(decodeDpiCode(0x26, 2), 200);
  assert.equal(encodeDpiCode(0x26, 10000), 0x3C);
  assert.equal(decodeDpiCode(0x26, 0x3B), 10000);

  // 0x04
  assert.equal(encodeDpiCode(0x04, 1600), 16);
  assert.equal(decodeDpiCode(0x04, 16), 1600);
  assert.equal(encodeDpiCode(0x04, 8000), 0x2F);
  assert.equal(decodeDpiCode(0x04, 0x2F), 8000);

  // 0x95 & 0x96 (values > 255 require 16-bit LE; 0x95 decodes (code+1)*50, 0x96 decodes code*50 per disasm_macro_dpi)
  assert.equal(encodeDpiCode(0x95, 26000), 519);
  assert.equal(decodeDpiCode(0x95, 519), 26000);
  assert.equal(encodeDpiCode(0x96, 32000), 639);
  assert.equal(decodeDpiCode(0x96, 639), 31950);
  assert.equal(decodeDpiCode(0x96, 640), 32000);

  // 0x10, 0x12, 0x35
  for (const s of [0x10, 0x12, 0x35]) {
    assert.equal(encodeDpiCode(s, 3200), 32);
    assert.equal(decodeDpiCode(s, 32), 3200);
  }
  assert.equal(encodeDpiCode(0x10, 4800), 48);
  assert.equal(encodeDpiCode(0x35, 16000), 160);

  // Fallback curve
  assert.equal(encodeDpiCode(0x7E, 1000), 19);
  assert.equal(decodeDpiCode(0x7E, 19), 1000);

  assert.equal(Object.keys(SENSOR_PROFILES).length, 11);

  // Asymmetric X/Y write + readback on device
  const mockHid = new MockHidDevice();
  mockHid.opened = true;
  const dev = new ValkyrieM220Device(mockHid, { writeSettleMs: 50 });
  await dev.syncAll();

  const updated = await dev.setDpiConfig({
    activeIndex: 1,
    unlockMax: true,
    stages: [
      { x: 800, y: 1600, color: '#112233' },
      { x: 26000, y: 12000, color: '#445566' },
    ],
  });
  assert.equal(updated.activeDpiStage, 1);
  assert.equal(updated.stages.length, 2);
  assert.deepEqual(updated.stages[0], { x: 800, y: 1600, color: '#112233' });
  assert.deepEqual(updated.stages[1], { x: 26000, y: 12000, color: '#445566' });
  dev.dispose();
});

test('6. Live virgin_backup.json decoders and full syncAll state match factory hardware', async () => {
  const hs = decodeHandshakePacket(parseHex(VIRGIN_BACKUP_FIXTURE.regs['0x10']));
  assert.equal(hs.devId, 'M220');
  assert.equal(hs.fwVersion, 'v3.17');
  assert.equal(hs.sensorId, 0x11);
  assert.equal(hs.maxPollingHz, 1000);
  assert.equal(hs.batteryPct, 100);
  assert.equal(hs.charging, true);
  assert.equal(hs.online, true);

  const buttons = decodeButtonsPacket(parseHex(VIRGIN_BACKUP_FIXTURE.regs['0x11']));
  assert.equal(buttons.length, 6);
  assert.equal(buttons[0].type, 'mouse');
  assert.equal(buttons[0].button, 1);
  assert.equal(buttons[4].button, 5);
  assert.deepEqual(buttons[5], { slot: 5, type: 'dpi', mode: 'cycle', raw: [0x40, 0x01, 0x00] });

  assert.equal(decodePollingPacket(parseHex(VIRGIN_BACKUP_FIXTURE.regs['0x12'])).pollingHz, 1000);

  const dpi = decodeDpiPacket(parseHex(VIRGIN_BACKUP_FIXTURE.regs['0x13']), 0x11);
  assert.equal(dpi.stageCount, 6);
  assert.equal(dpi.activeStage, 0);
  assert.deepEqual(dpi.stages.map((s) => s.rawX), [0x10, 0x18, 0x28, 0x64, 0xA0, 0xDC]);
  assert.deepEqual(dpi.stages.map((s) => s.x), [800, 1200, 2000, 5000, 8000, 12000]);
  assert.deepEqual(dpi.stages.map((s) => s.y), [800, 1200, 2000, 5000, 8000, 12000]);

  const colors = decodeDpiColorsPacket(parseHex(VIRGIN_BACKUP_FIXTURE.regs['0x14']));
  assert.deepEqual(colors, ['#FFFF00', '#00FFFF', '#00FF00', '#FF00FF', '#0000FF', '#FF0000']);

  const light = decodeLightingPacket(parseHex(VIRGIN_BACKUP_FIXTURE.regs['0x15']));
  assert.deepEqual({ mode: light.mode, brightness: light.brightness, speed: light.speed, direction: light.direction }, {
    mode: 1,
    brightness: 2,
    speed: 4,
    direction: 1,
  });

  const sensor = decodeSensorPacket(parseHex(VIRGIN_BACKUP_FIXTURE.regs['0x16']));
  assert.deepEqual(sensor, { lod: 2, angleSnap: false, ripple: false, motionSync: true });

  const sleep = decodeSleepPacket(parseHex(VIRGIN_BACKUP_FIXTURE.regs['0x17']));
  assert.deepEqual(sleep, { sleep10s: 30, sleepSec: 300, moveWake: true, moveCloseLight: true, debounceMs: 8 });

  const mockHid = new MockHidDevice(VIRGIN_BACKUP_FIXTURE.regs, { productId: 0x5C2F });
  mockHid.opened = true;
  const dev = new ValkyrieM220Device(mockHid, { isWireless: true, writeSettleMs: 50 });
  const state = await dev.syncAll();
  assert.equal(state.devId, 'M220');
  assert.equal(state.fwVersion, 'v3.17');
  assert.equal(state.rfFwVersion, 'v3.17');
  assert.equal(state.batteryPct, 100);
  dev.dispose();
});

test('7. Polling rate capability gating & status=0x03 rejection handling', async () => {
  const customRegs = { ...VIRGIN_BACKUP_FIXTURE.regs };
  const cap2k = parseHex(customRegs['0x10']);
  cap2k[11] = 0x10; // allows up to 2000Hz
  cap2k[31] = computeChecksum(cap2k);
  customRegs['0x10'] = formatHex(cap2k);

  const hid = new MockHidDevice(customRegs, { rejectCommands: [0x02] });
  hid.opened = true;
  const dev = new ValkyrieM220Device(hid, { writeSettleMs: 50 });
  await dev.syncAll();

  assert.deepEqual(dev.state.supportedPollingRates, [125, 250, 500, 1000, 2000]);

  await assert.rejects(
    () => dev.setPollingRate(8000),
    (err) => err.code === 'POLLING_UNSUPPORTED'
  );

  await assert.rejects(
    () => dev.setPollingRate(2000),
    (err) => err.code === 'HARDWARE_REJECTED' && err.status === 0x03 && err.cmd === 0x02
  );

  // Verify accepted write path works when rejection cleared
  hid.rejectCommands.delete(0x02);
  const hz = await dev.setPollingRate(2000);
  assert.equal(hz, 2000);
  dev.dispose();
});

test('8. Sensor MotionSync lock detection, 0..30ms debounce, and lighting modes 0..5', async () => {
  const hid = new MockHidDevice(VIRGIN_BACKUP_FIXTURE.regs, { lockMotionSync: true });
  hid.opened = true;
  const dev = new ValkyrieM220Device(hid, { writeSettleMs: 50 });
  await dev.syncAll();

  // Attempt disabling MotionSync when firmware forces 0x01
  const sensorRes = await dev.setSensorSettings({ lod: 3, angleSnap: true, ripple: true, motionSync: false });
  assert.equal(sensorRes.lod, 3);
  assert.equal(sensorRes.angleSnap, true);
  assert.equal(sensorRes.ripple, true);
  assert.equal(sensorRes.motionSync, true);
  assert.equal(sensorRes.motionSyncLocked, true);

  // Debounce 0..30ms
  const s0 = await dev.setSleepAndDebounce({ debounceMs: 0, sleepSec: 120, moveWake: false, moveCloseLight: false });
  assert.equal(s0.debounceMs, 0);
  assert.equal(s0.sleepSec, 120);
  const s30 = await dev.setSleepAndDebounce({ debounceMs: 30 });
  assert.equal(s30.debounceMs, 30);

  // Lighting modes 0, 2 (7-color breathing), 3 (constant), 4 (neon), 5 (waves)
  const m3 = await dev.setLighting({ mode: 3, brightness: 5, speed: 3, color: '#12ABEF' });
  assert.equal(m3.mode, 3);
  assert.equal(m3.brightness, 5);
  assert.equal(m3.color, '#12ABEF');

  const m2 = await dev.setLighting({
    mode: 2,
    brightness: 4,
    speed: 2,
    breathingColors: ['#110000', '#002200', '#000033', '#444400', '#550055', '#006666', '#777777'],
  });
  assert.equal(m2.mode, 2);
  assert.equal(m2.breathingColors[6], '#777777');

  const m0 = await dev.setLighting({ mode: 0, brightness: 1, speed: 1 });
  assert.equal(m0.mode, 0);
  dev.dispose();
});

test('9. Button codecs & keycode conversions (GetFlashKeyCode / GetSysKeyCode / 0x11 / 0x09)', () => {
  assert.equal(getFlashKeyCode(0x41), 0x04); // 'A'
  assert.equal(getFlashKeyCode('KeyC'), 0x06);
  assert.equal(getSysKeyCode(0xA2), 0x01); // LControl
  assert.equal(getSysKeyCode(0xA0), 0x02); // LShift
  assert.equal(getSysKeyCode(0xA4), 0x04); // LAlt
  assert.equal(getSysKeyCode(0x5B), 0x08); // LWin
  assert.equal(getSysKeyCode(0x5D), 0x80); // RWin
  assert.equal(HID_TO_CODE[0x2B], 'Tab');

  assert.deepEqual(encodeButtonDescriptor({ type: 'mouse', button: 4 }), [0x10, 0x08, 0x00]);
  assert.deepEqual(encodeButtonDescriptor({ type: 'keyboard', modifiers: 0x08, code: 'KeyD' }), [0x70, 0x08, 0x07]);
  assert.deepEqual(encodeButtonDescriptor({ type: 'keyboard', modifiers: 0, code: 'MetaLeft' }), [0x70, 0x08, 0x00]);
  assert.deepEqual(encodeButtonDescriptor({ type: 'media', keyName: 'vol_up' }), [0x80, 0xE9, 0x00]);
  assert.deepEqual(encodeButtonDescriptor({ type: 'media', usage: MEDIA_KEYS.calculator }), [0x80, 0x92, 0x01]);
  assert.deepEqual(encodeButtonDescriptor({ type: 'fire', repeatCount: 5, interval: 25 }), [0x30, 0x05, 0x19]);
  assert.deepEqual(encodeButtonDescriptor({ type: 'macro', slotIndex: 3, loopMode: 'hold' }), [0x90, 0x43, 0x00]);
  assert.deepEqual(encodeButtonDescriptor({ type: 'macro', slotIndex: 2, loopMode: 'count', loopCount: 4 }), [0x90, 0x22, 0x04]);
  assert.deepEqual(encodeButtonDescriptor({ type: 'dpi', mode: 'cycle' }), [0x40, 0x01, 0x00]);
  assert.deepEqual(encodeButtonDescriptor({ type: 'dpi', mode: 'up' }), [0x40, 0x02, 0x00]);
  assert.deepEqual(encodeButtonDescriptor({ type: 'dpi', mode: 'down' }), [0x40, 0x03, 0x00]);
  assert.deepEqual(encodeButtonDescriptor({ type: 'disabled' }), [0x60, 0x00, 0x00]);

  assert.equal(decodeButtonDescriptor(0x70, 0x01, 0x06).code, 'KeyC');
  assert.equal(decodeButtonDescriptor(0x80, 0xE9, 0x00).keyName, 'vol_up');
  assert.deepEqual(decodeButtonDescriptor(0x90, 0x43, 0x00), {
    type: 'macro',
    macroId: 3,
    slotIndex: 3,
    loopMode: 'hold',
    loopCount: 0,
    raw: [0x90, 0x43, 0x00],
  });
});

test('10. Macro compiler: LE prev-event delay, Win-key 0x5B/0x5D release fix (0xA0), multi-chunk 0x08 framing', () => {
  // Check Win-key press & release (0x5B LWin, 0x5D RWin)
  const winEvents = [
    { type: 'keyDown', vk: 0x5B },
    { type: 'delay', delayMs: 300 }, // 0x012C -> [0x2C, 0x01] attached to LWin down
    { type: 'keyDown', code: 'KeyR' },
    { type: 'delay', delayMs: 40 },
    { type: 'keyUp', code: 'KeyR' },
    { type: 'keyUp', vk: 0x5B }, // MUST emit 0xA0 (NOT 0x20!)
    { type: 'delay', delayMs: 120 }, // trailing delay on last event
    { type: 'keyDown', vk: 0x5D },
    { type: 'keyUp', vk: 0x5D },
  ];

  const stream = compileMacroStream(winEvents, 4);
  assert.equal(stream[0], 4, 'keyIdx byte 0');
  // Event 0: LWin down, delay 300ms (0x012C LE)
  assert.deepEqual(Array.from(stream.subarray(1, 5)), [MACRO_OPS.MOD_DOWN, 0x2C, 0x01, 0x08]);
  // Event 1: KeyR down, delay 40ms
  assert.deepEqual(Array.from(stream.subarray(5, 9)), [MACRO_OPS.KEY_DOWN, 40, 0x00, 0x15]);
  // Event 2: KeyR up, default delay 1ms
  assert.deepEqual(Array.from(stream.subarray(9, 13)), [MACRO_OPS.KEY_UP, 0x01, 0x00, 0x15]);
  // Event 3: LWin up MUST be 0xA0 with trailing 120ms delay
  assert.deepEqual(Array.from(stream.subarray(13, 17)), [MACRO_OPS.MOD_UP, 120, 0x00, 0x08]);
  // Event 4 & 5: RWin down 0x20 + RWin up 0xA0
  assert.equal(stream[17], MACRO_OPS.MOD_DOWN);
  assert.equal(stream[20], 0x80);
  assert.equal(stream[21], MACRO_OPS.MOD_UP);
  assert.equal(stream[24], 0x80);

  // Decompile stream round-trip
  const decompiled = decompileMacroStream(stream);
  assert.equal(decompiled.keyIdx, 4);
  assert.equal(decompiled.events[0].type, 'keyDown');
  assert.equal(decompiled.events[1].type, 'delay');
  assert.equal(decompiled.events[1].delayMs, 300);

  // Multi-chunk framing (> 6 events -> 16 events = 1 + 64 = 65 bytes = 3 chunks of 27/27/11)
  const longEvents = [];
  for (let i = 0; i < 8; i += 1) {
    longEvents.push({ type: 'keyDown', code: 'KeyA' });
    longEvents.push({ type: 'keyUp', code: 'KeyA' });
  }
  const chunks = compileMacroPackets(2, longEvents);
  assert.equal(chunks.length, 3);
  assert.equal(chunks[0][0], 0x08);
  assert.equal(chunks[0][2], (0 << 4) | 3);
  assert.equal(chunks[0][3], 27);
  assert.equal(chunks[1][2], (1 << 4) | 3);
  assert.equal(chunks[1][3], 27);
  assert.equal(chunks[2][2], (2 << 4) | 3);
  assert.equal(chunks[2][3], 11);
  for (const pkt of chunks) {
    assert.equal(verifyPacketChecksum(pkt), true);
  }

  const reassembled = decompileMacroPackets(chunks);
  assert.equal(reassembled.keyIdx, 2);
  assert.equal(reassembled.events.length, 16);

  // Alias sanity
  assert.equal(frameMacroChunks(2, longEvents).length, 3);
});

test('11. Unsolicited 0xC0/0xC2 notifications, mutex serialization, and >= 50ms post-write settle delay', async () => {
  const traces = [];
  const hid = new MockHidDevice(VIRGIN_BACKUP_FIXTURE.regs);
  hid.opened = true;
  const dev = new ValkyrieM220Device(hid, {
    writeSettleMs: 55,
    logger: (dir, cmd, data) => traces.push({ dir, cmd, data }),
  });

  await dev.syncAll();

  // Trigger concurrent write + read and measure gap between write TX (0x07) and following read TX (0x17)
  const tStart = hid.txTimestamps.length;
  await dev.setSleepAndDebounce({ debounceMs: 5 });
  const writeIdx = tStart;
  const readBackIdx = tStart + 1;
  const deltaMs = hid.txTimestamps[readBackIdx] - hid.txTimestamps[writeIdx];
  assert.ok(deltaMs >= 45, `Expected >= 50ms write settle delay (got ${deltaMs.toFixed(1)} ms)`);

  // Queue two concurrent operations and assert strict FIFO completion
  const order = [];
  await Promise.all([
    dev.setPollingRate(500).then(() => order.push('poll')),
    dev.setLighting({ mode: 4, brightness: 3, speed: 2 }).then(() => order.push('light')),
  ]);
  assert.deepEqual(order, ['poll', 'light']);

  // Unsolicited 0xC2 (DPI stage 4 of 6)
  const pC2 = new Uint8Array(32);
  pC2[0] = 0xC2;
  pC2[1] = 0x46;
  hid.emitInputReport(pC2);
  assert.equal(dev.state.activeDpiStage, 4);

  // Unsolicited 0xC0 (battery/online)
  const pC0 = new Uint8Array(32);
  pC0[0] = 0xC0;
  pC0[1] = 0x01; // online
  pC0[2] = 75;   // 75%
  pC0[3] = 0x00; // not charging
  hid.emitInputReport(pC0);
  assert.equal(dev.state.online, true);
  assert.equal(dev.state.batteryPct, 75);
  assert.equal(dev.state.charging, false);

  assert.equal(decodeNotificationPacket(pC2).activeStage, 4);
  assert.ok(traces.some((t) => t.dir === 'EVT' && t.cmd === 0xC0));
  assert.ok(traces.some((t) => t.dir === 'EVT' && t.cmd === 0xC2));
  dev.dispose();
});

test('12. Snapshot export/import, 256-bit diff, safeRollback [0x02..0x07,0x09], and Factory Reset', async () => {
  const hid = new MockHidDevice(VIRGIN_BACKUP_FIXTURE.regs);
  hid.opened = true;
  const dev = new ValkyrieM220Device(hid, { writeSettleMs: 50 });
  await dev.syncAll();

  const virgin = dev.importSnapshot(VIRGIN_BACKUP_FIXTURE);
  await dev.setSleepAndDebounce({ debounceMs: 2 }); // changes 0x08 -> 0x02 (bits 3 & 1 differ = 2 bits) and checksum 0x28 -> 0x22 (2 bits)

  const diff = dev.diffSnapshot(virgin);
  assert.ok(diff.changedOpcodes.includes('0x17'));
  assert.equal(diff.registers['0x17'].bits.length, 256);
  assert.equal(diff.registers['0x17'].changedBytes, 2); // byte[7] & byte[31] checksum
  assert.equal(diff.registers['0x17'].changedBits, 4);

  // Standalone computeSnapshotDiff sanity
  const zeroDiff = computeSnapshotDiff(virgin, virgin);
  assert.equal(zeroDiff.totalChangedBits, 0);

  // Safe rollback writes ONLY 0x02..0x07 & 0x09
  hid.sentReports.length = 0;
  const rb = await dev.safeRollback(virgin);
  const writeCmds = hid.sentReports
    .map((p) => p[0])
    .filter((cmd) => cmd < 0x10);
  const expectedWriteOrder = SAFE_ROLLBACK_WRITE_PAIRS.map((p) => p.writeCmd);
  assert.deepEqual(writeCmds, expectedWriteOrder);
  assert.equal(rb.diff.totalChangedBits, 0);

  // Factory reset 0x0F restores fixture after mutation
  await dev.setPollingRate(250);
  await dev.factoryResetDevice();
  assert.equal(dev.state.pollingHz, 1000);
  assert.ok(hid.sentReports.some((p) => p[0] === 0x0F && p[4] === 0xFF));

  // XML factory defaults (E023)
  await dev.restoreXmlFactoryDefaults('VK_M3');
  assert.deepEqual(dev.state.stages.map((s) => s.color), ['#FF0000', '#00FF00', '#0000FF', '#00FFFF', '#FFFF00', '#800080']);

  const snap = await dev.exportSnapshot({ refresh: false });
  assert.equal(snap.schema, 'valkyrie-snapshot-v1');
  assert.ok(snap.regs['0x10']);
  dev.dispose();
});

function createMockHelperServer({
  devices,
  initialRegs = VIRGIN_BACKUP_FIXTURE.regs,
  hidOpts = {},
  omitEventsBody = false,
} = {}) {
  const mockHid = new MockHidDevice(initialRegs, hidOpts);
  const calls = [];
  const encoder = new TextEncoder();
  let streamCtrl = null;

  const deviceList = devices ?? [
    {
      id: 'ota-ffef',
      vendorId: 0x248A,
      productId: 0x5D2E,
      productName: 'Valkyrie VK M3 OTA',
      usagePage: 0xFFEF,
      usage: 0x0000,
      inputReportBytes: 64,
      outputReportBytes: 64,
      isWireless: false,
    },
    {
      id: 'mi02-cmd',
      vendorId: 0x248A,
      productId: 0x5D2E,
      productName: 'Valkyrie VK M3 Series',
      usagePage: 0x0001,
      usage: 0x0000,
      inputReportBytes: 32,
      outputReportBytes: 32,
      isWireless: false,
    },
  ];

  mockHid.addEventListener('inputreport', (ev) => {
    if (!streamCtrl) return;
    const bytes = new Uint8Array(ev.data.buffer, ev.data.byteOffset, ev.data.byteLength);
    const line = `${JSON.stringify({ type: 'inputreport', reportId: 0, data: Array.from(bytes) })}\n`;
    streamCtrl.enqueue(encoder.encode(line));
  });

  const pushNdjsonLine = (text) => {
    if (!streamCtrl) return;
    streamCtrl.enqueue(encoder.encode(text));
  };

  const pushNdjsonObject = (obj) => {
    pushNdjsonLine(`${JSON.stringify(obj)}\n`);
  };

  const closeStream = () => {
    if (!streamCtrl) return;
    try {
      streamCtrl.close();
    } catch {
      // Ignore if already closed
    }
    streamCtrl = null;
  };

  const fetchImpl = async (url, init = {}) => {
    const parsedUrl = new URL(url);
    const method = (init.method || 'GET').toUpperCase();
    const parsedBody = init.body ? JSON.parse(init.body) : null;
    calls.push({ method, path: parsedUrl.pathname, body: parsedBody });

    if (method === 'GET' && parsedUrl.pathname === '/api/devices') {
      return new Response(JSON.stringify({ ok: true, devices: deviceList }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (method === 'POST' && parsedUrl.pathname === '/api/open') {
      await mockHid.open();
      const target = deviceList.find((d) => !parsedBody?.deviceId || d.id === parsedBody.deviceId) || deviceList[0];
      return new Response(JSON.stringify({ ok: true, device: target }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (method === 'GET' && parsedUrl.pathname === '/api/events') {
      if (omitEventsBody) {
        return { ok: true, status: 200 };
      }
      const stream = new ReadableStream({
        start(ctrl) {
          streamCtrl = ctrl;
          ctrl.enqueue(encoder.encode('{"type":"ready"}\n'));
        },
        cancel() {
          streamCtrl = null;
        },
      });
      return new Response(stream, {
        status: 200,
        headers: { 'Content-Type': 'application/x-ndjson' },
      });
    }

    if (method === 'POST' && parsedUrl.pathname === '/api/report') {
      const payload = Uint8Array.from(parsedBody.data || []);
      await mockHid.sendReport(parsedBody.reportId, payload);
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (method === 'POST' && parsedUrl.pathname === '/api/close') {
      await mockHid.close();
      pushNdjsonObject({ type: 'disconnect' });
      closeStream();
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ ok: false, error: 'NOT_FOUND' }), { status: 404 });
  };

  return { fetchImpl, calls, mockHid, pushNdjsonLine, pushNdjsonObject, closeStream };
}

test('13. WebHidManager.isSupported() and autoConnectExisting() perform zero localhost fetch calls', async () => {
  let globalFetchCalls = 0;
  let injectedFetchCalls = 0;
  const origFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    globalFetchCalls += 1;
    throw new Error('Unexpected global fetch call during page load');
  };

  try {
    const mgr = new WebHidManager({
      writeSettleMs: 50,
      fetchImpl: async () => {
        injectedFetchCalls += 1;
        throw new Error('Unexpected injected fetch call during autoConnectExisting');
      },
    });
    assert.equal(mgr.isSupported(), false);
    assert.equal(mgr.transportType, null);
    const res = await mgr.autoConnectExisting();
    assert.equal(res, null);
    assert.equal(globalFetchCalls, 0);
    assert.equal(injectedFetchCalls, 0);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('14. fetchHelperDevices maps unreachable/no-device errors and filters out 0xFFEF OTA & non-Valkyrie devices', async () => {
  await assert.rejects(
    () => fetchHelperDevices({
      baseUrl: DEFAULT_HELPER_BASE_URL,
      fetchImpl: async () => {
        throw new TypeError('Failed to fetch');
      },
    }),
    (err) => err.code === 'LOCAL_HELPER_UNAVAILABLE'
  );

  await assert.rejects(
    () => fetchHelperDevices({
      fetchImpl: async () => new Response(JSON.stringify({ ok: true, devices: [] }), { status: 200 }),
    }),
    (err) => err.code === 'LOCAL_HELPER_NO_DEVICE'
  );

  // Only OTA (0xFFEF) + wrong VID -> LOCAL_HELPER_NO_DEVICE
  await assert.rejects(
    () => fetchHelperDevices({
      fetchImpl: async () => new Response(JSON.stringify({
        ok: true,
        devices: [
          { id: 'ota', vendorId: 0x248A, productId: 0x5D2E, usagePage: 0xFFEF, usage: 0x0000, inputReportBytes: 64, outputReportBytes: 64 },
          { id: 'other', vendorId: 0x1234, productId: 0x5678, usagePage: 0x0001, usage: 0x0000, inputReportBytes: 32, outputReportBytes: 32 },
        ],
      }), { status: 200 }),
    }),
    (err) => err.code === 'LOCAL_HELPER_NO_DEVICE'
  );

  // Valid devices returned sorted with (0xFF01, 0x0010) preferred over (0x0001, 0x0000), excluding 0xFFEF
  const valid = await fetchHelperDevices({
    fetchImpl: async () => new Response(JSON.stringify({
      ok: true,
      devices: [
        { id: 'ota', vendorId: 0x248A, productId: 0x5D2E, usagePage: 0xFFEF, usage: 0x0000, inputReportBytes: 64, outputReportBytes: 64 },
        { id: 'desktop', vendorId: 0x248A, productId: 0x5D2E, usagePage: 0x0001, usage: 0x0000, inputReportBytes: 32, outputReportBytes: 32 },
        { id: 'vendor', vendorId: 0x249A, productId: 0x5C2F, usagePage: 0xFF01, usage: 0x0010, inputReportBytes: 32, outputReportBytes: 32, isWireless: true },
      ],
    }), { status: 200 }),
  });
  assert.equal(valid.length, 2);
  assert.equal(valid[0].id, 'vendor');
  assert.equal(valid[0].usagePage, 0xFF01);
  assert.equal(valid[1].id, 'desktop');

  // NotAllowedError maps to LOCAL_HELPER_BLOCKED (e.g. browser LNA/PNA permission block)
  await assert.rejects(
    () => fetchHelperDevices({
      fetchImpl: async () => {
        const err = new Error('Permission denied');
        err.name = 'NotAllowedError';
        throw err;
      },
    }),
    (err) => err.code === 'LOCAL_HELPER_BLOCKED'
  );

  // Direct open() on 0xFFEF LocalBridgeHidDevice throws OTA_COLLECTION_BLOCKED before fetch
  let otaFetchCalls = 0;
  const otaBridge = new LocalBridgeHidDevice(
    { id: 'ota', vendorId: 0x248A, productId: 0x5D2E, usagePage: 0xFFEF, usage: 0x0000, inputReportBytes: 64, outputReportBytes: 64 },
    { fetchImpl: async () => { otaFetchCalls += 1; } }
  );
  await assert.rejects(() => otaBridge.open(), (err) => err.code === 'OTA_COLLECTION_BLOCKED');
  assert.equal(otaFetchCalls, 0);
});

test('15. LocalBridgeHidDevice enforces reportId === 0 and 0x18..0x2A stall guard BEFORE fetch POST /api/report', async () => {
  const helper = createMockHelperServer();
  const bridge = new LocalBridgeHidDevice(
    { id: 'mi02-cmd', vendorId: 0x248A, productId: 0x5D2E, usagePage: 0x0001, usage: 0x0000, inputReportBytes: 32, outputReportBytes: 32 },
    { fetchImpl: helper.fetchImpl }
  );

  await bridge.open();
  helper.calls.length = 0;

  for (const blockedCmd of [0x18, 0x19, 0x21, 0x2A, 0x52]) {
    const pkt = new Uint8Array(32);
    pkt[0] = blockedCmd;
    await assert.rejects(
      () => bridge.sendReport(0, pkt),
      (err) => err.code === 'STALL_GUARD_BLOCKED'
    );
  }

  // Non-zero reportId must also fail before fetch
  await assert.rejects(
    () => bridge.sendReport(1, buildCommandPacket(0x10)),
    (err) => err.code === 'STALL_GUARD_BLOCKED'
  );

  assert.equal(helper.calls.length, 0, 'Zero POST /api/report calls may occur for stall-guarded reports');

  // Allowed 0x20 passes through to POST /api/report
  await bridge.sendReport(0, buildCommandPacket(0x20));
  assert.equal(helper.calls.filter((c) => c.path === '/api/report').length, 1);

  await bridge.close();
  assert.equal(bridge.opened, false);
});

test('16. WebHidManager.connectViaLocalHelper() completes syncAll, streams chunked 0xC0 NDJSON notifications, and disconnects cleanly', async () => {
  const helper = createMockHelperServer();
  const statusEvents = [];
  const notifications = [];
  const stateChanges = [];

  const mgr = new WebHidManager({
    writeSettleMs: 50,
    onStatusChange: (status, info) => statusEvents.push({ status, info }),
    onNotification: (evt) => notifications.push(evt),
    onStateChange: (st) => stateChanges.push(st),
  });

  const session = await mgr.connectViaLocalHelper({
    baseUrl: 'http://127.0.0.1:19480/',
    fetchImpl: helper.fetchImpl,
  });

  assert.equal(mgr.transportType, 'local-helper');
  assert.equal(session.transportType, 'local-helper');
  assert.equal(session.helperBaseUrl, 'http://127.0.0.1:19480');
  assert.equal(session.collection.usagePage, 0x0001);
  assert.equal(session.state.devId, 'M220');
  assert.equal(session.state.fwVersion, 'v3.17');
  assert.deepEqual(session.state.stages.map((s) => s.x), [800, 1200, 2000, 5000, 8000, 12000]);

  assert.equal(statusEvents.length, 1);
  assert.equal(statusEvents[0].status, 'connected');
  assert.equal(statusEvents[0].info.transportType, 'local-helper');
  assert.equal(statusEvents[0].info.helperBaseUrl, 'http://127.0.0.1:19480');

  // Verify 0x18 stall guard through ValkyrieM220Device over LocalBridgeHidDevice
  const reportCallsBefore = helper.calls.filter((c) => c.path === '/api/report').length;
  await assert.rejects(
    () => session.device.sendAllowlistedRaw(0x18, [0x00]),
    (err) => err.code === 'STALL_GUARD_BLOCKED'
  );
  assert.equal(helper.calls.filter((c) => c.path === '/api/report').length, reportCallsBefore);

  // Stream ping + unsolicited 0xC0 battery report split across two NDJSON chunks
  const c0 = new Uint8Array(32);
  c0[0] = 0xC0;
  c0[1] = 0x01; // online
  c0[2] = 42;   // 42%
  c0[3] = 0x01; // charging
  c0[31] = computeChecksum(c0);

  const ndjsonChunked = `{"type":"ping"}\n${JSON.stringify({
    type: 'inputreport',
    reportId: 0,
    data: Array.from(c0),
  })}\n`;
  const splitAt = Math.floor(ndjsonChunked.length / 2);
  helper.pushNdjsonLine(ndjsonChunked.slice(0, splitAt));
  helper.pushNdjsonLine(ndjsonChunked.slice(splitAt));

  await new Promise((r) => setTimeout(r, 25));
  assert.equal(notifications.length, 1);
  assert.equal(notifications[0].kind, 'battery');
  assert.equal(notifications[0].batteryPct, 42);
  assert.equal(notifications[0].charging, true);
  assert.equal(stateChanges.at(-1).batteryPct, 42);

  await mgr.disconnect();
  assert.equal(mgr.transportType, null);
  assert.equal(mgr.device, null);
  assert.equal(mgr.hidDevice, null);
  assert.equal(statusEvents.at(-1).status, 'disconnected');
  assert.ok(helper.calls.some((c) => c.method === 'POST' && c.path === '/api/close'));
});

test('17. LocalBridgeHidDevice handles missing response.body gracefully and propagates {"type":"disconnect"} to WebHidManager', async () => {
  // Part A: open/close gracefully when mock fetch response has no ReadableStream body
  const bodylessHelper = createMockHelperServer({ omitEventsBody: true });
  const bodylessBridge = new LocalBridgeHidDevice(
    { id: 'mi02-cmd', vendorId: 0x248A, productId: 0x5D2E, usagePage: 0x0001, usage: 0x0000, inputReportBytes: 32, outputReportBytes: 32 },
    { fetchImpl: bodylessHelper.fetchImpl }
  );
  await bodylessBridge.open();
  assert.equal(bodylessBridge.opened, true);
  await bodylessBridge.close();
  assert.equal(bodylessBridge.opened, false);

  // Part B: helper stream emitting {"type":"disconnect"} triggers WebHidManager.disconnect(true)
  const helper = createMockHelperServer();
  const events = [];
  let disconnectCallbackCalls = 0;

  const mgr = new WebHidManager({
    writeSettleMs: 50,
    onStatusChange: (status) => events.push(status),
    onDeviceDisconnect: () => { disconnectCallbackCalls += 1; },
  });

  await mgr.connectViaLocalHelper({ fetchImpl: helper.fetchImpl });
  assert.equal(mgr.transportType, 'local-helper');

  helper.pushNdjsonObject({ type: 'disconnect' });
  await new Promise((r) => setTimeout(r, 30));

  assert.equal(mgr.transportType, null);
  assert.equal(mgr.device, null);
  assert.equal(disconnectCallbackCalls, 1);
  assert.deepEqual(events, ['connected', 'disconnected']);

  // Part C: WebHID native connectDevice sets transportType === 'webhid' and helperBaseUrl === null
  const nativeStatuses = [];
  const nativeMgr = new WebHidManager({
    writeSettleMs: 50,
    onStatusChange: (status, info) => nativeStatuses.push({ status, info }),
  });
  const nativeHid = new MockHidDevice(VIRGIN_BACKUP_FIXTURE.regs, {
    collections: [makeCollection(0x0001, 0x0000, 32)],
  });
  const nativeSession = await nativeMgr.connectDevice(nativeHid);
  assert.equal(nativeMgr.transportType, 'webhid');
  assert.equal(nativeSession.transportType, 'webhid');
  assert.equal(nativeSession.helperBaseUrl, null);
  assert.equal(nativeStatuses[0].info.transportType, 'webhid');
  assert.equal(nativeStatuses[0].info.helperBaseUrl, null);
  await nativeMgr.disconnect();
  assert.equal(nativeMgr.transportType, null);
});

test('18. Fast disconnect while LocalBridgeHidDevice POST /api/report is in flight produces zero unhandled rejections', async () => {
  const helper = createMockHelperServer();
  let releaseReportFetch = null;
  let reportInFlightResolve = null;
  const reportInFlight = new Promise((r) => { reportInFlightResolve = r; });

  const delayedFetch = async (url, init = {}) => {
    const parsedUrl = new URL(url);
    if ((init.method || 'GET').toUpperCase() === 'POST' && parsedUrl.pathname === '/api/report') {
      const parsedBody = init.body ? JSON.parse(init.body) : null;
      // Hold one 0x20 report mid-flight so disconnect() runs while sendReport() is suspended
      if (parsedBody?.data?.[0] === 0x20 && !releaseReportFetch) {
        reportInFlightResolve();
        await new Promise((r) => { releaseReportFetch = r; });
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
    }
    return helper.fetchImpl(url, init);
  };

  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);

  try {
    const mgr = new WebHidManager({ writeSettleMs: 50 });
    const session = await mgr.connectViaLocalHelper({ fetchImpl: delayedFetch });

    const pendingOp = session.device.sendAllowlistedRaw(0x20, []);
    await reportInFlight;

    // Disconnect while POST /api/report is still suspended (triggers dispose() -> #pending.reject)
    await mgr.disconnect();
    releaseReportFetch();

    await assert.rejects(
      () => pendingOp,
      (err) => err.code === 'DEVICE_DISPOSED'
    );
    await new Promise((r) => setTimeout(r, 10));

    assert.equal(unhandled.length, 0);
    assert.equal(mgr.transportType, null);
    assert.equal(mgr.device, null);
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});
