/**
 * Valkyrie Control Application Controller
 *
 * Coordinates WebHID transport (`M220` VK M3 Lite / `E023` VK M3),
 * offline preview mode, 6 hardware workspaces, macro timeline compiler,
 * EEPROM snapshot/256-bit diffing, and live 32-byte protocol console.
 */

import { DEFAULT_DEVICE_FALLBACK, DEVICE_BY_DEVID, getDeviceByDevId } from './devices.js';
import { MODEL_PROFILES, getModelByKey, getModelByPid } from './models.js';
import { WebHidManager } from './hid/webhid-manager.js';
import {
  ALL_POLLING_RATES_HZ,
  HZ_TO_POLLING_CODE,
  SAFE_DUMP_OPCODES,
  buildCommandPacket,
  computeChecksum,
  computeSnapshotDiff,
  decodeButtonsPacket,
  decodeDonglePacket,
  decodeDpiCode,
  decodeDpiColorsPacket,
  decodeDpiPacket,
  decodeHandshakePacket,
  decodeLightingPacket,
  decodePollingPacket,
  decodeSensorPacket,
  decodeSleepPacket,
  encodeDpiCode,
  formatHex,
  getSensorProfile,
  hexToRgb,
  isAllowedOpcode,
  normalizeRegisterMap,
  parseHex,
} from './protocol/m220-device.js';
import {
  HID_TO_CODE,
  MEDIA_KEYS,
  USB_HID_KEYMAP,
  compileMacroStream,
  encodeButtonDescriptor,
  frameMacroChunks,
  resolveKeySpec,
} from './protocol/macro-compiler.js';
import { i18n, t } from './i18n/index.js';

const THEME_STORAGE_KEY = 'valkyrie-theme';

const STAGE_COLOR_PALETTE = [
  '#FFFF00',
  '#00FFFF',
  '#00FF00',
  '#800080',
  '#0000FF',
  '#FF0000',
];

const MEDIA_KEY_LIST = [
  'play_pause',
  'vol_up',
  'vol_down',
  'mute',
  'next_track',
  'prev_track',
  'stop_media',
  'browser_back',
  'browser_forward',
  'browser_refresh',
  'browser_home',
  'calculator',
  'email',
  'my_computer',
];

const COMMON_MACRO_KEYS = [
  'KeyA', 'KeyB', 'KeyC', 'KeyD', 'KeyE', 'KeyF', 'KeyG', 'KeyH',
  'KeyI', 'KeyJ', 'KeyK', 'KeyL', 'KeyM', 'KeyN', 'KeyO', 'KeyP',
  'KeyQ', 'KeyR', 'KeyS', 'KeyT', 'KeyU', 'KeyV', 'KeyW', 'KeyX',
  'KeyY', 'KeyZ', 'Digit1', 'Digit2', 'Digit3', 'Digit4', 'Digit5',
  'Digit6', 'Digit7', 'Digit8', 'Digit9', 'Digit0', 'Enter', 'Escape',
  'Backspace', 'Tab', 'Space', 'F1', 'F2', 'F3', 'F4', 'F5', 'F6',
  'F7', 'F8', 'F9', 'F10', 'F11', 'F12', 'ControlLeft', 'ShiftLeft',
  'AltLeft', 'MetaLeft',
];

function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

function formatCmdHex(cmd) {
  return `0x${(Number(cmd) & 0xFF).toString(16).toUpperCase().padStart(2, '0')}`;
}

function formatHex16(val) {
  return `0x${(Number(val) & 0xFFFF).toString(16).toUpperCase().padStart(4, '0')}`;
}

function formatDuration(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  const rem = String(s % 60).padStart(2, '0');
  return `${m}m ${rem}s`;
}

class ValkyrieControlApp {
  constructor() {
    this.hidManager = new WebHidManager({
      logger: (dir, cmd, bytes, entry) => this.appendConsoleEntry(dir, cmd, bytes, entry),
      onStatusChange: (status, info) => this.handleConnectionStatus(status, info),
      onStateChange: (hwState) => this.handleHardwareStateChange(hwState),
      onNotification: (evt) => this.handleDeviceNotification(evt),
      onDeviceDisconnect: () => this.handleDeviceDisconnected(),
    });

    this.device = null;
    this.descriptor = null;
    this.activeCollection = null;
    this.isConnected = false;

    this.theme = this.readSavedTheme();
    this.activeTab = 'performance';
    this.selectedButtonSlot = 0;
    this.activeMacroSlot = 0;
    this.selectedDiffOpcode = '0x13';

    this.winCompatVisible = false;
    this.wirelessWarnDismissed = false;
    this.helperConnecting = false;
    this.modalLastTrigger = null;

    this.pendingKey = { modifiers: 0, hid: 0, code: null };
    this.isRecordingMacro = false;
    this.lastMacroEventTs = 0;
    this._macroKeyDownHandler = null;
    this._macroKeyUpHandler = null;
    this._macroMouseDownHandler = null;
    this._macroMouseUpHandler = null;

    this.state = this.createPreviewState('VK_M3_LITE');
    this.previewRegs = this.buildPreviewRegisters();
    this.baselineCustomName = null;
    this.baselineSnapshot = {
      schema: 'valkyrie-snapshot-v1',
      regs: { ...this.previewRegs },
    };

    this.cacheDom();
    this.applyTheme(this.theme, false);
    this.bindEvents();
    this.initApp();
  }

  readSavedTheme() {
    try {
      const saved = localStorage.getItem(THEME_STORAGE_KEY);
      if (saved === 'light' || saved === 'dark') return saved;
    } catch {
      // Ignore storage errors
    }
    return document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
  }

  createPreviewState(modelKey) {
    const profile = getModelByKey(modelKey);
    const devSpec = getDeviceByDevId(profile.devId) || DEVICE_BY_DEVID.M220;
    const d = profile.factoryDefaults;
    const defaultPid = devSpec.usbPids?.[1] || devSpec.usbPids?.[0] || DEFAULT_DEVICE_FALLBACK.pid;

    return {
      connected: false,
      isWireless: false,
      vendorId: devSpec.usbVids?.[0] || 0x248A,
      productId: defaultPid,
      productName: profile.name,
      devId: profile.devId,
      modelKey: profile.id,
      fwRaw: 0,
      fwVersion: '—',
      rfFwRaw: 0,
      rfFwVersion: '—',
      sensorId: profile.sensorId,
      sensorName: profile.sensorName,
      unlockMax: false,
      lockDpiXY: true,
      maxDpiOfficial: 24000,
      maxDpiUnlocked: 26000,
      pollingCapsByte: 0x01,
      maxPollingHz: 1000,
      supportedPollingRates: [125, 250, 500, 1000],
      batteryPct: 100,
      charging: false,
      online: true,
      pollingHz: d.pollingHz,
      activeDpiStage: d.activeDpiStage,
      stages: d.stages.map((s) => ({ ...s })),
      lighting: { ...d.lighting, breathingColors: [...d.lighting.breathingColors] },
      lod: d.lod,
      angleSnap: d.angleSnap,
      ripple: d.ripple,
      motionSync: d.motionSync,
      motionSyncLocked: false,
      sleep10s: d.sleep10s,
      sleepSec: d.sleepSec,
      moveWake: d.moveWake,
      moveCloseLight: d.moveCloseLight,
      debounceMs: d.debounceMs,
      buttons: d.buttons.map((b, slot) => ({ slot, ...b })),
      macros: Array.from({ length: 6 }, (_, slot) => ({
        slot,
        name: '',
        events: [],
        loopMode: 'toggle',
        loopCount: 1,
      })),
    };
  }

  cacheDom() {
    const q = (id) => document.getElementById(id);
    this.dom = {
      appSidebar: q('appSidebar'),
      sidebarBackdrop: q('sidebarBackdrop'),
      btnMobileMenu: q('btnMobileMenu'),
      navItems: Array.from(document.querySelectorAll('.nav-item')),
      tabPanels: Array.from(document.querySelectorAll('.tab-panel')),
      sidebarDevId: q('sidebarDevId'),
      sidebarFwVersion: q('sidebarFwVersion'),
      sidebarSensor: q('sidebarSensor'),

      btnTheme: q('btnTheme'),
      iconThemeMoon: q('iconThemeMoon'),
      iconThemeSun: q('iconThemeSun'),
      lblThemeMode: q('lblThemeMode'),
      langPicker: q('langPicker'),
      btnLanguage: q('btnLanguage'),
      langMenu: q('langMenu'),
      selModel: q('selModel'),
      batteryBadge: q('batteryBadge'),
      batteryPercent: q('batteryPercent'),
      batteryChargingIcon: q('batteryChargingIcon'),
      statusDot: q('statusDot'),
      statusText: q('statusText'),
      btnTopbarCompatGuide: q('btnTopbarCompatGuide'),
      btnConnect: q('btnConnect'),

      // Compatibility & Wireless Banners
      winCompatBanner: q('winCompatBanner'),
      btnDismissWinCompat: q('btnDismissWinCompat'),
      btnHelperConnect: q('btnHelperConnect'),
      btnOpenCompatGuide: q('btnOpenCompatGuide'),
      wirelessStabilityBanner: q('wirelessStabilityBanner'),
      btnDismissWirelessWarn: q('btnDismissWirelessWarn'),

      // Compatibility Modal
      compatGuideModal: q('compatGuideModal'),
      btnModalCompatIconClose: q('btnModalCompatIconClose'),
      btnModalCompatClose: q('btnModalCompatClose'),
      btnModalHelperConnect: q('btnModalHelperConnect'),

      // Performance
      lblActiveStage: q('lblActiveStage'),
      chkLockDpiXY: q('chkLockDpiXY'),
      wrapUnlock26k: q('wrapUnlock26k'),
      chkUnlock26k: q('chkUnlock26k'),
      btnRemoveDpiStage: q('btnRemoveDpiStage'),
      btnAddDpiStage: q('btnAddDpiStage'),
      dpiStagesList: q('dpiStagesList'),
      lblPollingCap: q('lblPollingCap'),
      pollingGroup: q('pollingGroup'),
      pollingNotice: q('pollingNotice'),
      lodGroup: q('lodGroup'),
      chkAngleSnap: q('chkAngleSnap'),
      chkRipple: q('chkRipple'),
      rowMotionSync: q('rowMotionSync'),
      badgeMotionSyncLocked: q('badgeMotionSyncLocked'),
      chkMotionSync: q('chkMotionSync'),
      rngDebounce: q('rngDebounce'),
      numDebounce: q('numDebounce'),
      lblDebounceVal: q('lblDebounceVal'),
      rngSleepTimeout: q('rngSleepTimeout'),
      lblSleepTimeoutVal: q('lblSleepTimeoutVal'),
      chkMoveWake: q('chkMoveWake'),
      chkMoveCloseLight: q('chkMoveCloseLight'),
      btnFactoryReset: q('btnFactoryReset'),

      // Buttons
      schematicModelName: q('schematicModelName'),
      schematicSubtitle: q('schematicSubtitle'),
      schematicHardwareBadge: q('schematicHardwareBadge'),
      schematicCanvas: q('schematicCanvas'),
      schematicOverlay: q('schematicOverlay'),
      schematicCallouts: q('schematicCallouts'),
      schematicMouseFrame: q('schematicMouseFrame'),
      mouseRenderImg: q('mouseRenderImg'),
      schematicPins: q('schematicPins'),
      buttonSlotGrid: q('buttonSlotGrid'),
      selectedButtonName: q('selectedButtonName'),
      selectedButtonSlotBadge: q('selectedButtonSlotBadge'),
      btnReloadButtonsFromDevice: q('btnReloadButtonsFromDevice'),
      btnResetButtonDefault: q('btnResetButtonDefault'),
      selActionCategory: q('selActionCategory'),
      panelActionMouse: q('panelActionMouse'),
      selMouseAction: q('selMouseAction'),
      panelActionKeyboard: q('panelActionKeyboard'),
      keyCaptureBox: q('keyCaptureBox'),
      keyCaptureDisplay: q('keyCaptureDisplay'),
      btnClearChord: q('btnClearChord'),
      chkModCtrl: q('chkModCtrl'),
      chkModShift: q('chkModShift'),
      chkModAlt: q('chkModAlt'),
      chkModWin: q('chkModWin'),
      panelActionMedia: q('panelActionMedia'),
      selMediaAction: q('selMediaAction'),
      panelActionFire: q('panelActionFire'),
      rngFireInterval: q('rngFireInterval'),
      numFireInterval: q('numFireInterval'),
      lblFireIntervalVal: q('lblFireIntervalVal'),
      numFireCount: q('numFireCount'),
      panelActionMacro: q('panelActionMacro'),
      selMacroSlot: q('selMacroSlot'),
      selMacroLoop: q('selMacroLoop'),
      wrapMacroLoopCount: q('wrapMacroLoopCount'),
      numMacroLoopCount: q('numMacroLoopCount'),
      panelActionDpi: q('panelActionDpi'),
      selDpiAction: q('selDpiAction'),
      panelActionDisabled: q('panelActionDisabled'),
      btnApplyButton: q('btnApplyButton'),

      // Lighting
      lightingModeGroup: q('lightingModeGroup'),
      rngLightBri: q('rngLightBri'),
      lblLightBri: q('lblLightBri'),
      rngLightSpd: q('rngLightSpd'),
      lblLightSpd: q('lblLightSpd'),
      wrapLightDir: q('wrapLightDir'),
      lightDirGroup: q('lightDirGroup'),
      wrapLightColor: q('wrapLightColor'),
      inpLightColor: q('inpLightColor'),
      lblLightColorHex: q('lblLightColorHex'),
      wrapBreathingColors: q('wrapBreathingColors'),
      breathingColorRow: q('breathingColorRow'),
      btnApplyLighting: q('btnApplyLighting'),

      // Macros
      macroSlotList: q('macroSlotList'),
      inpMacroName: q('inpMacroName'),
      lblMacroActionCount: q('lblMacroActionCount'),
      lblMacroFrameBytes: q('lblMacroFrameBytes'),
      btnRecordMacro: q('btnRecordMacro'),
      btnClearMacro: q('btnClearMacro'),
      btnSaveMacro: q('btnSaveMacro'),
      btnExportMacro: q('btnExportMacro'),
      btnImportMacro: q('btnImportMacro'),
      inpImportMacro: q('inpImportMacro'),
      btnInsertKey: q('btnInsertKey'),
      btnInsertMouse: q('btnInsertMouse'),
      btnInsertDelay: q('btnInsertDelay'),
      selMacroStudioLoop: q('selMacroStudioLoop'),
      macroTimeline: q('macroTimeline'),

      // Inspector
      btnRefreshDump: q('btnRefreshDump'),
      dumpTable: q('dumpTable'),
      btnExportSnapshot: q('btnExportSnapshot'),
      btnImportBaseline: q('btnImportBaseline'),
      btnSafeRollback: q('btnSafeRollback'),
      inpImportBaseline: q('inpImportBaseline'),
      lblBaselineMeta: q('lblBaselineMeta'),
      inpRawOpcode: q('inpRawOpcode'),
      inpRawPayload: q('inpRawPayload'),
      btnRawSend: q('btnRawSend'),
      rawRunnerAlert: q('rawRunnerAlert'),
      rawRunnerOutput: q('rawRunnerOutput'),
      lblDiffSummary: q('lblDiffSummary'),
      diffOpcodeTabs: q('diffOpcodeTabs'),
      diffGridContainer: q('diffGridContainer'),
      btnClearConsole: q('btnClearConsole'),
      btnExportConsole: q('btnExportConsole'),
      packetLog: q('packetLog'),

      // Firmware
      fwSpecModel: q('fwSpecModel'),
      fwSpecDevId: q('fwSpecDevId'),
      fwSpecSensor: q('fwSpecSensor'),
      fwSpecVidPid: q('fwSpecVidPid'),
      fwSpecFw: q('fwSpecFw'),
      fwSpecCaps: q('fwSpecCaps'),
      fwSpecInterface: q('fwSpecInterface'),
      fwSpecTransport: q('fwSpecTransport'),
      fwSpecBattery: q('fwSpecBattery'),
      btnFwCompatGuide: q('btnFwCompatGuide'),

      toastContainer: q('toastContainer'),
    };
  }

  async initApp() {
    await i18n.init();
    i18n.onChange(() => this.onLocaleChanged());

    this.onLocaleChanged();

    if (typeof ResizeObserver === 'function' && this.dom.schematicCanvas) {
      this.schematicResizeObserver = new ResizeObserver(() => this.drawSchematicLeaders());
      this.schematicResizeObserver.observe(this.dom.schematicCanvas);
    }
    window.addEventListener('resize', () => this.drawSchematicLeaders());
    this.dom.mouseRenderImg?.addEventListener('load', () => this.drawSchematicLeaders());

    if (this.hidManager.isSupported()) {
      this.hidManager.autoConnectExisting().catch(() => {});
    } else {
      this.dom.statusText.textContent = t('topbar.statusUnavailable');
      this.dom.btnConnect.disabled = true;
    }
  }

  applyTheme(theme, persist = true) {
    this.theme = theme === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', this.theme);
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
      meta.setAttribute('content', this.theme === 'light' ? '#f6f8fa' : '#13161b');
    }
    if (persist) {
      try {
        localStorage.setItem(THEME_STORAGE_KEY, this.theme);
      } catch {
        // Ignore storage errors
      }
    }
    this.dom.iconThemeMoon?.classList.toggle('hidden', this.theme === 'light');
    this.dom.iconThemeSun?.classList.toggle('hidden', this.theme !== 'light');
    if (this.dom.lblThemeMode) {
      this.dom.lblThemeMode.textContent = this.theme === 'light'
        ? t('topbar.themeLight')
        : t('topbar.themeDark');
    }
  }

  onLocaleChanged() {
    i18n.applyDom(document);
    this.applyTheme(this.theme, false);
    this.renderAll();
  }

  formatProtocolError(err) {
    if (!err) return 'Unknown error';
    switch (err.code) {
      case 'WEBHID_UNSUPPORTED':
        return t('errors.webhidUnsupported');
      case 'NO_COMMAND_INTERFACE':
        return t('errors.noCommandInterface');
      case 'OTA_COLLECTION_BLOCKED':
        return t('errors.otaCollectionBlocked');
      case 'LOCAL_HELPER_UNAVAILABLE':
        return t('errors.localHelperUnavailable');
      case 'LOCAL_HELPER_NO_DEVICE':
        return t('errors.localHelperNoDevice');
      case 'LOCAL_HELPER_BLOCKED':
        return t('errors.localHelperBlocked');
      case 'HID_TIMEOUT':
        return this.state.isWireless
          ? t('toast.wirelessTimeoutTip')
          : (err.message || 'HID timeout');
      case 'STALL_GUARD_BLOCKED':
        return t('errors.stallGuardBlocked', { cmd: formatCmdHex(err.cmd ?? 0) });
      case 'HARDWARE_REJECTED':
        return t('toast.hardwareRejected', { cmd: formatCmdHex(err.cmd ?? 0) });
      case 'POLLING_UNSUPPORTED':
        return t('perf.pollingUnsupported', { max: err.maxPollingHz ?? this.state.maxPollingHz });
      case 'MISSING_EVENTS_ARRAY':
        return t('errors.missingEventsArray');
      default:
        return err.message || String(err);
    }
  }

  showHardwareError(err) {
    if (err?.code === 'HID_TIMEOUT' && this.state.isWireless) {
      this.showToast(t('toast.wirelessTimeoutTip'), true);
      return;
    }
    this.showToast(t('toast.hardwareWriteFailed', { msg: this.formatProtocolError(err) }), true);
  }

  getConnectedStatusText() {
    if (this.hidManager.transportType === 'local-helper') {
      return this.state.isWireless ? t('topbar.statusHelperDongle') : t('topbar.statusHelper');
    }
    return this.state.isWireless ? t('topbar.statusDongle') : t('topbar.statusConnected');
  }

  renderBanners() {
    const showWinCompat = !this.isConnected && this.winCompatVisible;
    const showWirelessWarn = this.isConnected && Boolean(this.state.isWireless) && !this.wirelessWarnDismissed;
    this.dom.winCompatBanner?.classList.toggle('hidden', !showWinCompat);
    this.dom.wirelessStabilityBanner?.classList.toggle('hidden', !showWirelessWarn);
  }

  renderHelperConnectButtons() {
    const busy = this.helperConnecting;
    if (this.dom.btnHelperConnect) {
      this.dom.btnHelperConnect.disabled = busy;
      this.dom.btnHelperConnect.textContent = busy
        ? t('diagnostics.connectingHelperBtn')
        : t('diagnostics.connectHelperBtn');
    }
    if (this.dom.btnModalHelperConnect) {
      this.dom.btnModalHelperConnect.disabled = busy;
      this.dom.btnModalHelperConnect.textContent = busy
        ? t('diagnostics.connectingHelperBtn')
        : t('compat.connectBtn');
    }
  }

  setCompatModalOpen(open, triggerEl = null) {
    if (!this.dom.compatGuideModal) return;
    if (open) {
      this.modalLastTrigger = triggerEl || document.activeElement;
      this.dom.compatGuideModal.classList.remove('hidden');
      this.dom.btnModalCompatIconClose?.focus();
    } else if (!this.dom.compatGuideModal.classList.contains('hidden')) {
      this.dom.compatGuideModal.classList.add('hidden');
      const target = this.modalLastTrigger;
      this.modalLastTrigger = null;
      if (target && typeof target.focus === 'function' && target.isConnected) {
        target.focus();
      }
    }
  }

  async connectViaLocalHelper() {
    if (this.helperConnecting) return;
    this.helperConnecting = true;
    this.renderHelperConnectButtons();
    try {
      await this.hidManager.connectViaLocalHelper();
      this.setCompatModalOpen(false);
    } catch (err) {
      const msg = this.formatProtocolError(err);
      if (err?.code === 'HID_TIMEOUT' && this.state.isWireless) {
        this.showToast(t('toast.wirelessTimeoutTip'), true);
      } else {
        this.showToast(msg, true);
      }
    } finally {
      this.helperConnecting = false;
      this.renderHelperConnectButtons();
    }
  }

  // === Connection Lifecycle ===

  async handleConnectionStatus(status, info = {}) {
    if (status === 'connected') {
      this.device = this.hidManager.device;
      this.descriptor = info.descriptor || null;
      this.activeCollection = info.collection || null;
      this.isConnected = true;
      this.winCompatVisible = false;

      if (info.state) {
        this.applyHardwareState(info.state, false);
      }

      this.dom.selModel.disabled = true;
      this.dom.btnConnect.textContent = t('topbar.disconnect');
      this.dom.statusDot.classList.add('connected');
      this.dom.statusText.textContent = this.getConnectedStatusText();
      this.dom.batteryBadge.classList.remove('hidden');
      this.renderBanners();

      try {
        await this.device.dumpAllRegisters();
      } catch {
        // Non-fatal if optional 0x20 times out
      }

      this.renderAll();
      const profile = getModelByKey(this.state.modelKey);
      const transport = info.transportType || this.hidManager.transportType;
      const toastKey = transport === 'local-helper' ? 'toast.helperConnected' : 'toast.connected';
      this.showToast(t(toastKey, { name: profile.name }));
    } else if (status === 'disconnected') {
      this.handleDeviceDisconnected();
    }
  }

  handleDeviceDisconnected() {
    this.device = null;
    this.descriptor = null;
    this.activeCollection = null;
    this.isConnected = false;
    this.state.connected = false;
    this.state.fwVersion = '—';
    this.state.rfFwVersion = '—';
    this.state.motionSyncLocked = false;

    this.dom.selModel.disabled = false;
    this.dom.btnConnect.textContent = t('topbar.connect');
    this.dom.statusDot.classList.remove('connected');
    this.dom.statusText.textContent = this.hidManager.isSupported()
      ? t('topbar.statusNotConnected')
      : t('topbar.statusUnavailable');
    this.dom.batteryBadge.classList.add('hidden');
    this.renderAll();
  }

  handleHardwareStateChange(hwState) {
    if (!hwState) return;
    this.applyHardwareState(hwState, true);
  }

  handleDeviceNotification(evt) {
    if (!evt) return;
    this.updateTopbarTelemetry();
    this.renderFirmwareTab();
    if (evt.kind === 'dpiStage') {
      this.renderDpiStages();
    }
  }

  applyHardwareState(hwState, rerender = true) {
    const prevMacros = this.state.macros;
    const lockDpiXY = Array.isArray(hwState.stages) && hwState.stages.length > 0
      ? hwState.stages.every((s) => s.x === s.y)
      : this.state.lockDpiXY;

    this.state = {
      ...this.state,
      ...hwState,
      lockDpiXY,
      macros: prevMacros,
    };

    if (this.dom.selModel && MODEL_PROFILES[this.state.modelKey]) {
      this.dom.selModel.value = this.state.modelKey;
    }

    if (rerender) {
      this.renderAll();
    }
  }

  getMacroDisplayName(slot) {
    const raw = this.state.macros[slot]?.name;
    if (!raw || raw === `Slot ${slot}`) {
      return t('buttons.macroSlotName', { n: slot });
    }
    return raw;
  }

  switchModelPreview(modelKey) {
    if (this.isConnected) return;
    const prevMacros = this.state.macros;
    this.state = this.createPreviewState(modelKey);
    this.state.macros = prevMacros;
    this.previewRegs = this.buildPreviewRegisters();
    this.baselineCustomName = null;
    this.baselineSnapshot = {
      schema: 'valkyrie-snapshot-v1',
      regs: { ...this.previewRegs },
    };
    if (this.dom.lblBaselineMeta) {
      this.dom.lblBaselineMeta.textContent = t('inspector.baselineFactory');
    }
    this.renderAll();
  }

  // === Preview Register Builder (Offline Parity) ===

  buildPreviewRegisters() {
    const devSpec = getDeviceByDevId(this.state.devId) || DEVICE_BY_DEVID.M220;
    const regs = {};

    // 0x10 Handshake
    const p10 = new Uint8Array(32);
    p10[0] = 0x10;
    p10[2] = 0x01;
    p10[3] = 0x0B;
    const idStr = (this.state.devId || 'M220').slice(0, 4);
    for (let i = 0; i < idStr.length; i += 1) {
      p10[4 + i] = idStr.charCodeAt(i);
    }
    p10[8] = 0x17;
    p10[9] = 0x03;
    p10[10] = this.state.sensorId & 0xFF;
    p10[11] = this.state.pollingCapsByte & 0xFF;
    p10[12] = this.state.charging ? 0x01 : 0x00;
    p10[13] = this.state.batteryPct & 0xFF;
    p10[14] = this.state.online ? 0x01 : 0x00;
    p10[31] = computeChecksum(p10);
    regs['0x10'] = formatHex(p10);

    // 0x11 Buttons
    const btnPayload = [];
    for (let i = 0; i < 6; i += 1) {
      const [b0, b1, b2] = encodeButtonDescriptor(this.state.buttons[i], i);
      btnPayload.push(b0, b1, b2);
    }
    const p11 = buildCommandPacket(0x11, btnPayload, { length: 0x12 });
    regs['0x11'] = formatHex(p11);

    // 0x12 Polling
    const p12 = buildCommandPacket(0x12, [HZ_TO_POLLING_CODE[this.state.pollingHz] ?? 0x01], { length: 0x01 });
    regs['0x12'] = formatHex(p12);

    // 0x13 DPI
    const dpiPayload = new Uint8Array(25);
    const count = clamp(this.state.stages.length, 1, 6);
    const active = clamp(this.state.activeDpiStage, 0, count - 1);
    dpiPayload[0] = ((active & 0x0F) << 4) | (count & 0x0F);
    for (let i = 0; i < count; i += 1) {
      const s = this.state.stages[i];
      const cx = encodeDpiCode(this.state.sensorId, s.x, { unlockMax: this.state.unlockMax });
      const cy = encodeDpiCode(this.state.sensorId, s.y, { unlockMax: this.state.unlockMax });
      const off = 1 + i * 4;
      dpiPayload[off] = cx & 0xFF;
      dpiPayload[off + 1] = (cx >> 8) & 0xFF;
      dpiPayload[off + 2] = cy & 0xFF;
      dpiPayload[off + 3] = (cy >> 8) & 0xFF;
    }
    regs['0x13'] = formatHex(buildCommandPacket(0x13, dpiPayload, { length: 0x19 }));

    // 0x14 DPI Colors
    const colorPayload = new Uint8Array(18);
    for (let i = 0; i < 6; i += 1) {
      const col = this.state.stages[i]?.color || devSpec.factoryColors[i] || '#2563EB';
      const [r, g, b] = hexToRgb(col);
      colorPayload[i * 3] = r;
      colorPayload[i * 3 + 1] = g;
      colorPayload[i * 3 + 2] = b;
    }
    regs['0x14'] = formatHex(buildCommandPacket(0x14, colorPayload, { length: 0x12 }));

    // 0x15 Lighting
    const l = this.state.lighting;
    const packed = ((l.speed & 0x0F) << 4) | (l.brightness & 0x0F);
    let lightPayload = [l.mode & 0xFF, packed];
    if (l.mode === 1) {
      lightPayload.push(l.direction & 0xFF);
    } else if (l.mode === 2) {
      lightPayload.push(0x07);
      for (let i = 0; i < 7; i += 1) {
        const [r, g, b] = hexToRgb(l.breathingColors[i] || '#FFFFFF');
        lightPayload.push(r, g, b);
      }
    } else if (l.mode === 3) {
      const [r, g, b] = hexToRgb(l.color || '#2563EB');
      lightPayload.push(r, g, b);
    }
    regs['0x15'] = formatHex(buildCommandPacket(0x15, lightPayload, { length: lightPayload.length }));

    // 0x16 Sensor
    regs['0x16'] = formatHex(
      buildCommandPacket(
        0x16,
        [this.state.lod, this.state.angleSnap ? 1 : 0, this.state.ripple ? 1 : 0, this.state.motionSync ? 1 : 0, 0x00],
        { length: 0x05 }
      )
    );

    // 0x17 Sleep & Debounce
    regs['0x17'] = formatHex(
      buildCommandPacket(
        0x17,
        [this.state.sleep10s & 0xFF, this.state.moveWake ? 1 : 0, this.state.moveCloseLight ? 1 : 0, this.state.debounceMs & 0xFF],
        { length: 0x04 }
      )
    );

    // 0x20 Extended
    regs['0x20'] = formatHex(buildCommandPacket(0x20, [0x17, 0x03], { length: 0x02 }));
    return regs;
  }

  getActiveRawRegisters() {
    if (this.isConnected && this.device) {
      const live = this.device.getRawRegisters();
      if (Object.keys(live).length > 0) return live;
    }
    this.previewRegs = this.buildPreviewRegisters();
    return this.previewRegs;
  }

  // === Event Wiring ===

  bindEvents() {
    const closeDrawer = () => {
      this.dom.appSidebar?.classList.remove('open');
      this.dom.sidebarBackdrop?.classList.remove('visible');
    };

    this.dom.btnMobileMenu?.addEventListener('click', () => {
      const opening = !this.dom.appSidebar.classList.contains('open');
      this.dom.appSidebar.classList.toggle('open', opening);
      this.dom.sidebarBackdrop.classList.toggle('visible', opening);
    });
    this.dom.sidebarBackdrop?.addEventListener('click', closeDrawer);

    this.dom.navItems.forEach((item) => {
      item.addEventListener('click', () => {
        this.switchTab(item.dataset.tab);
        closeDrawer();
      });
    });

    // Theme
    this.dom.btnTheme?.addEventListener('click', () => {
      this.applyTheme(this.theme === 'dark' ? 'light' : 'dark', true);
    });

    // Language Menu
    const setLangMenuOpen = (open) => {
      if (!this.dom.langMenu || !this.dom.btnLanguage) return;
      if (open) {
        const rect = this.dom.btnLanguage.getBoundingClientRect();
        this.dom.langMenu.classList.toggle('align-left', rect.right < 208);
      }
      this.dom.langMenu.classList.toggle('hidden', !open);
      this.dom.btnLanguage.setAttribute('aria-expanded', String(open));
    };

    this.dom.btnLanguage?.addEventListener('click', (e) => {
      e.stopPropagation();
      const willOpen = this.dom.langMenu?.classList.contains('hidden');
      setLangMenuOpen(Boolean(willOpen));
    });

    this.dom.langMenu?.addEventListener('click', async (e) => {
      const opt = e.target.closest('.lang-option');
      if (!opt) return;
      const pref = opt.dataset.lang;
      setLangMenuOpen(false);
      if (pref) await i18n.setPreference(pref);
    });

    document.addEventListener('click', (e) => {
      if (this.dom.langMenu && !this.dom.langMenu.classList.contains('hidden')) {
        if (this.dom.langPicker && !this.dom.langPicker.contains(e.target)) {
          setLangMenuOpen(false);
        }
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeDrawer();
        this.setCompatModalOpen(false);
        if (this.dom.langMenu && !this.dom.langMenu.classList.contains('hidden')) {
          setLangMenuOpen(false);
          this.dom.btnLanguage?.focus();
        }
      }
    });

    // Model & Connect
    this.dom.selModel?.addEventListener('change', (e) => {
      this.switchModelPreview(e.target.value);
    });

    this.dom.btnConnect?.addEventListener('click', async () => {
      if (this.isConnected) {
        await this.hidManager.disconnect();
        return;
      }
      try {
        await this.hidManager.requestAndConnect();
      } catch (err) {
        if (err?.code === 'OTA_COLLECTION_BLOCKED' || err?.code === 'NO_COMMAND_INTERFACE') {
          this.winCompatVisible = true;
          this.renderBanners();
        }
        const msg = this.formatProtocolError(err);
        if (err?.code === 'HID_TIMEOUT' && this.state.isWireless) {
          this.showToast(t('toast.wirelessTimeoutTip'), true);
        } else {
          this.showToast(t('toast.connectionFailed', { msg }), true);
        }
      }
    });

    // Compatibility & Wireless Banners + Modal
    this.dom.btnDismissWinCompat?.addEventListener('click', () => {
      this.winCompatVisible = false;
      this.renderBanners();
    });

    this.dom.btnDismissWirelessWarn?.addEventListener('click', () => {
      this.wirelessWarnDismissed = true;
      this.renderBanners();
    });

    this.dom.btnHelperConnect?.addEventListener('click', () => {
      this.connectViaLocalHelper();
    });

    this.dom.btnModalHelperConnect?.addEventListener('click', () => {
      this.connectViaLocalHelper();
    });

    this.dom.btnTopbarCompatGuide?.addEventListener('click', (e) => {
      this.setCompatModalOpen(true, e.currentTarget);
    });
    this.dom.btnOpenCompatGuide?.addEventListener('click', (e) => {
      this.setCompatModalOpen(true, e.currentTarget);
    });
    this.dom.btnFwCompatGuide?.addEventListener('click', (e) => {
      this.setCompatModalOpen(true, e.currentTarget);
    });

    this.dom.btnModalCompatClose?.addEventListener('click', () => {
      this.setCompatModalOpen(false);
    });
    this.dom.btnModalCompatIconClose?.addEventListener('click', () => {
      this.setCompatModalOpen(false);
    });
    this.dom.compatGuideModal?.addEventListener('click', (e) => {
      if (e.target === this.dom.compatGuideModal) {
        this.setCompatModalOpen(false);
      }
    });

    this.bindPerformanceEvents();
    this.bindButtonsEvents();
    this.bindLightingEvents();
    this.bindMacroEvents();
    this.bindInspectorEvents();
  }

  bindPerformanceEvents() {
    this.dom.chkLockDpiXY?.addEventListener('change', async (e) => {
      this.state.lockDpiXY = e.target.checked;
      if (this.state.lockDpiXY) {
        this.state.stages = this.state.stages.map((s) => ({ ...s, y: s.x }));
        await this.commitDpiConfig(false);
      }
      this.renderDpiStages();
    });

    this.dom.chkUnlock26k?.addEventListener('change', async (e) => {
      this.state.unlockMax = e.target.checked;
      const prof = getSensorProfile(this.state.sensorId, this.state.unlockMax);
      let clamped = false;
      this.state.stages = this.state.stages.map((s) => {
        const nx = Math.min(s.x, prof.effectiveMaxDpi);
        const ny = Math.min(s.y, prof.effectiveMaxDpi);
        if (nx !== s.x || ny !== s.y) clamped = true;
        return { ...s, x: nx, y: ny };
      });
      if (clamped || this.isConnected) {
        await this.commitDpiConfig(false);
      }
      this.renderDpiStages();
    });

    this.dom.btnAddDpiStage?.addEventListener('click', async () => {
      if (this.state.stages.length >= 6) return;
      const prof = getSensorProfile(this.state.sensorId, this.state.unlockMax);
      const last = this.state.stages[this.state.stages.length - 1]?.x || 800;
      const next = decodeDpiCode(
        this.state.sensorId,
        encodeDpiCode(this.state.sensorId, Math.min(prof.effectiveMaxDpi, last + 400), { unlockMax: this.state.unlockMax })
      );
      const idx = this.state.stages.length;
      this.state.stages.push({
        x: next,
        y: next,
        color: STAGE_COLOR_PALETTE[idx % STAGE_COLOR_PALETTE.length],
      });
      await this.commitDpiConfig(true);
      this.renderDpiStages();
    });

    this.dom.btnRemoveDpiStage?.addEventListener('click', async () => {
      if (this.state.stages.length <= 1) return;
      this.state.stages.pop();
      this.state.activeDpiStage = clamp(this.state.activeDpiStage, 0, this.state.stages.length - 1);
      await this.commitDpiConfig(false);
      this.renderDpiStages();
    });

    this.dom.pollingGroup?.addEventListener('click', async (e) => {
      const btn = e.target.closest('.poll-btn');
      if (!btn) return;
      const hz = Number(btn.dataset.hz);
      const prevHz = this.state.pollingHz;

      if (!this.state.supportedPollingRates.includes(hz)) {
        const msg = t('perf.pollingUnsupported', { max: this.state.maxPollingHz });
        this.setPollingNotice(msg, true);
        this.showToast(msg, true);
        return;
      }

      this.setPollingNotice('', false);
      this.state.pollingHz = hz;
      this.renderPolling();

      if (this.device) {
        try {
          await this.device.setPollingRate(hz);
        } catch (err) {
          this.state.pollingHz = prevHz;
          this.renderPolling();
          const msg = err.code === 'HARDWARE_REJECTED'
            ? t('perf.pollingRejected', { hz })
            : this.formatProtocolError(err);
          this.setPollingNotice(msg, true);
          this.showToast(msg, true);
          return;
        }
      } else {
        this.previewRegs = this.buildPreviewRegisters();
      }
      this.refreshInspectorIfVisible();
    });

    this.dom.lodGroup?.addEventListener('click', async (e) => {
      const btn = e.target.closest('.seg-btn');
      if (!btn) return;
      this.state.lod = Number(btn.dataset.lod);
      this.renderSensorTuning();
      await this.commitSensorTuning({ lod: this.state.lod });
    });

    this.dom.chkAngleSnap?.addEventListener('change', async (e) => {
      this.state.angleSnap = e.target.checked;
      await this.commitSensorTuning({ angleSnap: this.state.angleSnap });
    });

    this.dom.chkRipple?.addEventListener('change', async (e) => {
      this.state.ripple = e.target.checked;
      await this.commitSensorTuning({ ripple: this.state.ripple });
    });

    this.dom.chkMotionSync?.addEventListener('change', async (e) => {
      const requested = e.target.checked;
      this.state.motionSync = requested;
      await this.commitSensorTuning({ motionSync: requested });
    });

    const syncDebounceInput = (val) => {
      const ms = clamp(Math.round(Number(val) || 0), 0, 30);
      this.state.debounceMs = ms;
      this.dom.rngDebounce.value = String(ms);
      this.dom.numDebounce.value = String(ms);
      this.dom.lblDebounceVal.textContent = `${ms} ms`;
    };

    this.dom.rngDebounce?.addEventListener('input', (e) => syncDebounceInput(e.target.value));
    this.dom.rngDebounce?.addEventListener('change', async (e) => {
      syncDebounceInput(e.target.value);
      await this.commitSleepAndDebounce();
    });
    this.dom.numDebounce?.addEventListener('change', async (e) => {
      syncDebounceInput(e.target.value);
      await this.commitSleepAndDebounce();
    });

    this.dom.rngSleepTimeout?.addEventListener('input', (e) => {
      const sec = clamp(Math.round(Number(e.target.value) / 10) * 10, 10, 2550);
      this.state.sleepSec = sec;
      this.state.sleep10s = Math.round(sec / 10);
      this.dom.lblSleepTimeoutVal.textContent = formatDuration(sec);
    });
    this.dom.rngSleepTimeout?.addEventListener('change', async () => {
      await this.commitSleepAndDebounce();
    });

    this.dom.chkMoveWake?.addEventListener('change', async (e) => {
      this.state.moveWake = e.target.checked;
      await this.commitSleepAndDebounce();
    });

    this.dom.chkMoveCloseLight?.addEventListener('change', async (e) => {
      this.state.moveCloseLight = e.target.checked;
      await this.commitSleepAndDebounce();
    });

    this.dom.btnFactoryReset?.addEventListener('click', async () => {
      if (!window.confirm(t('perf.factoryResetConfirm'))) return;
      if (this.device) {
        try {
          const nextState = await this.device.restoreXmlFactoryDefaults(this.state.modelKey);
          this.applyHardwareState(nextState, true);
          this.showToast(t('toast.factoryRestored'));
        } catch (err) {
          this.showHardwareError(err);
        }
      } else {
        this.switchModelPreview(this.state.modelKey);
        this.showToast(t('toast.factoryRestored'));
      }
    });
  }

  async commitDpiConfig(writeColors = false) {
    if (this.device) {
      try {
        const nextState = await this.device.setDpiConfig({
          activeIndex: this.state.activeDpiStage,
          stages: this.state.stages,
          unlockMax: this.state.unlockMax,
          writeColors,
        });
        this.applyHardwareState(nextState, true);
      } catch (err) {
        this.showHardwareError(err);
      }
    } else {
      this.previewRegs = this.buildPreviewRegisters();
      this.refreshInspectorIfVisible();
    }
  }

  async commitSensorTuning(opts) {
    if (this.device) {
      try {
        const res = await this.device.setSensorSettings(opts);
        this.state.lod = res.lod;
        this.state.angleSnap = res.angleSnap;
        this.state.ripple = res.ripple;
        this.state.motionSync = res.motionSync;
        this.state.motionSyncLocked = res.motionSyncLocked;
        this.renderSensorTuning();
      } catch (err) {
        this.showHardwareError(err);
      }
    } else {
      this.previewRegs = this.buildPreviewRegisters();
    }
    this.refreshInspectorIfVisible();
  }

  async commitSleepAndDebounce() {
    if (this.device) {
      try {
        await this.device.setSleepAndDebounce({
          sleep10s: this.state.sleep10s,
          moveWake: this.state.moveWake,
          moveCloseLight: this.state.moveCloseLight,
          debounceMs: this.state.debounceMs,
        });
      } catch (err) {
        this.showHardwareError(err);
      }
    } else {
      this.previewRegs = this.buildPreviewRegisters();
    }
    this.refreshInspectorIfVisible();
  }

  bindButtonsEvents() {
    this.dom.btnReloadButtonsFromDevice?.addEventListener('click', async () => {
      if (this.device) {
        try {
          const nextState = await this.device.syncAll({ includeDongle: this.state.isWireless });
          this.applyHardwareState(nextState, true);
        } catch (err) {
          this.showHardwareError(err);
        }
      } else {
        this.renderButtonsTab();
      }
    });

    this.dom.btnResetButtonDefault?.addEventListener('click', async () => {
      const slot = this.selectedButtonSlot;
      const profile = getModelByKey(this.state.modelKey);
      const def = profile.factoryDefaults.buttons[slot] || { type: 'disabled' };
      const spec = { slot, ...def };
      this.state.buttons[slot] = spec;
      this.populateButtonEditor(spec);
      this.renderSchematic();
      await this.writeButtonSlot(slot, spec);
    });

    this.dom.selActionCategory?.addEventListener('change', () => {
      this.showButtonCategorySubpanel();
    });

    const syncFireInterval = (val) => {
      const ms = clamp(Math.round(Number(val) || 50), 5, 255);
      this.dom.rngFireInterval.value = String(ms);
      this.dom.numFireInterval.value = String(ms);
      this.dom.lblFireIntervalVal.textContent = `${ms} ms`;
    };
    this.dom.rngFireInterval?.addEventListener('input', (e) => syncFireInterval(e.target.value));
    this.dom.numFireInterval?.addEventListener('input', (e) => syncFireInterval(e.target.value));

    this.dom.selMacroLoop?.addEventListener('change', (e) => {
      this.dom.wrapMacroLoopCount?.classList.toggle('hidden', e.target.value !== 'count');
    });

    // Keyboard shortcut capture
    this.dom.keyCaptureBox?.addEventListener('keydown', (e) => {
      e.preventDefault();
      e.stopPropagation();

      const resolved = resolveKeySpec({ code: e.code, keyCode: e.keyCode });
      if (resolved.isModifier && resolved.modMask) {
        this.pendingKey.modifiers |= resolved.modMask;
      } else if (resolved.hid) {
        let evMods = 0;
        if (e.ctrlKey) evMods |= 0x01;
        if (e.shiftKey) evMods |= 0x02;
        if (e.altKey) evMods |= 0x04;
        if (e.metaKey) evMods |= 0x08;
        if (evMods > 0) {
          this.pendingKey.modifiers = evMods;
        }
        this.pendingKey.hid = resolved.hid;
        this.pendingKey.code = resolved.code;
      }
      this.syncKeyboardCaptureDisplay();
    });

    [
      [this.dom.chkModCtrl, 0x01],
      [this.dom.chkModShift, 0x02],
      [this.dom.chkModAlt, 0x04],
      [this.dom.chkModWin, 0x08],
    ].forEach(([chk, bit]) => {
      chk?.addEventListener('change', () => {
        if (chk.checked) this.pendingKey.modifiers |= bit;
        else this.pendingKey.modifiers &= ~(bit | (bit << 4));
        this.syncKeyboardCaptureDisplay();
      });
    });

    this.dom.btnClearChord?.addEventListener('click', () => {
      this.pendingKey = { modifiers: 0, hid: 0, code: null };
      this.syncKeyboardCaptureDisplay();
    });

    this.dom.btnApplyButton?.addEventListener('click', async () => {
      const slot = this.selectedButtonSlot;
      const spec = this.readButtonEditorSpec(slot);
      this.state.buttons[slot] = spec;
      this.renderSchematic();
      await this.writeButtonSlot(slot, spec);
    });
  }

  async writeButtonSlot(slot, spec) {
    if (this.device) {
      try {
        await this.device.setButtonAction(slot, spec);
        this.showToast(t('toast.buttonApplied', { id: slot }));
      } catch (err) {
        this.showHardwareError(err);
        return;
      }
    } else {
      this.previewRegs = this.buildPreviewRegisters();
      this.showToast(t('toast.buttonApplied', { id: slot }));
    }
    this.refreshInspectorIfVisible();
  }

  bindLightingEvents() {
    this.dom.lightingModeGroup?.addEventListener('click', (e) => {
      const btn = e.target.closest('.seg-btn');
      if (!btn) return;
      this.state.lighting.mode = Number(btn.dataset.lmode);
      this.renderLightingTab();
    });

    this.dom.rngLightBri?.addEventListener('input', (e) => {
      this.state.lighting.brightness = clamp(Number(e.target.value), 0, 5);
      this.dom.lblLightBri.textContent = String(this.state.lighting.brightness);
    });

    this.dom.rngLightSpd?.addEventListener('input', (e) => {
      this.state.lighting.speed = clamp(Number(e.target.value), 0, 5);
      this.dom.lblLightSpd.textContent = String(this.state.lighting.speed);
    });

    this.dom.lightDirGroup?.addEventListener('click', (e) => {
      const btn = e.target.closest('.seg-btn');
      if (!btn) return;
      this.state.lighting.direction = Number(btn.dataset.ldir);
      this.renderLightingTab();
    });

    this.dom.inpLightColor?.addEventListener('input', (e) => {
      const hex = e.target.value.toUpperCase();
      this.state.lighting.color = hex;
      this.dom.lblLightColorHex.textContent = hex;
    });

    this.dom.btnApplyLighting?.addEventListener('click', async () => {
      if (this.device) {
        try {
          const updated = await this.device.setLighting(this.state.lighting);
          this.state.lighting = updated;
          this.renderLightingTab();
        } catch (err) {
          this.showHardwareError(err);
          return;
        }
      } else {
        this.previewRegs = this.buildPreviewRegisters();
      }
      this.refreshInspectorIfVisible();
    });
  }

  bindMacroEvents() {
    this.dom.inpMacroName?.addEventListener('input', (e) => {
      const m = this.state.macros[this.activeMacroSlot];
      m.name = e.target.value;
      this.renderMacroSlots();
    });

    this.dom.selMacroStudioLoop?.addEventListener('change', (e) => {
      this.state.macros[this.activeMacroSlot].loopMode = e.target.value;
    });

    this.dom.btnRecordMacro?.addEventListener('click', () => {
      if (this.isRecordingMacro) this.stopMacroRecording();
      else this.startMacroRecording();
    });

    this.dom.btnClearMacro?.addEventListener('click', () => {
      if (this.isRecordingMacro) this.stopMacroRecording();
      const m = this.state.macros[this.activeMacroSlot];
      m.events = [];
      this.renderMacroSlots();
      this.renderMacroTimeline();
    });

    this.dom.btnSaveMacro?.addEventListener('click', async () => {
      if (this.isRecordingMacro) this.stopMacroRecording();
      const slot = this.activeMacroSlot;
      const m = this.state.macros[slot];
      const hwEvents = m.events.filter((ev) => ev.type !== 'delay');
      if (hwEvents.length === 0) {
        this.showToast(t('macros.emptyState'), true);
        return;
      }

      const currentButton = this.state.buttons[slot];
      const bindOptions = currentButton?.type === 'macro'
        ? { bindButton: true, loopMode: m.loopMode || 'toggle', loopCount: m.loopCount || 1 }
        : null;

      if (this.device) {
        try {
          await this.device.writeMacro(slot, m.events, bindOptions);
          this.showToast(t('toast.macroSaved', { count: hwEvents.length }));
        } catch (err) {
          this.showHardwareError(err);
          return;
        }
      } else {
        try {
          frameMacroChunks(slot, m.events);
          this.showToast(t('toast.macroSaved', { count: hwEvents.length }));
        } catch (err) {
          this.showToast(err.message, true);
        }
      }
      this.renderMacroSlots();
    });

    this.dom.btnExportMacro?.addEventListener('click', () => {
      const m = this.state.macros[this.activeMacroSlot];
      this.downloadJson(
        {
          schema: 'valkyrie-macro-v1',
          slot: m.slot,
          name: this.getMacroDisplayName(m.slot),
          loopMode: m.loopMode,
          events: m.events,
        },
        `valkyrie-macro-slot-${m.slot}.json`
      );
    });

    this.dom.btnImportMacro?.addEventListener('click', () => this.dom.inpImportMacro?.click());
    this.dom.inpImportMacro?.addEventListener('change', async (e) => {
      const file = e.target.files?.[0];
      e.target.value = '';
      if (!file) return;
      try {
        const parsed = JSON.parse(await file.text());
        if (!Array.isArray(parsed.events)) {
          throw new Error(t('errors.missingEventsArray'));
        }
        const slot = this.activeMacroSlot;
        this.state.macros[slot] = {
          slot,
          name: parsed.name ? String(parsed.name).slice(0, 30) : '',
          loopMode: parsed.loopMode || 'toggle',
          loopCount: Number(parsed.loopCount) || 1,
          events: parsed.events.map((ev) => ({ ...ev })),
        };
        this.renderMacroTab();
      } catch (err) {
        this.showToast(this.formatProtocolError(err), true);
      }
    });

    this.dom.btnInsertKey?.addEventListener('click', () => {
      this.appendMacroSteps([
        { type: 'keyDown', code: 'KeyA' },
        { type: 'delay', delayMs: 25 },
        { type: 'keyUp', code: 'KeyA' },
      ]);
    });

    this.dom.btnInsertMouse?.addEventListener('click', () => {
      this.appendMacroSteps([
        { type: 'mouseDown', button: 1 },
        { type: 'delay', delayMs: 25 },
        { type: 'mouseUp', button: 1 },
      ]);
    });

    this.dom.btnInsertDelay?.addEventListener('click', () => {
      this.appendMacroSteps([{ type: 'delay', delayMs: 50 }]);
    });
  }

  bindInspectorEvents() {
    this.dom.btnRefreshDump?.addEventListener('click', async () => {
      if (this.device) {
        try {
          await this.device.dumpAllRegisters();
        } catch (err) {
          this.showHardwareError(err);
        }
      } else {
        this.previewRegs = this.buildPreviewRegisters();
      }
      this.renderInspectorTab();
    });

    this.dom.btnExportSnapshot?.addEventListener('click', async () => {
      let snapshot;
      if (this.device) {
        try {
          snapshot = await this.device.exportSnapshot({ refresh: true });
        } catch (err) {
          this.showHardwareError(err);
          return;
        }
      } else {
        snapshot = {
          schema: 'valkyrie-snapshot-v1',
          timestamp: new Date().toISOString(),
          device: {
            vid: this.state.vendorId,
            pid: this.state.productId,
            devId: this.state.devId,
            fwVersion: this.state.fwVersion,
            isWireless: this.state.isWireless,
          },
          regs: this.getActiveRawRegisters(),
        };
      }
      this.downloadJson(snapshot, `valkyrie-snapshot-${(this.state.devId || 'm220').toLowerCase()}.json`);
      this.showToast(t('toast.snapshotExported'));
      this.renderInspectorTab();
    });

    this.dom.btnImportBaseline?.addEventListener('click', () => this.dom.inpImportBaseline?.click());
    this.dom.inpImportBaseline?.addEventListener('change', async (e) => {
      const file = e.target.files?.[0];
      e.target.value = '';
      if (!file) return;
      try {
        const parsed = JSON.parse(await file.text());
        const regsMap = normalizeRegisterMap(parsed);
        const keys = Object.keys(regsMap);
        if (keys.length === 0) {
          throw new Error('No register entries found');
        }
        const hexRegs = {};
        for (const [k, v] of Object.entries(regsMap)) {
          hexRegs[k] = formatHex(v);
        }
        this.baselineCustomName = file.name;
        this.baselineSnapshot = {
          device: parsed.device || null,
          regs: hexRegs,
        };
        this.dom.lblBaselineMeta.textContent = file.name;
        this.renderDiffGrid();
      } catch (err) {
        this.showToast(err.message, true);
      }
    });

    this.dom.btnSafeRollback?.addEventListener('click', async () => {
      if (this.device) {
        try {
          const res = await this.device.safeRollback(this.baselineSnapshot);
          this.applyHardwareState(res.state, true);
          this.showToast(t('toast.rollbackDone'));
        } catch (err) {
          this.showHardwareError(err);
        }
      } else {
        this.applyBaselineToPreview(this.baselineSnapshot);
        this.renderAll();
        this.showToast(t('toast.rollbackDone'));
      }
    });

    this.dom.btnRawSend?.addEventListener('click', () => this.runAllowlistedRawCommand());

    this.dom.btnClearConsole?.addEventListener('click', () => {
      if (this.device) this.device.clearTrace();
      this.dom.packetLog.innerHTML = '';
    });

    this.dom.btnExportConsole?.addEventListener('click', () => {
      const lines = Array.from(this.dom.packetLog.querySelectorAll('.log-entry'))
        .map((el) => el.textContent)
        .join('\n');
      const blob = new Blob([lines], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'valkyrie-hid-trace.log';
      a.click();
      URL.revokeObjectURL(url);
    });
  }

  applyBaselineToPreview(snapshot) {
    const regs = normalizeRegisterMap(snapshot);
    if (regs['0x12']) this.state.pollingHz = decodePollingPacket(regs['0x12']).pollingHz;
    if (regs['0x13']) {
      const dpi = decodeDpiPacket(regs['0x13'], this.state.sensorId);
      const colors = regs['0x14'] ? decodeDpiColorsPacket(regs['0x14']) : [];
      this.state.activeDpiStage = dpi.activeStage;
      this.state.stages = dpi.stages.map((s, idx) => ({
        x: s.x,
        y: s.y,
        color: colors[idx] || this.state.stages[idx]?.color || '#2563EB',
      }));
      this.state.lockDpiXY = this.state.stages.every((s) => s.x === s.y);
    }
    if (regs['0x15']) this.state.lighting = decodeLightingPacket(regs['0x15']);
    if (regs['0x16']) {
      const sensor = decodeSensorPacket(regs['0x16']);
      this.state.lod = sensor.lod;
      this.state.angleSnap = sensor.angleSnap;
      this.state.ripple = sensor.ripple;
      this.state.motionSync = sensor.motionSync;
    }
    if (regs['0x17']) {
      const sl = decodeSleepPacket(regs['0x17']);
      this.state.sleep10s = sl.sleep10s;
      this.state.sleepSec = sl.sleepSec;
      this.state.moveWake = sl.moveWake;
      this.state.moveCloseLight = sl.moveCloseLight;
      this.state.debounceMs = sl.debounceMs;
    }
    if (regs['0x11']) {
      this.state.buttons = decodeButtonsPacket(regs['0x11']);
    }
    this.previewRegs = this.buildPreviewRegisters();
  }

  switchTab(tabId) {
    this.activeTab = tabId;
    this.dom.navItems.forEach((item) => item.classList.toggle('active', item.dataset.tab === tabId));
    this.dom.tabPanels.forEach((panel) => panel.classList.toggle('active', panel.id === `tab-${tabId}`));
    if (tabId === 'buttons') {
      requestAnimationFrame(() => this.drawSchematicLeaders());
    }
    if (tabId === 'inspector') {
      this.renderInspectorTab();
    }
    if (tabId === 'firmware') {
      this.renderFirmwareTab();
    }
  }

  refreshInspectorIfVisible() {
    if (this.activeTab === 'inspector') {
      this.renderInspectorTab();
    }
  }

  // === Full Rendering ===

  renderAll() {
    this.updateSidebarFooter();
    this.updateTopbarTelemetry();
    this.renderBanners();
    this.renderHelperConnectButtons();
    this.renderPerformanceTab();
    this.renderButtonsTab();
    this.renderLightingTab();
    this.renderMacroTab();
    this.renderInspectorTab();
    this.renderFirmwareTab();
  }

  updateSidebarFooter() {
    if (this.dom.sidebarDevId) this.dom.sidebarDevId.textContent = this.state.devId || 'M220';
    if (this.dom.sidebarFwVersion) {
      this.dom.sidebarFwVersion.textContent = this.isConnected ? (this.state.fwVersion || '—') : '—';
    }
    if (this.dom.sidebarSensor) {
      this.dom.sidebarSensor.textContent = this.state.sensorName || 'PAW3395';
    }
  }

  updateTopbarTelemetry() {
    if (this.dom.batteryPercent) {
      this.dom.batteryPercent.textContent = `${this.state.batteryPct}%`;
    }
    this.dom.batteryChargingIcon?.classList.toggle('hidden', !this.state.charging);
    if (this.isConnected) {
      this.dom.btnConnect.textContent = t('topbar.disconnect');
      this.dom.statusText.textContent = this.getConnectedStatusText();
    } else {
      this.dom.btnConnect.textContent = t('topbar.connect');
      this.dom.statusText.textContent = this.hidManager.isSupported()
        ? t('topbar.statusNotConnected')
        : t('topbar.statusUnavailable');
    }
  }

  // === Tab 1: Performance ===

  renderPerformanceTab() {
    this.renderDpiStages();
    this.renderPolling();
    this.renderSensorTuning();
    this.renderPowerAndDebounce();
  }

  renderDpiStages() {
    const prof = getSensorProfile(this.state.sensorId, this.state.unlockMax);
    const minDpi = prof.minDpi;
    const maxDpi = prof.effectiveMaxDpi;
    const activeNum = this.state.activeDpiStage + 1;

    this.dom.lblActiveStage.textContent = t('perf.activeStage', { n: activeNum });
    this.dom.chkLockDpiXY.checked = Boolean(this.state.lockDpiXY);
    this.dom.chkUnlock26k.checked = Boolean(this.state.unlockMax);
    this.dom.wrapUnlock26k?.classList.toggle('hidden', this.state.sensorId !== 0x11);

    this.dom.btnAddDpiStage.disabled = this.state.stages.length >= 6;
    this.dom.btnRemoveDpiStage.disabled = this.state.stages.length <= 1;

    this.dom.dpiStagesList.innerHTML = '';
    this.state.stages.forEach((stage, idx) => {
      const stageNum = idx + 1;
      const isActive = idx === this.state.activeDpiStage;
      const stageColor = stage.color || STAGE_COLOR_PALETTE[idx % STAGE_COLOR_PALETTE.length];

      const row = document.createElement('div');
      row.className = `dpi-stage-row${isActive ? ' active' : ''}`;

      const selBtn = document.createElement('button');
      selBtn.type = 'button';
      selBtn.className = 'dpi-stage-select';
      const dot = document.createElement('span');
      dot.className = 'dpi-stage-dot';
      const lbl = document.createElement('span');
      lbl.className = 'mono-num';
      lbl.textContent = t('perf.stageLabel', { n: stageNum });
      selBtn.append(dot, lbl);
      selBtn.addEventListener('click', async () => {
        this.state.activeDpiStage = idx;
        this.renderDpiStages();
        await this.commitDpiConfig(false);
      });

      const axesWrap = document.createElement('div');
      axesWrap.className = 'dpi-axes-stack';

      const buildAxisRow = (axisTag, prop) => {
        const line = document.createElement('div');
        line.className = 'dpi-axis-row';

        const tag = document.createElement('span');
        tag.className = 'axis-tag';
        tag.textContent = axisTag;

        const range = document.createElement('input');
        range.type = 'range';
        range.className = 'range-input';
        range.min = String(minDpi);
        range.max = String(maxDpi);
        range.step = String(prof.step || 50);
        range.value = String(stage[prop]);

        const num = document.createElement('input');
        num.type = 'number';
        num.className = 'num-input mono-num';
        num.min = String(minDpi);
        num.max = String(maxDpi);
        num.step = String(prof.step || 50);
        num.value = String(stage[prop]);

        const computeHardwareDpi = (raw) => {
          const clamped = clamp(Number(raw) || minDpi, minDpi, maxDpi);
          return decodeDpiCode(
            this.state.sensorId,
            encodeDpiCode(this.state.sensorId, clamped, { unlockMax: this.state.unlockMax })
          );
        };

        range.addEventListener('input', (e) => {
          const next = computeHardwareDpi(e.target.value);
          stage[prop] = next;
          if (this.state.lockDpiXY) {
            stage.x = next;
            stage.y = next;
          }
          num.value = String(next);
        });
        range.addEventListener('change', async (e) => {
          const next = computeHardwareDpi(e.target.value);
          stage[prop] = next;
          if (this.state.lockDpiXY) {
            stage.x = next;
            stage.y = next;
          }
          range.value = String(next);
          num.value = String(next);
          await this.commitDpiConfig(false);
        });
        num.addEventListener('change', async (e) => {
          const next = computeHardwareDpi(e.target.value);
          stage[prop] = next;
          if (this.state.lockDpiXY) {
            stage.x = next;
            stage.y = next;
          }
          range.value = String(next);
          num.value = String(next);
          await this.commitDpiConfig(false);
        });

        line.append(tag, range, num);
        return line;
      };

      axesWrap.appendChild(buildAxisRow(this.state.lockDpiXY ? 'XY' : 'X', 'x'));
      if (!this.state.lockDpiXY) {
        axesWrap.appendChild(buildAxisRow('Y', 'y'));
      }

      const colorWrap = document.createElement('div');
      colorWrap.className = 'color-pair';
      const colorInput = document.createElement('input');
      colorInput.type = 'color';
      colorInput.className = 'color-swatch-input';
      colorInput.value = stageColor;
      colorInput.title = t('perf.stageColorTitle', { n: stageNum });
      colorInput.addEventListener('change', async (e) => {
        stage.color = e.target.value.toUpperCase();
        if (this.device) {
          try {
            await this.device.setDpiColors(this.state.stages.map((s) => s.color));
          } catch (err) {
            this.showToast(t('toast.hardwareWriteFailed', { msg: this.formatProtocolError(err) }), true);
          }
        } else {
          this.previewRegs = this.buildPreviewRegisters();
          this.refreshInspectorIfVisible();
        }
      });
      colorWrap.appendChild(colorInput);

      row.append(selBtn, axesWrap, colorWrap);
      this.dom.dpiStagesList.appendChild(row);
    });
  }

  renderPolling() {
    this.dom.lblPollingCap.textContent = t('perf.pollingUnsupported', { max: this.state.maxPollingHz });
    const supported = new Set(this.state.supportedPollingRates || [125, 250, 500, 1000]);

    this.dom.pollingGroup?.querySelectorAll('.poll-btn').forEach((btn) => {
      const hz = Number(btn.dataset.hz);
      const isSupported = supported.has(hz);
      btn.classList.toggle('gated', !isSupported);
      btn.classList.toggle('active', hz === this.state.pollingHz);
      btn.title = isSupported ? `${hz} Hz` : t('perf.pollingUnsupported', { max: this.state.maxPollingHz });
      btn.setAttribute('aria-disabled', String(!isSupported));
    });
  }

  setPollingNotice(message, isWarn) {
    if (!this.dom.pollingNotice) return;
    this.dom.pollingNotice.textContent = message;
    this.dom.pollingNotice.classList.toggle('hidden', !message);
    this.dom.pollingNotice.classList.toggle('hint-warn', Boolean(isWarn));
  }

  renderSensorTuning() {
    this.dom.lodGroup?.querySelectorAll('.seg-btn').forEach((btn) => {
      btn.classList.toggle('active', Number(btn.dataset.lod) === this.state.lod);
    });
    this.dom.chkAngleSnap.checked = Boolean(this.state.angleSnap);
    this.dom.chkRipple.checked = Boolean(this.state.ripple);
    this.dom.chkMotionSync.checked = Boolean(this.state.motionSync);

    const locked = Boolean(this.state.motionSyncLocked);
    this.dom.chkMotionSync.disabled = locked;
    this.dom.rowMotionSync?.classList.toggle('is-readonly', locked);
    this.dom.badgeMotionSyncLocked?.classList.toggle('hidden', !locked);
  }

  renderPowerAndDebounce() {
    const ms = clamp(this.state.debounceMs ?? 8, 0, 30);
    this.dom.rngDebounce.value = String(ms);
    this.dom.numDebounce.value = String(ms);
    this.dom.lblDebounceVal.textContent = `${ms} ms`;

    const sec = clamp(this.state.sleepSec ?? 60, 10, 2550);
    this.dom.rngSleepTimeout.value = String(sec);
    this.dom.lblSleepTimeoutVal.textContent = formatDuration(sec);

    this.dom.chkMoveWake.checked = Boolean(this.state.moveWake);
    this.dom.chkMoveCloseLight.checked = Boolean(this.state.moveCloseLight);
  }

  // === Tab 2: Buttons ===

  renderButtonsTab() {
    if (this.dom.selMacroSlot) {
      Array.from(this.dom.selMacroSlot.options).forEach((opt) => {
        opt.textContent = this.getMacroDisplayName(Number(opt.value));
      });
    }
    this.renderSchematic();
    this.populateButtonEditor(this.state.buttons[this.selectedButtonSlot]);
  }

  formatButtonSummary(spec) {
    if (!spec || spec.type === 'disabled') return t('buttons.sumDisabled');
    switch (spec.type) {
      case 'mouse': {
        if (spec.action === 'double_click') return t('buttons.sumDoubleClick');
        if (spec.action === 'scroll_up') return t('buttons.sumScrollUp');
        if (spec.action === 'scroll_down') return t('buttons.sumScrollDown');
        if (spec.action === 'scroll_left') return t('buttons.sumTiltLeft');
        if (spec.action === 'scroll_right') return t('buttons.sumTiltRight');
        const btnNum = clamp(Number(spec.button) || 1, 1, 5);
        return t(`buttons.mouse${btnNum}`);
      }
      case 'keyboard': {
        const parts = [];
        const m = Number(spec.modifiers) || 0;
        if (m & 0x11) parts.push('Ctrl');
        if (m & 0x22) parts.push('Shift');
        if (m & 0x44) parts.push('Alt');
        if (m & 0x88) parts.push('Win');
        if (spec.code) {
          parts.push(spec.code.replace(/^Key/, '').replace(/^Digit/, ''));
        } else if (spec.hid) {
          parts.push(HID_TO_CODE[spec.hid] || formatCmdHex(spec.hid));
        }
        return parts.length > 0 ? parts.join(' + ') : t('buttons.sumUnassigned');
      }
      case 'media': {
        const key = spec.keyName && MEDIA_KEY_LIST.includes(spec.keyName)
          ? `media.${spec.keyName}`
          : null;
        return key ? t(key) : (spec.keyName || t('buttons.catMedia'));
      }
      case 'fire':
        return `${spec.repeatCount ?? 3}x · ${spec.interval ?? 50} ms`;
      case 'macro': {
        const slot = spec.slotIndex ?? spec.macroId ?? 0;
        return this.getMacroDisplayName(slot);
      }
      case 'dpi': {
        if (spec.mode === 'up') return t('buttons.dpiUp');
        if (spec.mode === 'down') return t('buttons.dpiDown');
        return t('buttons.dpiCycle');
      }
      case 'reportRate':
        return t('buttons.sumPollingStep', { step: spec.step || 1 });
      default:
        return t('buttons.sumUnassigned');
    }
  }

  renderSchematic() {
    const profile = getModelByKey(this.state.modelKey);
    this.dom.schematicModelName.textContent = profile.name;
    this.dom.schematicSubtitle.textContent = t('buttons.schematicSub', {
      count: profile.buttons.length,
      sensor: this.state.sensorName || profile.sensorName,
    });
    if (this.isConnected) {
      const pidHex = (this.state.productId || 0x5D2E).toString(16).toUpperCase().padStart(4, '0');
      this.dom.schematicHardwareBadge.textContent = t('buttons.syncedBadge', { pid: pidHex });
    } else {
      this.dom.schematicHardwareBadge.textContent = t('buttons.offlinePreview');
    }

    if (this.dom.mouseRenderImg.getAttribute('src') !== profile.image) {
      this.dom.mouseRenderImg.src = profile.image;
    }

    this.dom.schematicPins.innerHTML = '';
    this.dom.schematicCallouts.innerHTML = '';
    this.dom.buttonSlotGrid.innerHTML = '';

    const leftSlots = profile.buttons
      .filter((b) => b.calloutSide === 'left')
      .sort((a, b) => a.pinY - b.pinY);
    const rightSlots = profile.buttons
      .filter((b) => b.calloutSide !== 'left')
      .sort((a, b) => a.pinY - b.pinY);

    const calloutPositions = new Map();
    leftSlots.forEach((b, idx) => {
      calloutPositions.set(b.id, { side: 'left', topPct: 18 + idx * 28 });
    });
    rightSlots.forEach((b, idx) => {
      calloutPositions.set(b.id, { side: 'right', topPct: 18 + idx * 28 });
    });

    profile.buttons.forEach((btnDef) => {
      const isSelected = btnDef.id === this.selectedButtonSlot;
      const spec = this.state.buttons[btnDef.id];
      const summary = this.formatButtonSummary(spec);
      const slotLabel = t(`buttons.btn${btnDef.id}`);

      // Numbered pin on aspect-locked mouse image
      const pin = document.createElement('button');
      pin.type = 'button';
      pin.className = `pin-hotspot${btnDef.dashed ? ' dashed' : ''}${isSelected ? ' active' : ''}`;
      pin.style.left = `${btnDef.pinX}%`;
      pin.style.top = `${btnDef.pinY}%`;
      pin.dataset.slotId = String(btnDef.id);
      pin.title = `${slotLabel}: ${summary}`;
      pin.textContent = String(btnDef.id);
      pin.addEventListener('click', () => this.selectButtonSlot(btnDef.id));
      this.dom.schematicPins.appendChild(pin);

      // Edge-aligned callout card inside schematic viewport
      const pos = calloutPositions.get(btnDef.id);
      const callout = document.createElement('button');
      callout.type = 'button';
      callout.className = `pin-callout-badge${btnDef.dashed ? ' dashed' : ''}${isSelected ? ' active' : ''}`;
      callout.dataset.slotId = String(btnDef.id);
      callout.dataset.side = pos.side;
      callout.style.top = `${pos.topPct}%`;
      if (pos.side === 'left') {
        callout.style.left = '12px';
      } else {
        callout.style.right = '12px';
      }

      const cTitle = document.createElement('span');
      cTitle.className = 'callout-title';
      cTitle.textContent = `${btnDef.id} · ${slotLabel}`;
      const cAction = document.createElement('span');
      cAction.className = 'callout-action';
      cAction.textContent = summary;
      callout.append(cTitle, cAction);
      callout.addEventListener('click', () => this.selectButtonSlot(btnDef.id));
      this.dom.schematicCallouts.appendChild(callout);

      // Clickable slot summary card below schematic
      const card = document.createElement('button');
      card.type = 'button';
      card.className = `slot-summary-card${btnDef.dashed ? ' dashed' : ''}${isSelected ? ' active' : ''}`;
      const left = document.createElement('span');
      left.className = 'slot-card-left';
      const idxBadge = document.createElement('span');
      idxBadge.className = 'slot-index-tag';
      idxBadge.textContent = String(btnDef.id);
      const nameEl = document.createElement('span');
      nameEl.className = 'slot-card-name';
      nameEl.textContent = slotLabel;
      left.append(idxBadge, nameEl);

      const actEl = document.createElement('span');
      actEl.className = 'slot-card-action';
      actEl.textContent = summary;
      card.append(left, actEl);
      card.addEventListener('click', () => this.selectButtonSlot(btnDef.id));
      this.dom.buttonSlotGrid.appendChild(card);
    });

    requestAnimationFrame(() => this.drawSchematicLeaders());
  }

  drawSchematicLeaders() {
    const canvas = this.dom.schematicCanvas;
    const svg = this.dom.schematicOverlay;
    if (!canvas || !svg) return;

    const canvasRect = canvas.getBoundingClientRect();
    if (canvasRect.width <= 0 || canvasRect.height <= 0) return;

    svg.setAttribute('viewBox', `0 0 ${canvasRect.width} ${canvasRect.height}`);
    svg.innerHTML = '';

    const profile = getModelByKey(this.state.modelKey);
    profile.buttons.forEach((btnDef) => {
      const pin = this.dom.schematicPins.querySelector(`[data-slot-id="${btnDef.id}"]`);
      const callout = this.dom.schematicCallouts.querySelector(`[data-slot-id="${btnDef.id}"]`);
      if (!pin || !callout) return;

      const calloutStyle = window.getComputedStyle(callout);
      if (calloutStyle.display === 'none') return;

      const pRect = pin.getBoundingClientRect();
      const cRect = callout.getBoundingClientRect();
      const px = pRect.left + pRect.width / 2 - canvasRect.left;
      const py = pRect.top + pRect.height / 2 - canvasRect.top;
      const side = callout.dataset.side;
      const cx = side === 'left'
        ? (cRect.right - canvasRect.left)
        : (cRect.left - canvasRect.left);
      const cy = cRect.top + cRect.height / 2 - canvasRect.top;
      const elbowX = side === 'left'
        ? cx + Math.max(12, (px - cx) * 0.4)
        : cx - Math.max(12, (cx - px) * 0.4);

      const poly = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
      poly.setAttribute('points', `${cx.toFixed(1)},${cy.toFixed(1)} ${elbowX.toFixed(1)},${cy.toFixed(1)} ${px.toFixed(1)},${py.toFixed(1)}`);
      const isSelected = btnDef.id === this.selectedButtonSlot;
      poly.setAttribute(
        'class',
        `schematic-leader${btnDef.dashed ? ' dashed' : ''}${isSelected ? ' active' : ''}`
      );
      svg.appendChild(poly);
    });
  }

  selectButtonSlot(slotId) {
    this.selectedButtonSlot = clamp(slotId, 0, 5);
    this.renderSchematic();
    this.populateButtonEditor(this.state.buttons[this.selectedButtonSlot]);
  }

  populateButtonEditor(spec) {
    const slot = this.selectedButtonSlot;
    this.dom.selectedButtonName.textContent = t(`buttons.btn${slot}`);
    this.dom.selectedButtonSlotBadge.textContent = t('buttons.slotBadge', { id: slot });

    const s = spec || { type: 'disabled' };
    const category = ['mouse', 'keyboard', 'media', 'fire', 'macro', 'dpi', 'disabled'].includes(s.type)
      ? s.type
      : 'mouse';
    this.dom.selActionCategory.value = category;

    if (category === 'mouse') {
      this.dom.selMouseAction.value = String(clamp(Number(s.button) || 1, 1, 5));
    }

    if (category === 'keyboard') {
      this.pendingKey = {
        modifiers: Number(s.modifiers) || 0,
        hid: Number(s.hid) || 0,
        code: s.code || (s.hid ? HID_TO_CODE[s.hid] : null),
      };
    } else {
      this.pendingKey = { modifiers: 0, hid: 0, code: null };
    }
    this.syncKeyboardCaptureDisplay();

    if (category === 'media') {
      this.dom.selMediaAction.value = MEDIA_KEY_LIST.includes(s.keyName) ? s.keyName : 'play_pause';
    }

    if (category === 'fire') {
      const iv = clamp(Number(s.interval) || 50, 5, 255);
      const rawRep = s.repeatCount === undefined || s.repeatCount === null ? 3 : Number(s.repeatCount);
      const rep = clamp(Number.isFinite(rawRep) ? rawRep : 3, 0, 255);
      this.dom.rngFireInterval.value = String(iv);
      this.dom.numFireInterval.value = String(iv);
      this.dom.lblFireIntervalVal.textContent = `${iv} ms`;
      this.dom.numFireCount.value = String(rep);
    }

    if (category === 'macro') {
      const targetSlot = clamp(Number(s.slotIndex ?? s.macroId ?? 0), 0, 5);
      this.dom.selMacroSlot.value = String(targetSlot);
      const lm = s.loopMode === 'hold' ? 'hold' : (s.loopMode === 'count' ? 'count' : 'toggle');
      this.dom.selMacroLoop.value = lm;
      this.dom.numMacroLoopCount.value = String(clamp(Number(s.loopCount) || 1, 1, 255));
      this.dom.wrapMacroLoopCount?.classList.toggle('hidden', lm !== 'count');
    }

    if (category === 'dpi') {
      this.dom.selDpiAction.value = ['cycle', 'up', 'down'].includes(s.mode) ? s.mode : 'cycle';
    }

    this.showButtonCategorySubpanel();
  }

  syncKeyboardCaptureDisplay() {
    const m = this.pendingKey.modifiers || 0;
    this.dom.chkModCtrl.checked = Boolean(m & 0x11);
    this.dom.chkModShift.checked = Boolean(m & 0x22);
    this.dom.chkModAlt.checked = Boolean(m & 0x44);
    this.dom.chkModWin.checked = Boolean(m & 0x88);

    const summary = this.formatButtonSummary({
      type: 'keyboard',
      modifiers: m,
      hid: this.pendingKey.hid,
      code: this.pendingKey.code,
    });
    if (m === 0 && !this.pendingKey.hid && !this.pendingKey.code) {
      this.dom.keyCaptureDisplay.textContent = t('buttons.capturePlaceholder');
    } else {
      this.dom.keyCaptureDisplay.textContent = summary;
    }
  }

  showButtonCategorySubpanel() {
    const cat = this.dom.selActionCategory.value;
    const map = {
      mouse: this.dom.panelActionMouse,
      keyboard: this.dom.panelActionKeyboard,
      media: this.dom.panelActionMedia,
      fire: this.dom.panelActionFire,
      macro: this.dom.panelActionMacro,
      dpi: this.dom.panelActionDpi,
      disabled: this.dom.panelActionDisabled,
    };
    Object.values(map).forEach((el) => el?.classList.add('hidden'));
    map[cat]?.classList.remove('hidden');
    if (cat === 'macro') {
      this.dom.wrapMacroLoopCount?.classList.toggle('hidden', this.dom.selMacroLoop.value !== 'count');
    }
  }

  readButtonEditorSpec(slot) {
    const cat = this.dom.selActionCategory.value;
    switch (cat) {
      case 'mouse':
        return { slot, type: 'mouse', button: clamp(Number(this.dom.selMouseAction.value) || 1, 1, 5) };
      case 'keyboard':
        return {
          slot,
          type: 'keyboard',
          modifiers: this.pendingKey.modifiers & 0xFF,
          hid: this.pendingKey.hid & 0xFF,
          code: this.pendingKey.code,
        };
      case 'media': {
        const keyName = this.dom.selMediaAction.value;
        return { slot, type: 'media', keyName, usage: MEDIA_KEYS[keyName] ?? 0x00CD };
      }
      case 'fire': {
        const rawRep = this.dom.numFireCount.value === '' ? 3 : Number(this.dom.numFireCount.value);
        return {
          slot,
          type: 'fire',
          interval: clamp(Number(this.dom.numFireInterval.value) || 50, 5, 255),
          repeatCount: clamp(Number.isFinite(rawRep) ? rawRep : 3, 0, 255),
        };
      }
      case 'macro': {
        const macroSlot = clamp(Number(this.dom.selMacroSlot.value) || 0, 0, 5);
        const lm = this.dom.selMacroLoop.value;
        return {
          slot,
          type: 'macro',
          slotIndex: macroSlot,
          macroId: macroSlot,
          loopMode: lm,
          loopCount: lm === 'count' ? clamp(Number(this.dom.numMacroLoopCount.value) || 1, 1, 255) : 0,
        };
      }
      case 'dpi':
        return { slot, type: 'dpi', mode: this.dom.selDpiAction.value || 'cycle' };
      default:
        return { slot, type: 'disabled' };
    }
  }

  // === Tab 3: Lighting ===

  renderLightingTab() {
    const l = this.state.lighting;
    this.dom.lightingModeGroup?.querySelectorAll('.seg-btn').forEach((btn) => {
      btn.classList.toggle('active', Number(btn.dataset.lmode) === l.mode);
    });
    this.dom.rngLightBri.value = String(l.brightness);
    this.dom.lblLightBri.textContent = String(l.brightness);
    this.dom.rngLightSpd.value = String(l.speed);
    this.dom.lblLightSpd.textContent = String(l.speed);

    this.dom.wrapLightDir?.classList.toggle('hidden', l.mode !== 1);
    this.dom.lightDirGroup?.querySelectorAll('.seg-btn').forEach((btn) => {
      btn.classList.toggle('active', Number(btn.dataset.ldir) === l.direction);
    });

    this.dom.wrapLightColor?.classList.toggle('hidden', l.mode !== 3);
    this.dom.inpLightColor.value = l.color || '#2563EB';
    this.dom.lblLightColorHex.textContent = (l.color || '#2563EB').toUpperCase();

    this.dom.wrapBreathingColors?.classList.toggle('hidden', l.mode !== 2);
    if (l.mode === 2 && this.dom.breathingColorRow) {
      this.dom.breathingColorRow.innerHTML = '';
      (l.breathingColors || []).slice(0, 7).forEach((hex, idx) => {
        const inp = document.createElement('input');
        inp.type = 'color';
        inp.className = 'color-swatch-input';
        inp.value = hex;
        inp.title = `#${idx + 1}`;
        inp.addEventListener('change', (e) => {
          l.breathingColors[idx] = e.target.value.toUpperCase();
        });
        this.dom.breathingColorRow.appendChild(inp);
      });
    }
  }

  // === Tab 4: Macros ===

  renderMacroTab() {
    this.renderMacroSlots();
    this.renderMacroTimeline();
  }

  renderMacroSlots() {
    this.dom.macroSlotList.innerHTML = '';
    for (let slot = 0; slot < 6; slot += 1) {
      const m = this.state.macros[slot];
      const hwCount = m.events.filter((ev) => ev.type !== 'delay').length;

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `macro-slot-item${slot === this.activeMacroSlot ? ' active' : ''}`;
      const nameSpan = document.createElement('span');
      nameSpan.textContent = this.getMacroDisplayName(slot);
      const countSpan = document.createElement('span');
      countSpan.className = 'mono-tag';
      countSpan.textContent = String(hwCount);
      btn.append(nameSpan, countSpan);

      btn.addEventListener('click', () => {
        if (this.isRecordingMacro) this.stopMacroRecording();
        this.activeMacroSlot = slot;
        this.dom.inpMacroName.value = this.getMacroDisplayName(slot);
        this.dom.selMacroStudioLoop.value = m.loopMode || 'toggle';
        this.renderMacroSlots();
        this.renderMacroTimeline();
      });

      this.dom.macroSlotList.appendChild(btn);
    }

    const active = this.state.macros[this.activeMacroSlot];
    if (document.activeElement !== this.dom.inpMacroName) {
      this.dom.inpMacroName.value = this.getMacroDisplayName(this.activeMacroSlot);
    }
    this.dom.selMacroStudioLoop.value = active.loopMode || 'toggle';
  }

  appendMacroSteps(steps) {
    const m = this.state.macros[this.activeMacroSlot];
    for (const s of steps) {
      m.events.push(s);
    }
    this.renderMacroSlots();
    this.renderMacroTimeline();
  }

  startMacroRecording() {
    this.isRecordingMacro = true;
    this.lastMacroEventTs = performance.now();
    this.dom.btnRecordMacro.querySelector('span').textContent = t('macros.stopRecording');

    const pushGap = () => {
      const now = performance.now();
      const delta = Math.round(now - this.lastMacroEventTs);
      this.lastMacroEventTs = now;
      if (delta >= 5) {
        this.state.macros[this.activeMacroSlot].events.push({
          type: 'delay',
          delayMs: clamp(delta, 1, 65535),
        });
      }
    };

    this._macroKeyDownHandler = (e) => {
      if (e.repeat) return;
      e.preventDefault();
      e.stopPropagation();
      const spec = resolveKeySpec({ code: e.code, keyCode: e.keyCode });
      if (!spec.hid) return;
      pushGap();
      this.appendMacroSteps([{ type: 'keyDown', code: spec.code || e.code, hid: spec.hid }]);
    };

    this._macroKeyUpHandler = (e) => {
      e.preventDefault();
      e.stopPropagation();
      const spec = resolveKeySpec({ code: e.code, keyCode: e.keyCode });
      if (!spec.hid) return;
      pushGap();
      this.appendMacroSteps([{ type: 'keyUp', code: spec.code || e.code, hid: spec.hid }]);
    };

    const mapMouseBtn = (b) => ({ 0: 1, 1: 3, 2: 2, 3: 4, 4: 5 }[b] || 1);

    this._macroMouseDownHandler = (e) => {
      if (this.dom.btnRecordMacro.contains(e.target)) return;
      pushGap();
      this.appendMacroSteps([{ type: 'mouseDown', button: mapMouseBtn(e.button) }]);
    };

    this._macroMouseUpHandler = (e) => {
      if (this.dom.btnRecordMacro.contains(e.target)) return;
      pushGap();
      this.appendMacroSteps([{ type: 'mouseUp', button: mapMouseBtn(e.button) }]);
    };

    window.addEventListener('keydown', this._macroKeyDownHandler, true);
    window.addEventListener('keyup', this._macroKeyUpHandler, true);
    window.addEventListener('mousedown', this._macroMouseDownHandler, true);
    window.addEventListener('mouseup', this._macroMouseUpHandler, true);
  }

  stopMacroRecording() {
    if (!this.isRecordingMacro) return;
    this.isRecordingMacro = false;
    this.dom.btnRecordMacro.querySelector('span').textContent = t('macros.startRecording');
    window.removeEventListener('keydown', this._macroKeyDownHandler, true);
    window.removeEventListener('keyup', this._macroKeyUpHandler, true);
    window.removeEventListener('mousedown', this._macroMouseDownHandler, true);
    window.removeEventListener('mouseup', this._macroMouseUpHandler, true);
  }

  renderMacroTimeline() {
    const m = this.state.macros[this.activeMacroSlot];
    const hwCount = m.events.filter((ev) => ev.type !== 'delay').length;
    this.dom.lblMacroActionCount.textContent = t('macros.actionCount', { count: hwCount });

    try {
      const stream = compileMacroStream(m.events, this.activeMacroSlot);
      const chunks = frameMacroChunks(this.activeMacroSlot, stream);
      this.dom.lblMacroFrameBytes.textContent = `${stream.length} B · ${chunks.length}/15`;
    } catch {
      this.dom.lblMacroFrameBytes.textContent = 'Overflow';
    }

    this.dom.macroTimeline.innerHTML = '';
    if (m.events.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = t('macros.emptyState');
      this.dom.macroTimeline.appendChild(empty);
      return;
    }

    const badgeMap = {
      keyDown: ['macros.badgeKeyDown', 'down'],
      keyUp: ['macros.badgeKeyUp', 'up'],
      mouseDown: ['macros.badgeMouseDown', 'down'],
      mouseUp: ['macros.badgeMouseUp', 'up'],
      delay: ['macros.badgeDelay', 'delay'],
    };

    m.events.forEach((ev, idx) => {
      const row = document.createElement('div');
      row.className = 'macro-event-row';

      const meta = document.createElement('div');
      meta.className = 'macro-event-meta';

      const stepNo = document.createElement('span');
      stepNo.className = 'macro-step-idx';
      stepNo.textContent = String(idx + 1).padStart(2, '0');
      meta.appendChild(stepNo);

      const [badgeKey, badgeCls] = badgeMap[ev.type] || ['macros.badgeDelay', 'delay'];
      const badge = document.createElement('span');
      badge.className = `macro-badge ${badgeCls}`;
      badge.textContent = t(badgeKey);
      meta.appendChild(badge);

      if (ev.type === 'delay') {
        const msVal = clamp(Number(ev.delayMs ?? ev.ms ?? 50), 1, 65535);
        ev.delayMs = msVal;
        const inp = document.createElement('input');
        inp.type = 'number';
        inp.className = 'num-input mono-num';
        inp.min = '1';
        inp.max = '65535';
        inp.value = String(msVal);

        const leTag = document.createElement('span');
        leTag.className = 'mono-tag';
        const updateLeTag = (v) => {
          const lo = (v & 0xFF).toString(16).toUpperCase().padStart(2, '0');
          const hi = ((v >> 8) & 0xFF).toString(16).toUpperCase().padStart(2, '0');
          leTag.textContent = `LE ${lo} ${hi}`;
        };
        updateLeTag(msVal);

        inp.addEventListener('change', (e) => {
          const next = clamp(Math.round(Number(e.target.value) || 1), 1, 65535);
          ev.delayMs = next;
          e.target.value = String(next);
          updateLeTag(next);
          this.renderMacroTimeline();
        });

        const unit = document.createElement('span');
        unit.className = 'field-label-inline';
        unit.textContent = 'ms';
        meta.append(inp, unit, leTag);
      } else if (ev.type === 'keyDown' || ev.type === 'keyUp') {
        const sel = document.createElement('select');
        sel.className = 'select-input select-sm mono-num';
        const curCode = ev.code || (ev.hid ? HID_TO_CODE[ev.hid] : 'KeyA') || 'KeyA';
        const options = COMMON_MACRO_KEYS.includes(curCode)
          ? COMMON_MACRO_KEYS
          : [curCode, ...COMMON_MACRO_KEYS];
        options.forEach((k) => {
          const opt = document.createElement('option');
          opt.value = k;
          opt.textContent = k;
          if (k === curCode) opt.selected = true;
          sel.appendChild(opt);
        });
        sel.addEventListener('change', (e) => {
          ev.code = e.target.value;
          ev.hid = USB_HID_KEYMAP[ev.code] || 0x04;
          this.renderMacroTimeline();
        });
        meta.appendChild(sel);
      } else if (ev.type === 'mouseDown' || ev.type === 'mouseUp') {
        const sel = document.createElement('select');
        sel.className = 'select-input select-sm';
        for (let b = 1; b <= 5; b += 1) {
          const opt = document.createElement('option');
          opt.value = String(b);
          opt.textContent = t(`buttons.mouse${b}`);
          if (Number(ev.button) === b) opt.selected = true;
          sel.appendChild(opt);
        }
        sel.addEventListener('change', (e) => {
          ev.button = Number(e.target.value);
        });
        meta.appendChild(sel);
      }

      const actions = document.createElement('div');
      actions.className = 'header-action-group';

      const upBtn = document.createElement('button');
      upBtn.type = 'button';
      upBtn.className = 'btn btn-ghost btn-xs';
      upBtn.disabled = idx === 0;
      upBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="18 15 12 9 6 15"/></svg>`;
      upBtn.addEventListener('click', () => {
        if (idx === 0) return;
        const [item] = m.events.splice(idx, 1);
        m.events.splice(idx - 1, 0, item);
        this.renderMacroTimeline();
      });

      const downBtn = document.createElement('button');
      downBtn.type = 'button';
      downBtn.className = 'btn btn-ghost btn-xs';
      downBtn.disabled = idx === m.events.length - 1;
      downBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>`;
      downBtn.addEventListener('click', () => {
        if (idx >= m.events.length - 1) return;
        const [item] = m.events.splice(idx, 1);
        m.events.splice(idx + 1, 0, item);
        this.renderMacroTimeline();
      });

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'btn btn-ghost btn-xs';
      delBtn.textContent = t('macros.removeStep');
      delBtn.addEventListener('click', () => {
        m.events.splice(idx, 1);
        this.renderMacroSlots();
        this.renderMacroTimeline();
      });

      actions.append(upBtn, downBtn, delBtn);
      row.append(meta, actions);
      this.dom.macroTimeline.appendChild(row);
    });
  }

  // === Tab 5: Inspector ===

  renderInspectorTab() {
    if (this.dom.lblBaselineMeta) {
      this.dom.lblBaselineMeta.textContent = this.baselineCustomName || t('inspector.baselineFactory');
    }
    this.renderDecodedDump();
    this.renderDiffGrid();
  }

  decodeDumpRowSummary(cmd, pkt) {
    if (!pkt || pkt.length < 32) return '—';
    switch (cmd) {
      case 0x10: {
        const hs = decodeHandshakePacket(pkt);
        return t('inspector.dumpHandshake', {
          devId: hs.devId,
          fw: hs.fwVersion,
          sensor: hs.sensorName,
          caps: formatCmdHex(hs.pollingCapsByte),
          hz: hs.maxPollingHz,
          pct: hs.batteryPct,
        });
      }
      case 0x11: {
        const btns = decodeButtonsPacket(pkt);
        return btns.map((b, i) => `[${i}] ${this.formatButtonSummary(b)}`).join(' · ');
      }
      case 0x12:
        return `${decodePollingPacket(pkt).pollingHz} Hz`;
      case 0x13: {
        const dpi = decodeDpiPacket(pkt, this.state.sensorId);
        return t('inspector.dumpDpi', {
          active: dpi.activeStage + 1,
          total: dpi.stageCount,
          stages: dpi.stages.map((s) => `${s.x}/${s.y}`).join(', '),
        });
      }
      case 0x14:
        return decodeDpiColorsPacket(pkt).join(' · ');
      case 0x15: {
        const l = decodeLightingPacket(pkt);
        return t('inspector.dumpLighting', {
          mode: l.mode,
          modeName: t(`lighting.mode${l.mode}`),
          bri: l.brightness,
          spd: l.speed,
        });
      }
      case 0x16: {
        const s = decodeSensorPacket(pkt);
        return t('inspector.dumpSensor', {
          lod: s.lod,
          snap: s.angleSnap ? 1 : 0,
          ripple: s.ripple ? 1 : 0,
          ms: s.motionSync ? 1 : 0,
        });
      }
      case 0x17: {
        const sl = decodeSleepPacket(pkt);
        return t('inspector.dumpSleep', {
          sec: sl.sleepSec,
          wake: sl.moveWake ? 1 : 0,
          led: sl.moveCloseLight ? 1 : 0,
          deb: sl.debounceMs,
        });
      }
      case 0x20: {
        const d = decodeDonglePacket(pkt);
        return t('inspector.dumpRf', { ver: d.rfFwVersion });
      }
      default:
        return '—';
    }
  }

  renderDecodedDump() {
    const regs = this.getActiveRawRegisters();
    this.dom.dumpTable.innerHTML = '';

    for (const cmd of SAFE_DUMP_OPCODES) {
      const key = formatCmdHex(cmd);
      const hex = regs[key];
      let pkt = null;
      if (hex) {
        try {
          pkt = parseHex(hex);
        } catch {
          pkt = null;
        }
      }

      const row = document.createElement('div');
      row.className = 'dump-row';

      const opTag = document.createElement('span');
      opTag.className = 'mono-tag';
      opTag.textContent = key;

      const decodedEl = document.createElement('span');
      decodedEl.className = 'dump-decoded';
      decodedEl.textContent = this.decodeDumpRowSummary(cmd, pkt);

      const hexEl = document.createElement('span');
      hexEl.className = 'dump-hex';
      hexEl.textContent = hex || '—';

      row.append(opTag, decodedEl, hexEl);
      this.dom.dumpTable.appendChild(row);
    }
  }

  renderDiffGrid() {
    const currentRegs = this.getActiveRawRegisters();
    const diff = computeSnapshotDiff(this.baselineSnapshot, currentRegs);
    this.dom.lblDiffSummary.textContent = t('inspector.diffSummary', {
      changed: diff.totalChangedBits,
      total: diff.totalBits,
    });

    const opcodes = Object.keys(diff.registers);
    if (!opcodes.includes(this.selectedDiffOpcode)) {
      this.selectedDiffOpcode = diff.changedOpcodes[0] || opcodes[0] || '0x10';
    }

    this.dom.diffOpcodeTabs.innerHTML = '';
    opcodes.forEach((op) => {
      const reg = diff.registers[op];
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `btn btn-ghost btn-xs mono-num${reg.changedBits > 0 ? ' has-diff' : ''}${op === this.selectedDiffOpcode ? ' active' : ''}`;
      btn.textContent = reg.changedBits > 0 ? `${op} (${reg.changedBits})` : op;
      btn.addEventListener('click', () => {
        this.selectedDiffOpcode = op;
        this.renderDiffGrid();
      });
      this.dom.diffOpcodeTabs.appendChild(btn);
    });

    this.dom.diffGridContainer.innerHTML = '';
    const regDiff = diff.registers[this.selectedDiffOpcode];
    if (!regDiff) return;

    regDiff.byteDiffs.forEach((bd) => {
      const cell = document.createElement('div');
      cell.className = `diff-byte-cell${bd.changed ? ' changed' : ''}`;
      const baseHex = bd.baseline.toString(16).toUpperCase().padStart(2, '0');
      const curHex = bd.current.toString(16).toUpperCase().padStart(2, '0');
      cell.title = t('inspector.diffByteTitle', {
        index: bd.byteIndex,
        base: baseHex,
        cur: curHex,
      });

      const head = document.createElement('div');
      head.className = 'diff-byte-head';
      const idxSpan = document.createElement('span');
      idxSpan.className = 'diff-byte-idx';
      idxSpan.textContent = String(bd.byteIndex).padStart(2, '0');
      const valSpan = document.createElement('span');
      valSpan.className = 'diff-byte-hex';
      valSpan.textContent = curHex;
      head.append(idxSpan, valSpan);

      const strip = document.createElement('div');
      strip.className = 'diff-bit-strip';
      for (let b = 0; b < 8; b += 1) {
        const bit = regDiff.bits[bd.byteIndex * 8 + b];
        const dot = document.createElement('span');
        dot.className = `diff-bit${bit.currentBit ? ' on' : ''}${bit.changed ? ' changed' : ''}`;
        strip.appendChild(dot);
      }

      cell.append(head, strip);
      this.dom.diffGridContainer.appendChild(cell);
    });
  }

  async runAllowlistedRawCommand() {
    this.dom.rawRunnerAlert.classList.add('hidden');
    this.dom.rawRunnerOutput.classList.add('hidden');

    const opStr = (this.dom.inpRawOpcode.value || '').trim();
    if (!/^(?:0x)?[0-9a-f]{1,2}$/i.test(opStr)) {
      this.dom.rawRunnerAlert.textContent = t('errors.invalidHexOpcode');
      this.dom.rawRunnerAlert.classList.remove('hidden');
      return;
    }
    const cmd = parseInt(opStr, 16);

    const cmdHex = formatCmdHex(cmd);
    if (!isAllowedOpcode(cmd)) {
      const msg = t('errors.stallGuardBlocked', { cmd: cmdHex });
      this.dom.rawRunnerAlert.textContent = msg;
      this.dom.rawRunnerAlert.classList.remove('hidden');
      this.showToast(msg, true);
      return;
    }

    let payload;
    try {
      payload = this.dom.inpRawPayload.value.trim()
        ? parseHex(this.dom.inpRawPayload.value)
        : new Uint8Array(0);
    } catch (err) {
      this.dom.rawRunnerAlert.textContent = err.message;
      this.dom.rawRunnerAlert.classList.remove('hidden');
      return;
    }

    if (this.device) {
      try {
        const res = await this.device.sendAllowlistedRaw(cmd, payload);
        this.dom.rawRunnerOutput.textContent = `TX: ${formatHex(res.tx)}\nRX: ${res.rx ? formatHex(res.rx) : 'timeout'}`;
        this.dom.rawRunnerOutput.classList.remove('hidden');
        this.showToast(t('toast.rawSent', { cmd: cmdHex }));
        this.renderInspectorTab();
      } catch (err) {
        const msg = this.formatProtocolError(err);
        this.dom.rawRunnerAlert.textContent = msg;
        this.dom.rawRunnerAlert.classList.remove('hidden');
        this.showToast(msg, true);
      }
    } else {
      const pkt = buildCommandPacket(cmd, payload);
      this.appendConsoleEntry('TX', cmd, pkt, { status: 0 });
      this.dom.rawRunnerOutput.textContent = `TX (Preview): ${formatHex(pkt)}`;
      this.dom.rawRunnerOutput.classList.remove('hidden');
      this.showToast(t('toast.rawSent', { cmd: cmdHex }));
    }
  }

  appendConsoleEntry(dir, cmd, bytes, entry = {}) {
    if (!this.dom.packetLog) return;
    const row = document.createElement('div');
    row.className = 'log-entry';
    const d = new Date(entry.ts || Date.now());
    const ts = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}.${String(d.getMilliseconds()).padStart(3, '0')}`;
    const cls = dir === 'TX' ? 'log-dir-tx' : dir === 'RX' ? 'log-dir-rx' : 'log-dir-evt';

    const tsSpan = document.createElement('span');
    tsSpan.className = 'log-ts';
    tsSpan.textContent = ts;

    const dirSpan = document.createElement('span');
    dirSpan.className = cls;
    dirSpan.textContent = `[${dir} ${formatCmdHex(cmd)}]`;

    const hexSpan = document.createElement('span');
    hexSpan.textContent = formatHex(bytes);

    row.append(tsSpan, dirSpan, hexSpan);
    this.dom.packetLog.appendChild(row);
    while (this.dom.packetLog.children.length > 250) {
      this.dom.packetLog.removeChild(this.dom.packetLog.firstChild);
    }
    this.dom.packetLog.scrollTop = this.dom.packetLog.scrollHeight;
  }

  // === Tab 6: Firmware & Device Identity ===

  renderFirmwareTab() {
    const profile = getModelByKey(this.state.modelKey);
    this.dom.fwSpecModel.textContent = profile.name;
    this.dom.fwSpecDevId.textContent = this.state.devId || profile.devId;
    this.dom.fwSpecSensor.textContent = `${this.state.sensorName || profile.sensorName} (${formatCmdHex(this.state.sensorId ?? 0x11)})`;
    this.dom.fwSpecVidPid.textContent = `${formatHex16(this.state.vendorId)} / ${formatHex16(this.state.productId)}`;

    if (this.isConnected) {
      const fwText = this.state.rfFwVersion && this.state.rfFwVersion !== '—'
        ? `${this.state.fwVersion} · RF ${this.state.rfFwVersion}`
        : this.state.fwVersion;
      this.dom.fwSpecFw.textContent = fwText;
      this.dom.fwSpecBattery.textContent = this.state.charging
        ? t('firmware.batteryCharging', { pct: this.state.batteryPct })
        : `${this.state.batteryPct}%`;
    } else {
      this.dom.fwSpecFw.textContent = '—';
      this.dom.fwSpecBattery.textContent = '—';
    }

    this.dom.fwSpecCaps.textContent = `${formatCmdHex(this.state.pollingCapsByte)} · ${this.state.maxPollingHz} Hz`;

    if (this.activeCollection) {
      this.dom.fwSpecInterface.textContent = `${formatHex16(this.activeCollection.usagePage)} / ${formatHex16(this.activeCollection.usage)} (${this.activeCollection.outputBytes} B)`;
    } else {
      this.dom.fwSpecInterface.textContent = '0xFF01 / 0x0010 · 0x0001 / 0x0000 (32 B)';
    }

    if (this.dom.fwSpecTransport) {
      if (!this.isConnected) {
        this.dom.fwSpecTransport.textContent = '—';
      } else if (this.hidManager.transportType === 'local-helper') {
        this.dom.fwSpecTransport.textContent = t('firmware.transportLocalHelper');
      } else {
        this.dom.fwSpecTransport.textContent = t('firmware.transportWebHid');
      }
    }
  }

  // === Utilities ===

  downloadJson(obj, filename) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  showToast(message, isError = false) {
    if (!this.dom.toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast${isError ? ' error' : ''}`;
    toast.textContent = message;
    this.dom.toastContainer.appendChild(toast);
    setTimeout(() => toast.remove(), 3500);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.valkyrieApp = new ValkyrieControlApp();
});
