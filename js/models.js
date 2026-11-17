/**
 * Valkyrie Mouse Visual & Schematic Model Registry
 *
 * Pin positions map onto `assets/models/vk_m3_lite.png` (260x506), matching the
 * 6-slot button layout and XML leader-line coordinates (`mouse_vk m3*.xml`).
 */

import { DEVICE_BY_DEVID, getDeviceByDevId, getDeviceByPid } from './devices.js';

/**
 * Official 6-button schematic template shared by VK M3 Lite and VK M3 shells.
 * XML `location="labelX,anchorX,anchorY"` places slots around the 260x506 render
 * centered at X=250 in the original container (`120..380`, `Y=0..506`).
 */
function createSchematicButtons() {
  return [
    {
      id: 0,
      keyName: 'btn0',
      name: 'Left',
      defaultAction: 'Mouse Left',
      defaultActionSpec: { type: 'mouse', button: 1 },
      pinX: 30,
      pinY: 16,
      calloutSide: 'left',
      dashed: false,
      xmlLocation: [100, 180, 50],
    },
    {
      id: 1,
      keyName: 'btn1',
      name: 'Right',
      defaultAction: 'Mouse Right',
      defaultActionSpec: { type: 'mouse', button: 2 },
      pinX: 70,
      pinY: 16,
      calloutSide: 'right',
      dashed: false,
      xmlLocation: [305, 390, 50],
    },
    {
      id: 2,
      keyName: 'btn2',
      name: 'Middle',
      defaultAction: 'Mouse Middle',
      defaultActionSpec: { type: 'mouse', button: 3 },
      pinX: 50,
      pinY: 20,
      calloutSide: 'right',
      dashed: false,
      xmlLocation: [251, 390, 90],
    },
    {
      id: 3,
      keyName: 'btn3',
      name: 'Back',
      defaultAction: 'Mouse Back',
      defaultActionSpec: { type: 'mouse', button: 4 },
      pinX: 4,
      pinY: 47,
      calloutSide: 'left',
      dashed: false,
      xmlLocation: [100, 123, 238],
    },
    {
      id: 4,
      keyName: 'btn4',
      name: 'Forward',
      defaultAction: 'Mouse Forward',
      defaultActionSpec: { type: 'mouse', button: 5 },
      pinX: 4,
      pinY: 34,
      calloutSide: 'left',
      dashed: false,
      xmlLocation: [100, 121, 170],
    },
    {
      id: 5,
      keyName: 'btn5',
      name: 'DPI Cycle',
      defaultAction: 'DPI Cycle',
      defaultActionSpec: { type: 'dpi', mode: 'cycle' },
      pinX: 50,
      pinY: 46,
      calloutSide: 'right',
      dashed: true,
      xmlLocation: [350, 390, 230],
    },
  ];
}

function buildXmlFactoryDefaults(devSpec) {
  return {
    stages: devSpec.factoryDpis.map((dpi, idx) => ({
      x: dpi,
      y: dpi,
      color: devSpec.factoryColors[idx] || '#2563EB',
    })),
    activeDpiStage: devSpec.defaultDpiIndex,
    pollingHz: devSpec.defaultPollingHz,
    sleepSec: devSpec.defaultSleepSec,
    sleep10s: Math.round(devSpec.defaultSleepSec / 10),
    moveWake: false,
    moveCloseLight: false,
    debounceMs: devSpec.defaultDebounceMs,
    lod: devSpec.defaultLod,
    angleSnap: false,
    ripple: false,
    motionSync: true,
    lighting: {
      mode: devSpec.defaultLightMode,
      brightness: 2,
      speed: 4,
      direction: 1,
      color: '#2563EB',
      breathingColors: [
        '#FF0000',
        '#00FF00',
        '#0000FF',
        '#FFFF00',
        '#FF00FF',
        '#00FFFF',
        '#FFFFFF',
      ],
    },
    buttons: [
      { type: 'mouse', button: 1 },
      { type: 'mouse', button: 2 },
      { type: 'mouse', button: 3 },
      { type: 'mouse', button: 4 },
      { type: 'mouse', button: 5 },
      { type: 'dpi', mode: 'cycle' },
    ],
  };
}

export const MODEL_PROFILES = {
  VK_M3_LITE: {
    id: 'VK_M3_LITE',
    devId: DEVICE_BY_DEVID.M220.devId,
    deviceType: DEVICE_BY_DEVID.M220.deviceType,
    name: 'VK M3 Lite',
    optKey: 'models.opt.VK_M3_LITE',
    subtitle: 'PAW3311 · 6 buttons · M220',
    image: 'assets/models/vk_m3_lite.png',
    imageWidth: 260,
    imageHeight: 506,
    sensorId: 0x11,
    sensorCurveId: 0x11,
    sensorName: 'PAW3311',
    nativeMaxDpi: 12000,
    lightEnabledInXml: false,
    buttons: createSchematicButtons(),
    factoryDefaults: buildXmlFactoryDefaults(DEVICE_BY_DEVID.M220),
  },
  VK_M3: {
    id: 'VK_M3',
    devId: DEVICE_BY_DEVID.E023.devId,
    deviceType: DEVICE_BY_DEVID.E023.deviceType,
    name: 'VK M3',
    optKey: 'models.opt.VK_M3',
    subtitle: '6 buttons · E023',
    image: 'assets/models/vk_m3_lite.png',
    imageWidth: 260,
    imageHeight: 506,
    sensorId: 0x11,
    sensorCurveId: 0x11,
    sensorName: 'PAW3395',
    nativeMaxDpi: 26000,
    lightEnabledInXml: false,
    buttons: createSchematicButtons(),
    factoryDefaults: buildXmlFactoryDefaults(DEVICE_BY_DEVID.E023),
  },
};

/**
 * Resolve model profile from model key or firmware `devId`.
 * @param {string} keyOrDevId
 * @returns {object}
 */
export function getModelByKey(keyOrDevId) {
  if (!keyOrDevId) return MODEL_PROFILES.VK_M3_LITE;
  if (MODEL_PROFILES[keyOrDevId]) return MODEL_PROFILES[keyOrDevId];
  const devSpec = getDeviceByDevId(keyOrDevId);
  if (devSpec && MODEL_PROFILES[devSpec.modelKey]) {
    return MODEL_PROFILES[devSpec.modelKey];
  }
  return MODEL_PROFILES.VK_M3_LITE;
}

/**
 * Resolve model profile using handshake `devId` (preferred) or USB PID fallback.
 * @param {number} pid
 * @param {string} [devId]
 * @returns {object}
 */
export function getModelByPid(pid, devId = null) {
  if (devId) {
    const devSpec = getDeviceByDevId(devId);
    if (devSpec && MODEL_PROFILES[devSpec.modelKey]) {
      return MODEL_PROFILES[devSpec.modelKey];
    }
  }
  const desc = getDeviceByPid(pid);
  return MODEL_PROFILES[desc.modelId] || MODEL_PROFILES.VK_M3_LITE;
}

/**
 * Return selectable model entries for topbar selector.
 * @returns {Array<object>}
 */
export function getModelList() {
  return [MODEL_PROFILES.VK_M3_LITE, MODEL_PROFILES.VK_M3];
}
