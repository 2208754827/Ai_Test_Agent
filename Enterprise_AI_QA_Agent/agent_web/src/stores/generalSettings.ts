import { defineStore } from "pinia";

import { api } from "../services/api";
import { setLocale } from "../services/i18n";

export type SystemLanguage = string;
export type ModelOutputLanguage = string;
export type AppFontFamily = "system" | "sans" | "chinese" | "serif" | "mono";
export type AppFontSize = "small" | "compact" | "standard" | "comfortable" | "large";
export type DesktopNotificationPermission = NotificationPermission | "unsupported";

export interface GeneralSettingsSnapshot {
  language: SystemLanguage;
  modelOutputLanguage: ModelOutputLanguage;
  notifySessionCompleteWhenAway: boolean;
  notifyApprovalRequiredWhenAway: boolean;
  notificationsAwayOnly: boolean;
  fontFamily: AppFontFamily;
  fontSize: AppFontSize;
  reduceMotion: boolean;
  lastSavedAt: string;
}

interface GeneralSettingsState extends GeneralSettingsSnapshot {
  notificationPermissionStatus: DesktopNotificationPermission;
  backendAvailable: boolean;
  syncError: string;
}

const STORAGE_KEY = "enterprise-ai-qa-agent-general-settings";

const defaultSettings: GeneralSettingsSnapshot = {
  language: "zh-CN",
  modelOutputLanguage: "follow-system",
  notifySessionCompleteWhenAway: true,
  notifyApprovalRequiredWhenAway: true,
  notificationsAwayOnly: true,
  fontFamily: "system",
  fontSize: "standard",
  reduceMotion: false,
  lastSavedAt: "",
};

const fontFamilyMap: Record<AppFontFamily, string> = {
  system: 'Inter, "PingFang SC", "Microsoft YaHei", ui-sans-serif, system-ui, sans-serif',
  sans: 'Roboto, "Helvetica Neue", Helvetica, Arial, sans-serif',
  chinese: '"PingFang SC", "Microsoft YaHei", "Noto Sans SC", "LXGW WenKai", ui-sans-serif, system-ui, sans-serif',
  serif: '"Noto Serif CJK SC", "Noto Serif SC", SimSun, "Times New Roman", serif',
  mono: '"JetBrains Mono", "SFMono-Regular", Consolas, "Liberation Mono", "Microsoft YaHei", monospace',
};

const fontSizeScaleMap: Record<AppFontSize, string> = {
  small: "0.85",
  compact: "0.92",
  standard: "1",
  comfortable: "1.08",
  large: "1.18",
};

function setFontSizeVariables(root: HTMLElement, scale: string) {
  const numericScale = Number(scale);
  const normalizedScale = Number.isFinite(numericScale) ? numericScale : 1;
  const size = (value: number) => `${Number((value * normalizedScale).toFixed(2))}px`;

  root.style.setProperty("--app-font-size-scale", scale);
  root.style.setProperty("--app-font-size", size(14));
  root.style.setProperty("--app-font-size-mini", size(12));
  root.style.setProperty("--app-font-size-tiny", size(12));
  root.style.setProperty("--app-font-size-small", size(14));
  root.style.setProperty("--app-font-size-medium", size(14));
  root.style.setProperty("--app-font-size-large", size(15));
  root.style.setProperty("--app-font-size-huge", size(16));
}

function applyInterfaceScale(scale: string) {
  if (typeof document === "undefined") {
    return;
  }

  const appRoot = document.getElementById("app");
  if (appRoot) {
    appRoot.style.removeProperty("zoom");
  }

  if (typeof window !== "undefined" && window.qaAgentDesktop?.setZoomFactor) {
    window.qaAgentDesktop.setZoomFactor(Number(scale)).catch((error) => {
      console.warn("Failed to apply desktop zoom factor", error);
    });
    document.body.style.removeProperty("font-size");
    return;
  }

  document.body.style.setProperty("font-size", `var(--app-font-size)`);
}

function isLanguageCode(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isAppFontFamily(value: unknown): value is AppFontFamily {
  return value === "system" || value === "sans" || value === "chinese" || value === "serif" || value === "mono";
}

function isAppFontSize(value: unknown): value is AppFontSize {
  return value === "small" || value === "compact" || value === "standard" || value === "comfortable" || value === "large";
}

function readDesktopPermission(): DesktopNotificationPermission {
  if (typeof window !== "undefined" && window.qaAgentDesktop?.isDesktop) {
    return "granted";
  }
  if (typeof window === "undefined" || !("Notification" in window)) {
    return "unsupported";
  }
  return window.Notification.permission;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function normalizeSettings(value: unknown): GeneralSettingsSnapshot {
  const record = asRecord(value);
  return {
    language: isLanguageCode(record.language) ? record.language : defaultSettings.language,
    modelOutputLanguage: isLanguageCode(record.modelOutputLanguage)
      ? record.modelOutputLanguage
      : defaultSettings.modelOutputLanguage,
    notifySessionCompleteWhenAway:
      typeof record.notifySessionCompleteWhenAway === "boolean"
        ? record.notifySessionCompleteWhenAway
        : defaultSettings.notifySessionCompleteWhenAway,
    notifyApprovalRequiredWhenAway:
      typeof record.notifyApprovalRequiredWhenAway === "boolean"
        ? record.notifyApprovalRequiredWhenAway
        : defaultSettings.notifyApprovalRequiredWhenAway,
    notificationsAwayOnly:
      typeof record.notificationsAwayOnly === "boolean" ? record.notificationsAwayOnly : defaultSettings.notificationsAwayOnly,
    fontFamily: isAppFontFamily(record.fontFamily) ? record.fontFamily : defaultSettings.fontFamily,
    fontSize: isAppFontSize(record.fontSize) ? record.fontSize : defaultSettings.fontSize,
    reduceMotion: typeof record.reduceMotion === "boolean" ? record.reduceMotion : defaultSettings.reduceMotion,
    lastSavedAt: typeof record.lastSavedAt === "string" ? record.lastSavedAt : defaultSettings.lastSavedAt,
  };
}

function persistToLocalStorage(settings: GeneralSettingsSnapshot) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
}

function readFromLocalStorage(): GeneralSettingsSnapshot | null {
  if (typeof window === "undefined") return null;
  const saved = window.localStorage.getItem(STORAGE_KEY);
  if (!saved) return null;
  try { return normalizeSettings(JSON.parse(saved)); } catch { return null; }
}

function applySettingsToDocument(settings: GeneralSettingsSnapshot) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.lang = settings.language;
  root.dataset.appLanguage = settings.language;
  root.dataset.modelOutputLanguage = settings.modelOutputLanguage;
  root.dataset.appFont = settings.fontFamily;
  root.dataset.reduceMotion = settings.reduceMotion ? "true" : "false";
  root.style.setProperty("--app-font-family", fontFamilyMap[settings.fontFamily]);
  setFontSizeVariables(root, fontSizeScaleMap[settings.fontSize]);
  // Use Chromium/Electron page zoom instead of CSS `zoom`. CSS `zoom` changes
  // DOM subtree geometry without keeping teleported popups in the same coordinate
  // system, which breaks Naive UI dropdown/popover placement.
  applyInterfaceScale(fontSizeScaleMap[settings.fontSize]);
  // Sync i18n locale.
  setLocale(settings.language);
}

export const useGeneralSettingsStore = defineStore("generalSettings", {
  state: (): GeneralSettingsState => ({
    ...defaultSettings,
    notificationPermissionStatus: readDesktopPermission(),
    backendAvailable: false,
    syncError: "",
  }),
  getters: {
    hasDesktopNotificationSupport(state): boolean {
      return state.notificationPermissionStatus !== "unsupported";
    },
    canSendDesktopNotifications(state): boolean {
      return state.notificationPermissionStatus === "granted";
    },
    settingsSnapshot(state): GeneralSettingsSnapshot {
      return normalizeSettings(state);
    },
    lastSavedAt(state): string {
      return state.lastSavedAt;
    },
  },
  actions: {
    async hydrateGeneralSettings() {
      // Priority: backend > localStorage > defaults.
      try {
        const backendData = await api.getGeneralSettings();
        if (backendData && typeof backendData === "object" && (backendData as Record<string, unknown>).lastSavedAt) {
          const settings = normalizeSettings(backendData);
          this.$patch({ ...settings, notificationPermissionStatus: readDesktopPermission(), backendAvailable: true, syncError: "" });
          persistToLocalStorage(settings);
          applySettingsToDocument(settings);
          return;
        }
      } catch { /* backend unavailable */ }

      const localSettings = readFromLocalStorage();
      const nextSettings = localSettings || { ...defaultSettings };
      this.$patch({ ...nextSettings, notificationPermissionStatus: readDesktopPermission(), backendAvailable: false, syncError: "" });
      applySettingsToDocument(nextSettings);

      if (localSettings && localSettings.lastSavedAt) {
        this._tryMigrateToBackend(localSettings);
      }
    },

    async saveGeneralSettings(patch: Partial<GeneralSettingsSnapshot>) {
      const nextSettings = normalizeSettings({
        ...this.settingsSnapshot,
        ...patch,
        lastSavedAt: new Date().toISOString(),
      });
      this.$patch(nextSettings);
      applySettingsToDocument(nextSettings);
      persistToLocalStorage(nextSettings);

      try {
        await api.saveGeneralSettings(nextSettings as unknown as Record<string, unknown>);
        this.backendAvailable = true;
        this.syncError = "";
      } catch (error) {
        this.backendAvailable = false;
        this.syncError = error instanceof Error ? error.message : "保存到后端失败，已保存到本地。";
      }
    },

    async resetGeneralSettings() {
      const nextSettings = normalizeSettings({ ...defaultSettings, lastSavedAt: new Date().toISOString() });
      this.$patch(nextSettings);
      applySettingsToDocument(nextSettings);
      persistToLocalStorage(nextSettings);
      try {
        await api.saveGeneralSettings(nextSettings as unknown as Record<string, unknown>);
        this.backendAvailable = true;
        this.syncError = "";
      } catch { this.backendAvailable = false; }
    },

    previewAppearance(patch: Pick<GeneralSettingsSnapshot, "fontFamily" | "fontSize" | "reduceMotion">) {
      if (typeof document === "undefined") return;
      const root = document.documentElement;
      root.dataset.appFont = patch.fontFamily;
      root.dataset.reduceMotion = patch.reduceMotion ? "true" : "false";
      root.style.setProperty("--app-font-family", fontFamilyMap[patch.fontFamily]);
      setFontSizeVariables(root, fontSizeScaleMap[patch.fontSize]);
      applyInterfaceScale(fontSizeScaleMap[patch.fontSize]);
    },

    restoreAppearance() {
      applySettingsToDocument(this.settingsSnapshot);
    },

    async _tryMigrateToBackend(settings: GeneralSettingsSnapshot) {
      try {
        await api.saveGeneralSettings(settings as unknown as Record<string, unknown>);
        this.backendAvailable = true;
      } catch { /* silent */ }
    },
  },
});
