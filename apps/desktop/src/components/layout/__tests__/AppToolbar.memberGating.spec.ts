// @vitest-environment happy-dom
import { createApp, nextTick } from "vue";
import { createPinia, setActivePinia } from "pinia";
import { createI18n } from "vue-i18n";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/backend/tauriRuntime", () => ({
  isTauriRuntime: () => false,
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn(async () => undefined) }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => {}),
  emit: vi.fn(async () => undefined),
}));
vi.mock("@tauri-apps/api/webviewWindow", () => ({
  getAllWebviewWindows: vi.fn(async () => []),
  WebviewWindow: { getByLabel: vi.fn(async () => null) },
}));
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    label: "main",
    isMaximized: async () => false,
    isFullscreen: async () => false,
    isAlwaysOnTop: async () => false,
    setAlwaysOnTop: async () => {},
    onResized: async () => () => {},
    onFocusChanged: async () => () => {},
    minimize: async () => {},
    toggleMaximize: async () => {},
  }),
}));

vi.mock("@/components/ui/button", () => ({
  Button: { name: "ButtonStub", props: ["ariaLabel"], template: `<button :aria-label="ariaLabel"><slot /></button>` },
}));
vi.mock("@/components/ui/tooltip", () => ({
  Tooltip: { name: "TooltipStub", template: `<span><slot /></span>` },
  TooltipTrigger: { name: "TooltipTriggerStub", template: `<span><slot /></span>` },
  TooltipContent: { name: "TooltipContentStub", template: `<span><slot /></span>` },
}));
vi.mock("@/components/ui/LightDropdown.vue", () => ({
  default: { name: "LightDropdownStub", template: `<div />` },
}));
vi.mock("@/components/layout/WindowControls.vue", () => ({
  default: { name: "WindowControlsStub", template: `<div />` },
}));
vi.mock("@/components/export/ExportProgressPopover.vue", () => ({
  default: { name: "ExportProgressPopoverStub", template: `<div />` },
}));
vi.mock("@/components/layout/ToolbarUpdateIcon.vue", () => ({
  default: { name: "ToolbarUpdateIconStub", template: `<span />` },
}));
vi.mock("@/components/plugins/PluginShortcutToolbar.vue", () => ({
  default: { name: "PluginShortcutToolbarStub", template: `<div />` },
}));

import { useWebIdentityStore } from "@/stores/webIdentityStore";
import AppToolbar from "../AppToolbar.vue";

const defaultToolbarProps = {
  isDark: false,
  themeMode: "light" as const,
  showSidebarExpand: false,
  showAiPanel: false,
  activeAiRunCount: 0,
  awaitingAiRunCount: 0,
  showHistory: false,
  showSqlLibrary: false,
  sqlLibrarySaveFeedbackId: 0,
  showSqlFilePanel: false,
  showDriverStore: false,
  showPluginCenter: false,
  showSettingsPage: false,
  checkingUpdates: false,
  hasUpdateAvailable: false,
  isDownloadingUpdate: false,
  downloadProgress: null,
  updateReadyToInstall: false,
  updateReady: false,
  agentDriverUpdateCount: 0,
  hasMcpUpdateAvailable: false,
  hasConnections: false,
  canNewQuery: false,
  hasSqlFileConnections: false,
  immediateSyncing: false,
};

let pinia: ReturnType<typeof createPinia>;

function mount() {
  const host = document.createElement("div");
  document.body.appendChild(host);
  const app = createApp(AppToolbar, defaultToolbarProps);
  app.use(pinia);
  app.use(
    createI18n({
      legacy: false,
      locale: "en",
      missingWarn: false,
      fallbackWarn: false,
      messages: {
        en: {
          toolbar: {
            newConnection: "New Connection",
            newQuery: "New Query",
            driverManager: "Driver Manager",
            pluginCenter: "Plugin Center",
          },
        },
      },
    }),
  );
  app.mount(host);
  return {
    host,
    unmount: () => {
      app.unmount();
      host.remove();
    },
  };
}

function buttonLabels(host: HTMLElement): string[] {
  return Array.from(host.querySelectorAll("button")).map((button) => button.textContent?.trim() ?? "");
}

describe("AppToolbar admin-only surfaces (#dbx-web member gating)", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
    pinia = createPinia();
    setActivePinia(pinia);
  });

  it("hides the driver manager entry from members", async () => {
    useWebIdentityStore().setRole("member");
    const { host, unmount } = mount();
    await nextTick();

    expect(buttonLabels(host)).not.toContain("Driver Manager");

    unmount();
  });

  it("hides the plugin center entry from members", async () => {
    useWebIdentityStore().setRole("member");
    const { host, unmount } = mount();
    await nextTick();

    expect(buttonLabels(host)).not.toContain("Plugin Center");

    unmount();
  });

  it("keeps both entries for administrators", async () => {
    useWebIdentityStore().setRole("admin");
    const { host, unmount } = mount();
    await nextTick();

    const labels = buttonLabels(host);
    expect(labels).toContain("Driver Manager");
    expect(labels).toContain("Plugin Center");

    unmount();
  });

  it("keeps both entries when no role is injected (desktop / single-tenant)", async () => {
    useWebIdentityStore().setRole(null);
    const { host, unmount } = mount();
    await nextTick();

    const labels = buttonLabels(host);
    expect(labels).toContain("Driver Manager");
    expect(labels).toContain("Plugin Center");

    unmount();
  });

  it("drops the entries as soon as the role degrades to member", async () => {
    const identity = useWebIdentityStore();
    identity.setRole("admin");
    const { host, unmount } = mount();
    await nextTick();
    expect(buttonLabels(host)).toContain("Driver Manager");

    identity.setRole("member");
    await nextTick();
    expect(buttonLabels(host)).not.toContain("Driver Manager");

    unmount();
  });
});
