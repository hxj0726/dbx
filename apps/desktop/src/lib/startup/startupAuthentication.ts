import { apiUrl } from "@/lib/common/webPath";

/** 网页版身份角色；传统口令模式与桌面版没有这个概念 */
export type WebIdentityRole = "admin" | "member";

export interface StartupAuthentication {
  required: boolean;
  authenticated: boolean;
  setup_required: boolean;
  /** 仅在可信代理模式（next-tdc 注入签名身份）下才有值 */
  role: WebIdentityRole | null;
}

function parseRole(value: unknown): WebIdentityRole | null {
  return value === "admin" || value === "member" ? value : null;
}

export async function checkStartupAuthentication(signal?: AbortSignal): Promise<StartupAuthentication> {
  const response = await fetch(apiUrl("/api/auth/check"), { credentials: "same-origin", signal });
  if (!response.ok) throw new Error("AUTH_CHECK_FAILED");
  const result: unknown = await response.json();
  if (!result || typeof result !== "object" || !("required" in result) || !("authenticated" in result) || typeof result.required !== "boolean" || typeof result.authenticated !== "boolean") {
    throw new Error("AUTH_CHECK_FAILED");
  }
  return {
    required: result.required,
    authenticated: result.authenticated,
    setup_required: "setup_required" in result && result.setup_required === true,
    role: parseRole("role" in result ? result.role : undefined),
  };
}

export async function logoutWeb(): Promise<void> {
  const response = await fetch(apiUrl("/api/auth/logout"), {
    method: "POST",
    credentials: "same-origin",
  });
  if (!response.ok) {
    throw new Error("AUTH_LOGOUT_FAILED");
  }
}
