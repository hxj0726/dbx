import { defineStore } from "pinia";
import { computed, ref } from "vue";
import type { WebIdentityRole } from "@/lib/startup/startupAuthentication";

/**
 * 网页版身份角色（仅 next-tdc 注入签名身份时才有值）
 *
 * 为什么 `role === null` 也算管理员：桌面版是单用户本地应用，传统口令模式是
 * 单租户部署，两者都不存在"会影响别人"的公共配置，因此不门禁。这样默认行为与
 * 改造前完全一致，不会因为升级而把老用户的设置页锁掉。
 */
export const useWebIdentityStore = defineStore("webIdentity", () => {
  const role = ref<WebIdentityRole | null>(null);

  /** 是否可管理公共配置（可信代理模式下只有 admin 为 true） */
  const isAdmin = computed(() => role.value === null || role.value === "admin");

  /** 是否受限的普通用户 */
  const isMember = computed(() => role.value === "member");

  function setRole(next: WebIdentityRole | null): void {
    role.value = next;
  }

  return { role, isAdmin, isMember, setRole };
});
