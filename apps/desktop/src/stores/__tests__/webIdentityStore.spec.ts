import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, it } from "vitest";
import { useWebIdentityStore } from "@/stores/webIdentityStore";

describe("webIdentityStore", () => {
  beforeEach(() => {
    setActivePinia(createPinia());
  });

  it("未拿到角色时不门禁公共配置", () => {
    // 桌面版与口令模式都没有角色概念：此时若按"非 admin"处理，会把老用户的
    // 设置页锁掉。这是刻意的兼容性取舍，用测试固定住。
    const store = useWebIdentityStore();
    expect(store.role).toBeNull();
    expect(store.isAdmin).toBe(true);
    expect(store.isMember).toBe(false);
  });

  it("admin 可管理公共配置", () => {
    const store = useWebIdentityStore();
    store.setRole("admin");
    expect(store.isAdmin).toBe(true);
    expect(store.isMember).toBe(false);
  });

  it("member 不可管理公共配置", () => {
    const store = useWebIdentityStore();
    store.setRole("member");
    expect(store.isAdmin).toBe(false);
    expect(store.isMember).toBe(true);
  });

  it("重置为 null 后恢复不门禁", () => {
    const store = useWebIdentityStore();
    store.setRole("member");
    store.setRole(null);
    expect(store.role).toBeNull();
    expect(store.isAdmin).toBe(true);
  });
});
