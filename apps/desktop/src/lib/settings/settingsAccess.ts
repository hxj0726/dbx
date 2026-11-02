import type { SettingsCategory } from "@/lib/settings/settingsSearch";

/** 非管理员打开受限分类时统一回落到外观页，保证设置页总有内容可渲染。 */
const FALLBACK_SETTINGS_CATEGORY: SettingsCategory = "appearance";

/**
 * 仅管理员可打开的设置分类。
 *
 * 导航栏已经按角色隐藏这些分类，但打开设置页的入口不止导航栏（工具栏、更新角标、
 * 快捷键、启动事件等都可能直接传 initialTab），所以这里必须再兜一层。
 *
 * 集合声明成 `ReadonlySet<string>` 是为了让调用方直接传 string、不必写类型断言；
 * 构造时仍标注 `SettingsCategory`，分类被改名/删除时这里会编译报错。
 */
const ADMIN_ONLY_SETTINGS_CATEGORIES: ReadonlySet<string> = new Set<SettingsCategory>(["mcp"]);

/** 当前角色是否可以打开指定设置分类。 */
export function canOpenSettingsCategory(category: string, isAdmin: boolean): boolean {
  return isAdmin || !ADMIN_ONLY_SETTINGS_CATEGORIES.has(category);
}

/** 把当前角色不能打开的分类替换成外观页，避免出现“导航里没有、内容却渲染”的空档。 */
export function sanitizeSettingsCategoryForRole(category: string, isAdmin: boolean): string {
  return canOpenSettingsCategory(category, isAdmin) ? category : FALLBACK_SETTINGS_CATEGORY;
}
