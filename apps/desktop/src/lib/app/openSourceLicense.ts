// 仓库根目录的 LICENSE / NOTICE 全文。直接 import 原始文件（Vite `?raw`）而不是在
// 源码里维护第二份副本：About 页展示的文本永远等于项目实际分发的许可证与归属声明，
// 无需网络请求，也不会出现两份文本各自漂移。
import licenseText from "../../../../../LICENSE?raw";
import noticeText from "../../../../../NOTICE?raw";

/** Apache License 2.0 全文，去掉文件首尾空行后直接渲染。 */
export const OPEN_SOURCE_LICENSE_TEXT = licenseText.trim();

/** 随附的第三方归属声明（NOTICE），去掉文件首尾空行后直接渲染。 */
export const OPEN_SOURCE_NOTICE_TEXT = noticeText.trim();
