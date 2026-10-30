#!/usr/bin/env python3
"""dbx-web 多租户隔离冒烟测试

用法:
  export DBX_TRUST_KEY='<与 dbx-web 相同的密钥>'
  python3 scripts/verify-dbx-tenants.py [http://127.0.0.1:4224]

只依赖标准库。逐项打印 PASS/FAIL，退出码非 0 表示有失败项。
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:4224").rstrip("/")
KEY = os.environ.get("DBX_TRUST_KEY", "").encode()
failures: list[str] = []


def sign(
    tenant: str, role: str = "member", act_as: str = "", ts: int | None = None, nonce: str | None = None
) -> dict[str, str]:
    """按生产协议签名：canonical 末尾带一次性 nonce。

    不传 nonce 时随机生成一个。同一租户一秒内可以发多个请求——这正是 nonce 存在的
    原因：旧协议用 (tenant, ts) 做重放键，第二秒内的第二个请求会被误判成重放。
    """
    stamp = str(ts if ts is not None else int(time.time()))
    token = nonce if nonce is not None else uuid.uuid4().hex
    canonical = f"{tenant}\n{role}\n{act_as}\n{stamp}\n{token}"
    digest = hmac.new(KEY, canonical.encode(), hashlib.sha256).digest()
    sig = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    headers = {
        "x-dbx-tenant": tenant,
        "x-dbx-role": role,
        "x-dbx-ts": stamp,
        "x-dbx-sig": sig,
        "x-dbx-nonce": token,
    }
    if act_as:
        headers["x-dbx-act-as"] = act_as
    return headers


def call(method: str, path: str, headers: dict[str, str] | None = None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("content-type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()
    except urllib.error.URLError as exc:
        sys.exit(f"无法连接 {BASE}: {exc}")


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def main() -> None:
    if not KEY:
        sys.exit("DBX_TRUST_KEY 未设置")

    alpha, beta = "u-alpha", "u-beta"

    # 1. 两个不同租户都能正常访问 —— 说明按签名头路由成功
    status_a, _ = call("GET", "/api/connection/list", sign(alpha))
    status_b, _ = call("GET", "/api/connection/list", sign(beta))
    check("租户 A 可访问", status_a == 200, f"status={status_a}")
    check("租户 B 可访问", status_b == 200, f"status={status_b}")

    # 2. 不带身份头必须被拒（浏览器直连不能冒充）
    status, _ = call("GET", "/api/connection/list")
    check("无身份头被拒", status == 401, f"status={status}")

    # 3. 签名错误必须被拒
    bad = sign(alpha)
    bad["x-dbx-sig"] = "A" * 43
    status, _ = call("GET", "/api/connection/list", bad)
    check("错误签名被拒", status == 401, f"status={status}")

    # 4. 重放必须被拒：同一组头连用两次，第二次应为 401
    replay = sign(alpha)
    call("GET", "/api/connection/list", replay)
    status, _ = call("GET", "/api/connection/list", replay)
    check("重放被拒", status == 401, f"status={status}")

    # 5. 时间戳超出 ±60s 必须被拒（用旧时间戳正确签名，排除"签名错"这一干扰因素）
    stale = sign(alpha, ts=int(time.time()) - 600)
    status, _ = call("GET", "/api/connection/list", stale)
    check("过期时间戳被拒", status == 401, f"status={status}")

    # 6. 普通用户不能操作全局模块，管理员可以
    status, _ = call("GET", "/api/system/fonts", sign(alpha, role="member"))
    check("member 访问 /api/system 被拒", status == 403, f"status={status}")
    status, _ = call("GET", "/api/system/fonts", sign(alpha, role="admin"))
    check("admin 访问 /api/system 放行", status == 200, f"status={status}")

    # 7. 驱动/插件属于管理面：读接口要留给普通用户（连接对话框靠它判断驱动装没装），
    #    写接口只有管理员能过。用 update-blockers 验证 admin 侧放行，避免真的去下载驱动。
    status, _ = call("GET", "/api/agents/installed", sign(alpha, role="member"))
    check("member 可读已安装驱动", status == 200, f"status={status}")
    status, _ = call("GET", "/api/jdbc/drivers", sign(alpha, role="member"))
    check("member 可读 JDBC 驱动列表", status == 200, f"status={status}")
    status, _ = call("POST", "/api/agents/install", sign(alpha, role="member"), {"dbType": "oracle"})
    check("member 安装驱动被拒", status == 403, f"status={status}")
    status, _ = call("POST", "/api/jdbc/drivers/maven", sign(alpha, role="member"), {})
    check("member 用 Maven 装 JDBC 驱动被拒", status == 403, f"status={status}")
    status, _ = call("POST", "/api/agents/update-blockers", sign(alpha, role="admin"), {})
    check("admin 的驱动写接口不被角色门禁拦截", status != 403, f"status={status}")

    # 8. 非法租户 id 必须被拒（防止路径穿越）
    status, _ = call("GET", "/api/connection/list", sign("../etc"))
    check("非法租户 id 被拒", status == 400, f"status={status}")

    print()
    if failures:
        print(f"{len(failures)} 项失败: {', '.join(failures)}")
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
