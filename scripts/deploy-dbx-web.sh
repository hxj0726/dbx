#!/usr/bin/env bash
# dbx-web 部署 / 回滚脚本
#
# 把 GitHub Actions 产出的 browser-static 包（静态 musl 二进制，前端已内嵌在
# 二进制里）换成正在跑的服务，启动失败自动回滚。
#
# 用法（在服务器上，root 或 sudo）：
#   sudo ./deploy-dbx-web.sh /tmp/DBX_0.6.61_x64-browser-static.tar.gz
#   sudo ./deploy-dbx-web.sh --rollback              # 回到上一次部署前的版本
#   sudo ./deploy-dbx-web.sh --list-tenants          # 看各租户现有驱动目录大小
#   sudo ./deploy-dbx-web.sh --adopt <租户uuid>      # 把某租户的驱动搬进共享目录
#
# 默认值都按本机现状，可用环境变量覆盖：
#   UNIT=dbx.service
#   INSTALL_DIR=/opt/hxj/dbx-linux-x64-browser-static
#   SERVICE_USER=<自动探测 unit 的 User=，未设置按 root>
#   DATA_DIR=<自动探测：进程里的 DBX_DATA_DIR → /var/lib/dbx → 安装目录/data>
#   AGENT_DIR=<自动：$DATA_DIR/shared/agents>
#   PORT=4224  BASE_PATH=/dbx
#   BACKUP_KEEP=3
#
set -euo pipefail

UNIT="${UNIT:-dbx.service}"
INSTALL_DIR="${INSTALL_DIR:-/opt/hxj/dbx-linux-x64-browser-static}"
SERVICE_USER="${SERVICE_USER:-}"      # 空=自动探测 unit 的 User=
SERVICE_GROUP="${SERVICE_GROUP:-}"    # 空=用户主组
DATA_DIR="${DATA_DIR:-}"
AGENT_DIR="${AGENT_DIR:-}"
PORT="${PORT:-4224}"
BASE_PATH="${BASE_PATH:-/dbx}"
BACKUP_KEEP="${BACKUP_KEEP:-3}"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  # 帮助文本就是文件头的注释块：结束位置按"第一行非注释"自动算，
  # 以后改头部注释不用再同步这里写死的行号。
  local last_comment
  last_comment=$(( $(grep -n -m1 -v '^#' "$0" | cut -d: -f1) - 1 ))
  sed -n "2,${last_comment}p" "$0" | sed 's/^# \{0,1\}//'
}

# 服务以哪个用户跑？不猜，直接读 unit 的 User=/Group=（系统级 unit 为空即 root）
resolve_unit_user() {
  if [ -z "$SERVICE_USER" ]; then
    SERVICE_USER="$(systemctl show -p User --value "$UNIT" 2>/dev/null || true)"
    SERVICE_USER="${SERVICE_USER:-root}"
  fi
  if [ -z "$SERVICE_GROUP" ]; then
    SERVICE_GROUP="$(systemctl show -p Group --value "$UNIT" 2>/dev/null || true)"
    [ -n "$SERVICE_GROUP" ] || SERVICE_GROUP="$(id -gn "$SERVICE_USER" 2>/dev/null || printf 'root')"
  fi
  id "$SERVICE_USER" >/dev/null 2>&1 || die "用户 $SERVICE_USER 不存在（可用 SERVICE_USER=xxx 指定）"
}

need_root() {
  [ "$(id -u)" -eq 0 ] || die "请用 root 或 sudo 运行"
  command -v systemctl >/dev/null || die "找不到 systemctl"
  command -v curl >/dev/null || die "找不到 curl（apt install curl）"
  command -v tar >/dev/null || die "找不到 tar"
  systemctl cat "$UNIT" >/dev/null 2>&1 || die "找不到 systemd 单元 $UNIT（可用 UNIT=xxx 指定）"
  resolve_unit_user
  log "服务用户: $SERVICE_USER:$SERVICE_GROUP"
}

# 正在运行的 dbx-web 进程 pid；没装或没跑时输出空
running_dbx_pid() {
  pgrep -f 'dbx-web-bin' | head -1 || true
}

# 读进程真实的环境变量（/proc/<pid>/environ 是 \0 分隔）
process_environ() {
  tr '\0' '\n' < "/proc/$1/environ"
}

# 从进程环境里取单个变量的值；变量未设置时输出空
process_env_value() {
  process_environ "$1" | sed -n "s/^$2=//p" | head -1
}

# 服务实际用的数据目录：优先读进程里的 DBX_DATA_DIR，避免脚本猜错
resolve_dirs() {
  if [ -z "$DATA_DIR" ]; then
    local pid running_data=""
    pid="$(running_dbx_pid)"
    if [ -n "$pid" ] && [ -r "/proc/$pid/environ" ]; then
      running_data="$(process_env_value "$pid" DBX_DATA_DIR)"
    fi
    if [ -n "$running_data" ]; then
      DATA_DIR="$running_data"
    elif [ -d /var/lib/dbx ]; then
      DATA_DIR=/var/lib/dbx
    else
      DATA_DIR="$INSTALL_DIR/data"
    fi
  fi
  [ -n "$AGENT_DIR" ] || AGENT_DIR="$DATA_DIR/shared/agents"
}

# unit 里写死的启动路径如果不是 INSTALL_DIR，说明参数猜错了，直接停手
check_install_dir() {
  local unit_exec detected dir
  unit_exec="$(systemctl show -p ExecStart --value "$UNIT" 2>/dev/null || true)"
  detected="$(printf '%s' "$unit_exec" | tr ' ' '\n' | sed -n 's/^path=//p' | head -1)"
  [ -n "$detected" ] || return 0
  dir="$(dirname "$detected")"
  case "$dir" in
    # ExecStart 走 shell wrapper 的情况，目录还是按 INSTALL_DIR 用
    /bin|/usr/bin|/usr/local/bin|/sbin|/usr/sbin|/bin/sh|/bin/bash)
      warn "unit 通过 $detected 启动，按 INSTALL_DIR=$INSTALL_DIR 继续"
      return 0 ;;
  esac
  if [ "$dir" != "$INSTALL_DIR" ] && [ "$dir" != "$INSTALL_DIR/bin" ]; then
    die "unit 的启动路径是 $detected，与 INSTALL_DIR=$INSTALL_DIR 不一致；请用 INSTALL_DIR=... 指定正确目录"
  fi
}

verify_checksum() {
  local pkg="$1"
  if [ -f "$pkg.sha256" ]; then
    command -v sha256sum >/dev/null || die "找不到 sha256sum（apt install coreutils）"
    log "校验 sha256"
    ( cd "$(dirname "$pkg")" && sha256sum -c "$(basename "$pkg").sha256" >/dev/null ) || die "sha256 校验失败"
  else
    warn "没有找到 $pkg.sha256，跳过校验"
  fi
}

# 共享驱动目录 + systemd drop-in。多租户下这一步不做，管理员装的驱动就只有管理员自己能用。
ensure_agent_dir() {
  if [ ! -d "$AGENT_DIR" ]; then
    log "创建共享驱动目录 $AGENT_DIR"
    install -d -m 0755 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$AGENT_DIR"
  fi
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$AGENT_DIR"

  local dropin="/etc/systemd/system/${UNIT}.d/10-agent-dir.conf"
  local want
  want="$(printf '[Service]\nEnvironment=DBX_AGENT_DIR=%s\n' "$AGENT_DIR")"
  if [ ! -f "$dropin" ] || ! printf '%s' "$want" | diff -q - "$dropin" >/dev/null 2>&1; then
    log "写入 systemd drop-in: $dropin"
    install -d -m 0755 "$(dirname "$dropin")"
    printf '%s' "$want" > "$dropin"
    systemctl daemon-reload
  else
    log "systemd drop-in 已是最新: $dropin"
  fi
}

health_url() { printf 'http://127.0.0.1:%s%s/' "$PORT" "${BASE_PATH%/}"; }

wait_healthy() {
  local url deadline code
  url="$(health_url)"
  deadline=$((SECONDS + 60))
  log "等待服务就绪: $url"
  while [ "$SECONDS" -lt "$deadline" ]; do
    if systemctl is-active --quiet "$UNIT"; then
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" || true)"
      case "$code" in
        2*|3*|401|403) log "健康检查通过（HTTP $code）"; return 0 ;;
      esac
    fi
    sleep 2
  done
  return 1
}

# 打印进程真实的环境变量：环境变量没生效时最容易在这里看出来
verify_runtime() {
  local pid envs
  pid="$(running_dbx_pid)"
  [ -n "$pid" ] || die "没找到 dbx-web 进程，检查 journalctl -u $UNIT"
  envs="$(process_environ "$pid")"
  log "运行进程 pid=$pid"
  printf '%s\n' "$envs" | grep -E '^(DBX_AGENT_DIR|DBX_DATA_DIR|DBX_PUBLIC_BASE_PATH|DBX_TRUST_PROXY|DBX_PORT)=' | sed 's/^/    /' || true

  journalctl -u "$UNIT" -n 40 --no-pager 2>/dev/null | grep -E '租户驱动目录|DBX_AGENT_DIR' | sed 's/^/    /' || true

  if ! printf '%s\n' "$envs" | grep -qx "DBX_AGENT_DIR=$AGENT_DIR"; then
    warn "进程环境里没有 DBX_AGENT_DIR=$AGENT_DIR —— 驱动目录仍是按租户隔离的"
    warn "常见原因：unit 用 EnvironmentFile 又把它覆盖了，或 drop-in 目录名不对（$(systemctl show -p DropInPaths --value "$UNIT")）"
    exit 2
  fi
}

# 只保留最近 BACKUP_KEEP 份备份（目录名带时间戳，sort 后越靠前越旧）
prune_backups() {
  local list count keep idx path
  list="$(ls -1d "${INSTALL_DIR}".bak.* 2>/dev/null | sort || true)"
  [ -n "$list" ] || return 0
  count="$(printf '%s\n' "$list" | wc -l | tr -d ' ')"
  keep=$((count - BACKUP_KEEP))
  idx=0
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if [ "$idx" -lt "$keep" ]; then
      log "清理旧备份 $path"
      rm -rf -- "$path"
    fi
    idx=$((idx + 1))
  done <<< "$list"
}

# 复制目录树 $1 → $2，其余参数原样交给 tar 作为排除项（不依赖 cp -a，跨文件系统也可用）
copy_tree() {
  local src="$1" dst="$2"
  shift 2
  mkdir -p "$dst"
  ( cd "$src" && tar -cf - "$@" . ) | ( cd "$dst" && tar -xf - )
}

deploy() {
  local pkg="${1:-}"
  [ -n "$pkg" ] || { usage; exit 2; }
  [ -f "$pkg" ] || die "找不到安装包: $pkg"

  need_root
  resolve_dirs
  check_install_dir
  verify_checksum "$pkg"

  local work src bin
  work="$(mktemp -d)"
  log "解包到 $work"
  tar -xzf "$pkg" -C "$work"
  src="$(find "$work" -maxdepth 1 -mindepth 1 -type d | head -1)"
  [ -n "$src" ] || die "安装包内没有顶层目录"
  bin="$src/bin/dbx-web-bin"
  [ -f "$bin" ] || die "安装包内缺少 bin/dbx-web-bin"
  if command -v file >/dev/null 2>&1; then
    file "$bin" | grep -Eq 'statically linked|static-pie' || die "bin/dbx-web-bin 不是静态链接，包不对"
  fi
  log "包内版本: $(basename "$src")"

  log "停止 $UNIT"
  systemctl stop "$UNIT"

  local backup="${INSTALL_DIR}.bak.$(date +%Y%m%d-%H%M%S)"
  log "备份当前版本 → $backup（不含 data/）"
  copy_tree "$INSTALL_DIR" "$backup" --exclude=./data

  log "写入新版本（保留 data/ 和服务器上改造过的 dbx 启动脚本）"
  copy_tree "$src" "$INSTALL_DIR" --exclude=./data --exclude=./dbx
  mkdir -p "$INSTALL_DIR/bin"
  install -m 0755 "$bin" "$INSTALL_DIR/bin/dbx-web-bin"
  if [ -f "$src/dbx" ] && ! cmp -s "$src/dbx" "$INSTALL_DIR/dbx"; then
    install -m 0755 "$src/dbx" "$INSTALL_DIR/dbx.new"
    warn "新包的启动脚本与服务器上的不同，已另存为 dbx.new（确认后再替换 dbx）"
  fi
  [ -e "$INSTALL_DIR/dbx-web" ] || ln -sfn dbx "$INSTALL_DIR/dbx-web"
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"

  ensure_agent_dir

  log "启动 $UNIT"
  if ! systemctl start "$UNIT" || ! wait_healthy; then
    warn "健康检查失败，自动回滚"
    journalctl -u "$UNIT" -n 60 --no-pager 2>/dev/null || true
    systemctl stop "$UNIT" || true
    copy_tree "$backup" "$INSTALL_DIR"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    systemctl start "$UNIT" || true
    rm -rf "$work"
    die "已回滚到部署前的版本，请把上面的日志贴给我"
  fi

  rm -rf "$work"
  prune_backups
  verify_runtime

  cat <<EOF

下一步（脚本不会替你做，因为要用浏览器/管理员账号）：
  1) 用管理员账号登录 → 驱动管理 → 重新安装需要的驱动和 JRE
     （共享目录 $AGENT_DIR 现在是空的，旧驱动还留在各租户目录里）
     不想重新下载就先搬过来一次：
       sudo $0 --adopt <管理员账号对应的租户 uuid>
  2) 用普通用户账号验收：工具栏不再有「驱动管理」「插件中心」，设置-更新页没有驱动卡片
  3) 验签接口（在仓库目录下执行）：
       DBX_TRUST_KEY=<与服务端一致> python3 scripts/verify-dbx-tenants.py http://127.0.0.1:$PORT
  4) 数据目录 $DATA_DIR 下的旧 agents 目录确认没用了再删：du -sh $DATA_DIR/*/agents
EOF
}

rollback() {
  local latest
  need_root
  resolve_dirs
  latest="$(ls -1d "${INSTALL_DIR}".bak.* 2>/dev/null | sort | tail -1 || true)"
  [ -n "$latest" ] || die "没有可用的备份（${INSTALL_DIR}.bak.*）"
  log "回滚到 $latest"
  systemctl stop "$UNIT"
  copy_tree "$latest" "$INSTALL_DIR"
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
  systemctl daemon-reload
  systemctl start "$UNIT" || die "回滚后无法启动，检查 journalctl -u $UNIT"
  wait_healthy || die "回滚后仍不健康，检查 journalctl -u $UNIT"
  verify_runtime || true
  log "回滚完成"
}

list_tenants() {
  resolve_dirs
  log "数据目录: $DATA_DIR"
  log "共享驱动目录: $AGENT_DIR"
  local found=0
  for dir in "$DATA_DIR"/*/agents; do
    [ -d "$dir" ] || continue
    found=1
    printf '    %-50s %s\n' "$dir" "$(du -sh "$dir" 2>/dev/null | cut -f1)"
  done
  [ "$found" -eq 1 ] || printf '    (没有按租户隔离的 agents 目录)\n'
}

adopt() {
  local tenant="${1:-}"
  [ -n "$tenant" ] || die "用法: $0 --adopt <租户uuid>（用 --list-tenants 看有哪些）"
  need_root
  resolve_dirs
  local src="$DATA_DIR/$tenant/agents"
  [ -d "$src" ] || die "找不到 $src"
  ensure_agent_dir
  if [ -n "$(ls -A "$AGENT_DIR" 2>/dev/null || true)" ]; then
    die "$AGENT_DIR 非空；确认要覆盖就先清空它（里面有驱动状态，别乱删，先备份）"
  fi
  log "把 $src 搬进 $AGENT_DIR"
  copy_tree "$src" "$AGENT_DIR"
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$AGENT_DIR"
  systemctl restart "$UNIT"
  wait_healthy || die "服务没起来，检查 journalctl -u $UNIT"
  verify_runtime
  log "完成：现在所有租户共用这份驱动"
}

main() {
  case "${1:-}" in
    ""|-h|--help) usage; exit 0 ;;
    --rollback) shift; rollback ;;
    --list-tenants) shift; list_tenants ;;
    --adopt) shift; adopt "${1:-}" ;;
    -*) die "未知参数: $1（试试 --help）" ;;
    *) deploy "$1" ;;
  esac
}

main "$@"
