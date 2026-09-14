#!/usr/bin/env bash
# worktree.sh — 并行开发工作树管理（开源仓库群标准工具）
#
# 约定：
#   - 工作树放在仓库平级目录 ../<repo>-worktrees/<name>/，不进仓库本体
#   - 分支命名 wt/<name>；主分支 main
#   - 并发软上限 10 个工作树；超过需 FORCE=1
#   - 合并回 main 前必须：check 绿（脱敏门禁）+ 本地测试绿
#   - 迁移主仓库目录后（如换父目录/换机器同步），先跑 git worktree repair
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
REPO_NAME="$(basename "$REPO_ROOT")"
WT_ROOT="${REPO_ROOT%/*}/${REPO_NAME}-worktrees"
MAIN_BRANCH="main"
MAX_CONCURRENT=10

# 开源卫生：合并/公开前禁止出现的敏感串（在此数组扩展；同步另一仓库的副本）
SENSITIVE_PATTERNS=(
  "dyyz""1993"      # 生产域名（拼接书写：文件内不得出现完整真串）
  "9ca""8f39"       # 测试设备 serial
  "WXS""YD"         # 测试设备 serial
  "/Use""rs/"       # 本机绝对路径（拼接书写）
)

# 豁免表（当前为空：pattern 拼接书写后门禁文件自身不再含完整真串）
EXEMPT_FILES=(
)

is_exempt() {
  local f="$1" e
  for e in ${EXEMPT_FILES[@]+"${EXEMPT_FILES[@]}"}; do [ "$f" = "$e" ] && return 0; done
  return 1
}

die()  { echo "✗ $*" >&2; exit 1; }
info() { echo "→ $*"; }

slot_count() {
  local total
  total="$(git worktree list --porcelain | grep -c '^worktree ' || true)"
  echo $(( ${total:-1} - 1 ))
}

cmd_new() {
  [ $# -eq 1 ] || die "用法: $0 new <name>"
  local name="$1" branch="wt/$1" path="$WT_ROOT/$1"
  [ -e "$path" ] && die "路径已存在: $path"
  git show-ref --verify --quiet "refs/heads/$branch" && die "分支已存在: $branch"
  local slots; slots="$(slot_count)"
  if [ "$slots" -ge "$MAX_CONCURRENT" ] && [ "${FORCE:-0}" != "1" ]; then
    die "并发工作树已达上限 ${MAX_CONCURRENT}（当前 ${slots}）。确需更多: FORCE=1 $0 new $name"
  fi
  mkdir -p "$WT_ROOT"
  git worktree add -b "$branch" "$path" "$MAIN_BRANCH"
  info "已创建: ${path}（分支 ${branch}，基于 ${MAIN_BRANCH}）"
  info "完成后: 在工作树内开发+测试+check，然后回主仓库 merge wt/$name"
}

cmd_list() {
  printf "%-52s %-24s %s\n" "PATH" "BRANCH" "STATUS"
  local path branch st
  git worktree list --porcelain | awk '/^worktree /{print $2} /^branch /{sub(/^refs\/heads\//,"",$2); print "  " $2}' \
  | while true; do
      read -r path || break
      read -r branch || break
      if [ -n "$(git -C "$path" status --porcelain 2>/dev/null)" ]; then st="dirty"; else st="clean"; fi
      printf "%-52s %-24s %s\n" "$path" "$branch" "$st"
    done
  echo "并发槽位: $(slot_count)/$MAX_CONCURRENT"
}

# 脱敏门禁：扫描当前目录（已跟踪 + 未忽略的未跟踪文件）中的敏感串；豁免表内文件不扫
cmd_check() {
  local fail=0 pattern hits f
  local excludes=()
  local e
  for e in ${EXEMPT_FILES[@]+"${EXEMPT_FILES[@]}"}; do excludes+=( ":(exclude)$e" ); done
  for pattern in "${SENSITIVE_PATTERNS[@]}"; do
    hits=""
    hits="$(git grep -I -l -F -- "$pattern" -- . ${excludes[@]+"${excludes[@]}"} 2>/dev/null || true)"
    while IFS= read -r f; do
      is_exempt "$f" && continue
      grep -q -I -F -- "$pattern" "$f" 2>/dev/null && hits="$hits
$f"
    done < <(git ls-files --others --exclude-standard)
    if [ -n "$hits" ]; then
      echo "✗ 敏感串命中 [$pattern]:" >&2
      printf '  %s\n' $hits >&2
      fail=1
    fi
  done
  [ "$fail" -eq 0 ] && info "check 通过：无敏感串，可合并/公开" || die "check 未通过：先清理上述文件"
}

cmd_rm() {
  [ $# -eq 1 ] || die "用法: $0 rm <name>"
  local name="$1" path="$WT_ROOT/$1" branch="wt/$1"
  [ -d "$path" ] || die "工作树不存在: $path"
  [ -n "$(git -C "$path" status --porcelain 2>/dev/null)" ] && die "有未提交改动，先提交或 stash: $path"
  git worktree remove "$path"
  git show-ref --verify --quiet "refs/heads/$branch" && git branch -D "$branch"
  info "已删除: ${path}（分支 ${branch}）"
}

cmd_prune() {
  git worktree prune
  info "已清理失效引用（孤儿目录请手动删除）"
}

case "${1:-}" in
  new)    shift; cmd_new "$@" ;;
  list)   cmd_list ;;
  check)  shift; cmd_check "$@" ;;
  rm)     shift; cmd_rm "$@" ;;
  prune)  cmd_prune ;;
  *) cat <<EOF
用法: $0 <命令> [参数]
  new <name>    从 $MAIN_BRANCH 创建工作树（分支 wt/<name>，路径 ../${REPO_NAME}-worktrees/<name>）
  list          列出工作树与状态、并发槽位
  check         脱敏门禁：扫描当前目录敏感串（合并/公开前必跑）
  rm <name>     删除工作树与分支（拒绝有未提交改动的）
  prune         清理失效的工作树引用
EOF
     exit 1 ;;
esac
