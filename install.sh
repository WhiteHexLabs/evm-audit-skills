#!/usr/bin/env bash
# Install this checkout's evm-audit-* Skill packages (and, for ZCode, the
# required custom worker agent definitions) via managed symlinks.
#
# Usage: ./install.sh [zcode|codex]
#
# With no argument the agent is auto-detected only when exactly one of
# ~/.zcode or ~/.codex exists. The script is idempotent. Installation is
# all-or-nothing: every destination is preflighted first, and any conflict
# (a foreign symlink or a user-created file) aborts with no mutation.
# ZCode custom agents register at session start, so a new ZCode session is
# required after installation.

set -euo pipefail

usage() {
  echo "usage: $0 [zcode|codex]" >&2
  exit 2
}

agent="${1:-}"
case "$agent" in
  zcode|codex) ;;
  "") ;;
  *) usage ;;
esac

if [ -z "$agent" ]; then
  count=0
  guess=""
  if [ -d "$HOME/.zcode" ]; then
    count=$((count + 1))
    guess="zcode"
  fi
  if [ -d "$HOME/.codex" ]; then
    count=$((count + 1))
    guess="codex"
  fi
  if [ "$count" -ne 1 ]; then
    echo "error: cannot auto-detect the agent; pass 'zcode' or 'codex'" >&2
    exit 2
  fi
  agent="$guess"
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd -P)"
skills_root="$HOME/.$agent/skills"
agents_root="$HOME/.zcode/agents"
suite_agents_root="$repo_root/skills/evm-audit-master/agents"
required_agents=(evm-audit-worker-flash evm-audit-worker-deep evm-audit-worker-proof)

if [ ! -d "$repo_root/skills" ]; then
  echo "error: $repo_root/skills not found; run this script from a checkout of the suite" >&2
  exit 1
fi
if [ "$agent" = "zcode" ] && [ ! -d "$suite_agents_root" ]; then
  echo "error: $suite_agents_root not found; the worker agent templates must ship with the suite" >&2
  exit 1
fi

# Destination pairs: <link path> <target path>
destinations=()
for skill in "$repo_root"/skills/evm-audit-*; do
  [ -d "$skill" ] || continue
  destinations+=("$skills_root/$(basename "$skill")" "$skill")
done
if [ "$agent" = "zcode" ]; then
  for name in "${required_agents[@]}"; do
    destinations+=("$agents_root/$name.md" "$suite_agents_root/$name.md")
  done
fi

# Preflight: classify every destination before creating anything.
conflicts=()
todo=()
already=0
i=0
while [ "$i" -lt "${#destinations[@]}" ]; do
  link="${destinations[$i]}"
  target="${destinations[$((i + 1))]}"
  if [ ! -e "$target" ]; then
    echo "error: install source is missing: $target" >&2
    exit 1
  fi
  if [ -L "$link" ]; then
    if [ "$(readlink "$link")" = "$target" ]; then
      already=$((already + 1))
    else
      conflicts+=("$link -> $(readlink "$link") (expected $target)")
    fi
  elif [ -e "$link" ]; then
    conflicts+=("$link exists and is not a symlink")
  else
    todo+=("$link" "$target")
  fi
  i=$((i + 2))
done

if [ "${#conflicts[@]}" -ne 0 ]; then
  echo "error: refusing to install; resolve these conflicting entries first:" >&2
  for conflict in "${conflicts[@]}"; do
    echo "  $conflict" >&2
  done
  echo "no entries were modified" >&2
  exit 1
fi

# Apply: create only the missing links.
mkdir -p "$skills_root"
if [ "$agent" = "zcode" ]; then
  mkdir -p "$agents_root"
fi
installed=0
i=0
while [ "$i" -lt "${#todo[@]}" ]; do
  link="${todo[$i]}"
  target="${todo[$((i + 1))]}"
  ln -s "$target" "$link"
  echo "linked: $link"
  installed=$((installed + 1))
  i=$((i + 2))
done

# Verify: every destination resolves to this checkout.
failed=0
i=0
while [ "$i" -lt "${#destinations[@]}" ]; do
  link="${destinations[$i]}"
  target="${destinations[$((i + 1))]}"
  if [ ! -e "$link" ]; then
    echo "error: $link does not resolve after install" >&2
    failed=1
  fi
  i=$((i + 2))
done
if [ "$failed" -ne 0 ]; then
  exit 1
fi

if [ "$agent" = "zcode" ]; then
  for name in "${required_agents[@]}"; do
    if ! grep -q "^model:" "$agents_root/$name.md"; then
      echo "error: $agents_root/$name.md is missing its pinned model frontmatter" >&2
      exit 1
    fi
  done
  echo "ok: skills available to $agent in $skills_root; worker agents installed in $agents_root"
  echo "note: a new ZCode session is required before custom agent definitions are registered"
else
  echo "ok: skills available to $agent in $skills_root"
fi
