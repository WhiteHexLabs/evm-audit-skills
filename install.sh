#!/usr/bin/env bash
# Install this checkout's evm-audit-* Skill packages into an agent's skills
# directory via top-level symlinks.
#
# Usage: ./install.sh [zcode|codex]
#
# With no argument the agent is auto-detected only when exactly one of
# ~/.zcode or ~/.codex exists. The script is idempotent: links that already
# point at this checkout are reported and left unchanged, while any existing
# entry that would be replaced is a fail-closed error.

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

if [ ! -d "$repo_root/skills" ]; then
  echo "error: $repo_root/skills not found; run this script from a checkout of the suite" >&2
  exit 1
fi

mkdir -p "$skills_root"

known=0
linked=0
failed=0
for skill in "$repo_root"/skills/evm-audit-*; do
  if [ ! -d "$skill" ]; then
    continue
  fi
  name="$(basename "$skill")"
  link="$skills_root/$name"
  known=$((known + 1))
  if [ -L "$link" ]; then
    if [ "$(readlink "$link")" = "$skill" ]; then
      echo "already linked: $name"
      linked=$((linked + 1))
    else
      echo "error: $link points to $(readlink "$link"), not this checkout" >&2
      failed=$((failed + 1))
    fi
  elif [ -e "$link" ]; then
    echo "error: $link exists and is not a symlink; remove it first" >&2
    failed=$((failed + 1))
  else
    ln -s "$skill" "$link"
    echo "linked: $name"
    linked=$((linked + 1))
  fi
done

if [ "$known" -eq 0 ]; then
  echo "error: no skills/evm-audit-* packages found in $repo_root" >&2
  exit 1
fi

if [ "$failed" -ne 0 ]; then
  echo "error: $failed skill package(s) could not be linked" >&2
  exit 1
fi

for skill in "$repo_root"/skills/evm-audit-*; do
  if [ ! -d "$skill" ]; then
    continue
  fi
  name="$(basename "$skill")"
  if [ ! -f "$skills_root/$name/SKILL.md" ]; then
    echo "error: $skills_root/$name/SKILL.md is missing after install" >&2
    exit 1
  fi
done

echo "ok: $known skill packages available to $agent in $skills_root"
