#!/usr/bin/env bash
# Install this checkout's evm-audit-* Skill packages (and, for ZCode, the
# required custom worker agent definitions). Skill packages install as
# managed symlinks; ZCode agent definition files are copied as regular
# files, because ZCode does not register symlinked agent files in
# ~/.zcode/agents.
#
# Usage: ./install.sh [zcode|codex]
#
# With no argument the agent is auto-detected only when exactly one of
# ~/.zcode or ~/.codex exists. The script is idempotent. Installation is
# all-or-nothing: every destination is preflighted first, and any conflict
# (a foreign symlink or a user-modified file) aborts with no mutation.
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

# Skill destinations: <link path> <target path>, installed as managed symlinks.
skill_dests=()
for skill in "$repo_root"/skills/evm-audit-*; do
  [ -d "$skill" ] || continue
  skill_dests+=("$skills_root/$(basename "$skill")" "$skill")
done

# Agent destinations: <copy path> <source path>, installed as regular file
# copies (ZCode only registers real files in its agents directory).
agent_dests=()
if [ "$agent" = "zcode" ]; then
  for name in "${required_agents[@]}"; do
    agent_dests+=("$agents_root/$name.md" "$suite_agents_root/$name.md")
  done
fi

# Preflight: classify every destination before creating anything.
conflicts=()
todo_links=()
todo_copies=()
migrate_copies=()
already=0
i=0
while [ "$i" -lt "${#skill_dests[@]}" ]; do
  link="${skill_dests[$i]}"
  target="${skill_dests[$((i + 1))]}"
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
    todo_links+=("$link" "$target")
  fi
  i=$((i + 2))
done

i=0
while [ "$i" -lt "${#agent_dests[@]}" ]; do
  dest="${agent_dests[$i]}"
  src="${agent_dests[$((i + 1))]}"
  if [ ! -f "$src" ]; then
    echo "error: install source is missing: $src" >&2
    exit 1
  fi
  if [ -L "$dest" ]; then
    if [ "$(readlink "$dest")" = "$src" ]; then
      # Managed symlink from a pre-copy release of this script; agents must
      # be real files, so migrate it in place.
      migrate_copies+=("$dest" "$src")
    else
      conflicts+=("$dest -> $(readlink "$dest") (expected a copy of $src)")
    fi
  elif [ -f "$dest" ]; then
    if cmp -s "$dest" "$src"; then
      already=$((already + 1))
    else
      conflicts+=("$dest exists with different content than $src")
    fi
  elif [ -e "$dest" ]; then
    conflicts+=("$dest exists and is not a regular file")
  else
    todo_copies+=("$dest" "$src")
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

# Apply: link only the missing skills, copy only the missing agents.
mkdir -p "$skills_root"
installed=0
i=0
while [ "$i" -lt "${#todo_links[@]}" ]; do
  link="${todo_links[$i]}"
  target="${todo_links[$((i + 1))]}"
  ln -s "$target" "$link"
  echo "linked: $link"
  installed=$((installed + 1))
  i=$((i + 2))
done
if [ "$agent" = "zcode" ]; then
  mkdir -p "$agents_root"
  i=0
  while [ "$i" -lt "${#todo_copies[@]}" ]; do
    dest="${todo_copies[$i]}"
    src="${todo_copies[$((i + 1))]}"
    cp "$src" "$dest"
    echo "copied: $dest"
    installed=$((installed + 1))
    i=$((i + 2))
  done
  i=0
  while [ "$i" -lt "${#migrate_copies[@]}" ]; do
    dest="${migrate_copies[$i]}"
    src="${migrate_copies[$((i + 1))]}"
    rm "$dest"
    cp "$src" "$dest"
    echo "migrated symlink to copy: $dest"
    installed=$((installed + 1))
    i=$((i + 2))
  done
fi

# Verify: every skill link resolves and every agent copy matches its source.
failed=0
i=0
while [ "$i" -lt "${#skill_dests[@]}" ]; do
  link="${skill_dests[$i]}"
  if [ ! -e "$link" ]; then
    echo "error: $link does not resolve after install" >&2
    failed=1
  fi
  i=$((i + 2))
done
i=0
while [ "$i" -lt "${#agent_dests[@]}" ]; do
  dest="${agent_dests[$i]}"
  src="${agent_dests[$((i + 1))]}"
  if [ ! -f "$dest" ] || ! cmp -s "$dest" "$src"; then
    echo "error: $dest is not a copy of $src after install" >&2
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
  echo "ok: skills available to $agent in $skills_root; worker agents copied to $agents_root"
  echo "note: a new ZCode session is required before custom agent definitions are registered"
else
  echo "ok: skills available to $agent in $skills_root"
fi
