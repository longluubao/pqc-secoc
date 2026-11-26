#!/usr/bin/env bash
# bench/stamp_commit.sh
#
# Write the commit of this checkout to bench/COMMIT ("-dirty" appended when Autosar_SecOC has
# uncommitted or untracked files). Run it right before the tree is copied to a Pi: the Pi copy
# has no .git, bench/CMakeLists.txt reads the stamp from this file, and it is the <commit>
# argument for scripts/capture_env.sh.
set -euo pipefail
TREE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(git -C "${TREE}" rev-parse HEAD)"
[[ -z "$(git -C "${TREE}" status --porcelain -- .)" ]] || STAMP="${STAMP}-dirty"
echo "${STAMP}" | tee "${TREE}/bench/COMMIT"
