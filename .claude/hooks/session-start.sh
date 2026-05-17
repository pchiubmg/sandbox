#!/bin/bash
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

echo "== Installing Ruby gems =="
bundle config set --local path 'vendor/bundle'
bundle install --jobs=4

echo "== Preparing databases =="
bundle exec ruby bin/rails db:prepare
