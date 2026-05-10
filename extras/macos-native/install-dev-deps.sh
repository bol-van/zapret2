#!/bin/sh
set -eu

[ "$(uname)" = "Darwin" ] || {
  echo "error: this helper is macOS-only" >&2
  exit 1
}

for prefix in /opt/homebrew /usr/local; do
  if [ -x "$prefix/bin/brew" ]; then
    PATH="$prefix/bin:$PATH"
    export PATH
    break
  fi
done

if ! command -v brew >/dev/null 2>&1; then
  cat >&2 <<'EOF'
error: Homebrew is required to install native development dependencies automatically.

Install Homebrew first from a regular Terminal window:
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

Then rerun:
  extras/macos-native/install-dev-deps.sh
EOF
  exit 1
fi

brew install pkg-config lua

cat <<'EOF'

Development dependencies installed.

Next checks:
  extras/macos-native/doctor.sh
  make -C nfq2 bsd

EOF
