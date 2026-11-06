#!/bin/sh
# Muse-Link client installer (sketch, MVP).
# Idempotent: copies the client into ~/.local/bin and the Muse pack
# (SKILL.md, CONNECTOR.md, INSTRUCTIONS.md) into the connector directory. It does NOT
# register the agent: enrollment needs a bootstrap token issued by the
# relay operator (`link bootstrap`) and the identity JSON the agent
# composes from it. No key material is created or moved by this script;
# keys are generated locally by `muse-link register` on first use.
set -eu

SRC_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_DIR="${HOME}/.local/bin"
PACK_DIR="${HOME}/workspace/custom-connectors/custom.muse-link"

mkdir -p "$BIN_DIR" "$PACK_DIR/bin" "$PACK_DIR/common"
# muse_link.py loads ../common relative to its own path, which only
# resolves inside the pack layout, so the bin entry point is a wrapper
# that runs the pack copy.
printf '#!/bin/sh\nexec python3 "%s/bin/muse_link.py" "$@"\n' "$PACK_DIR" > "$BIN_DIR/muse-link"
chmod +x "$BIN_DIR/muse-link"
cp "$SRC_DIR/muse_link.py" "$PACK_DIR/bin/muse_link.py"
cp "$SRC_DIR/../common/gpgutil.py" "$PACK_DIR/common/gpgutil.py"
cp "$SRC_DIR/muse/SKILL.md" "$PACK_DIR/SKILL.md"
cp "$SRC_DIR/muse/CONNECTOR.md" "$PACK_DIR/CONNECTOR.md"
if [ -f "$SRC_DIR/muse/INSTRUCTIONS.md" ]; then
  cp "$SRC_DIR/muse/INSTRUCTIONS.md" "$PACK_DIR/INSTRUCTIONS.md"
fi

echo "Installed: $BIN_DIR/muse-link"
echo "Muse pack: $PACK_DIR (SKILL.md, CONNECTOR.md, INSTRUCTIONS.md, bin/)"
echo "Next: get a bootstrap token from the relay operator, compose your"
echo "identity JSON, then run: muse-link register --bootstrap-json <path>"
