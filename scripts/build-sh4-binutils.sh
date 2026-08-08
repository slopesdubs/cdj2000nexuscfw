#!/bin/sh
# Build only the little-endian sh-elf GNU binutils used by the static trace.
set -eu

KOS_COMMIT=6cfcd74010fe6928431a233db399c5a28317ecf0
BINUTILS_VERSION=2.45.1

repo_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
install_dir="$repo_dir/work/toolchain/sh-elf"
objdump="$install_dir/bin/sh-elf-objdump"

if [ -x "$objdump" ]; then
    installed_version=$("$objdump" --version | head -1)
    case "$installed_version" in
        *"$BINUTILS_VERSION"*)
            echo "$installed_version"
            echo "Already installed in $install_dir/bin"
            exit 0
            ;;
    esac
fi

for command_name in curl make tar; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "error: required command is missing: $command_name" >&2
        exit 2
    fi
done

build_root=$(mktemp -d /tmp/cdj-sh4-binutils.XXXXXX)
trap 'rm -rf "$build_root"' EXIT HUP INT TERM
mkdir -p "$build_root/kos" "$install_dir"

echo "Downloading pinned KallistiOS kos-chain source ($KOS_COMMIT)..."
source_archive="$build_root/kallistikos.tar.gz"
curl -fL "https://github.com/KallistiOS/KallistiOS/archive/$KOS_COMMIT.tar.gz" \
    -o "$source_archive"
tar -xzf "$source_archive" -C "$build_root/kos" --strip-components=1

# kos-chain expands its configure command without shell-quoting the prefix.  Use a
# temporary no-space symlink so this repository's directory name remains harmless.
ln -s "$repo_dir" "$build_root/workspace"
cp -R "$build_root/kos/utils/kos-chain" "$build_root/chain"
cd "$build_root/chain"
cp Makefile.dreamcast.cfg Makefile.cfg
{
    printf '\n# Project-local overrides for the CDJ static-analysis toolchain.\n'
    printf 'toolchain_profile=stable\n'
    printf 'toolchain_path=%s\n' "$build_root/workspace/work/toolchain/sh-elf"
    printf 'erase=0\n'
    printf 'verbose=0\n'
} >> Makefile.cfg

echo "Building sh-elf binutils $BINUTILS_VERSION (no GCC, Newlib, or ARM toolchain)..."
if ! make build-binutils; then
    build_dir="build-binutils-sh-elf-$BINUTILS_VERSION"
    if [ ! -f "$build_dir/Makefile" ]; then
        echo "error: kos-chain failed before configuring $build_dir" >&2
        exit 2
    fi
    echo "Retrying the configured build with generated manuals disabled..."
    make -C "$build_dir" MAKEINFO=true
    make -C "$build_dir" install MAKEINFO=true
fi

"$objdump" --version | head -1
echo "Installed in $install_dir/bin"
