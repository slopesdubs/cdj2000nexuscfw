#!/bin/sh
# Build only the GNU Blackfin objdump used by the stock GUI receiver trace.
set -eu

BINUTILS_VERSION=2.45.1

repo_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
install_dir="$repo_dir/work/toolchain/bfin-elf"
objdump="$install_dir/bin/bfin-elf-objdump"

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

build_root=$(mktemp -d /tmp/cdj-bfin-binutils.XXXXXX)
trap 'rm -rf "$build_root"' EXIT HUP INT TERM
archive="$build_root/binutils.tar.xz"
source_dir="$build_root/binutils-$BINUTILS_VERSION"
build_dir="$build_root/build"

echo "Downloading GNU binutils $BINUTILS_VERSION..."
curl -fL "https://ftp.gnu.org/gnu/binutils/binutils-$BINUTILS_VERSION.tar.xz" \
    -o "$archive"
tar -xJf "$archive" -C "$build_root"
mkdir -p "$build_dir" "$install_dir"

# Configure paths containing spaces are unsafe in generated Makefiles. Install through
# a temporary no-space symlink while leaving the finished toolchain project-local.
ln -s "$repo_dir" "$build_root/workspace"
cd "$build_dir"
"$source_dir/configure" \
    --target=bfin-elf \
    --prefix="$build_root/workspace/work/toolchain/bfin-elf" \
    --disable-nls \
    --disable-werror \
    --disable-gdb \
    --disable-gprofng \
    --disable-gold \
    --disable-ld \
    --disable-gas \
    --disable-sim \
    --with-system-zlib

make all-binutils MAKEINFO=true
make install-binutils MAKEINFO=true
"$objdump" --version | head -1
echo "Installed in $install_dir/bin"
