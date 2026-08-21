#!/bin/sh
# Install pindrop from GitHub Releases.
#
# Downloads the release tarball for this OS/architecture, verifies it against the
# SHA-256 checksums.txt published alongside the release, and installs the binary.
# Scanner binaries are not included — run `pindrop setup` after install.
#
# Archive names must match .goreleaser.yaml archives.name_template:
#   pindrop_{version}_{os}_{arch}.tar.gz
#
# Usage:
#   curl -sfL https://raw.githubusercontent.com/AnimeshRy/pindrop/main/scripts/install.sh | sh
#   curl -sfL ... | sh -s -- -b ~/.local/bin v0.1.0
#
# Options:
#   -b BINDIR   install directory (default: $HOME/.local/bin)
#   -d          debug logging to stderr
#   [tag]       release tag, e.g. v0.1.0 (default: latest)

set -e

OWNER=AnimeshRy
REPO=pindrop
GITHUB=https://github.com
GITHUB_API=https://api.github.com
RELEASES_PAGE="${GITHUB}/${OWNER}/${REPO}/releases"

# Default install location: no sudo required on Ubuntu/Debian.
BINDIR="${HOME}/.local/bin"
DEBUG=0
REQUESTED_TAG=""

usage() {
	cat <<EOF
install pindrop from GitHub Releases

Usage: $0 [-b bindir] [-d] [tag]

  -b bindir   directory to install into (default: \$HOME/.local/bin)
  -d          print debug messages to stderr
  tag         release tag such as v0.1.0 (default: latest)

Each download is verified against checksums.txt from the same release.
There is no option to skip verification.

Examples:
  $0
  $0 -b /usr/local/bin v0.1.0
  BINDIR=\$HOME/bin $0
EOF
}

log() {
	if [ "$DEBUG" -eq 1 ]; then
		echo "$@" 1>&2
	fi
}

fail() {
	echo "install.sh: $*" 1>&2
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

# --- argument parsing ---

while [ $# -gt 0 ]; do
	case "$1" in
	-b)
		[ $# -ge 2 ] || fail "missing argument to -b"
		BINDIR=$2
		shift 2
		;;
	-d)
		DEBUG=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	-v* | v*)
		REQUESTED_TAG=$1
		shift
		;;
	-*)
		fail "unknown option: $1 (try --help)"
		;;
	*)
		REQUESTED_TAG=$1
		shift
		;;
	esac
done

# --- platform detection ---

uname_os() {
	os=$(uname -s | tr '[:upper:]' '[:lower:]')
	case "$os" in
	cygwin_nt* | mingw* | msys_nt*) os=windows ;;
	esac
	echo "$os"
}

uname_arch() {
	arch=$(uname -m)
	case "$arch" in
	x86_64) arch=amd64 ;;
	aarch64) arch=arm64 ;;
	esac
	echo "$arch"
}

OS=$(uname_os)
ARCH=$(uname_arch)

case "$OS" in
linux | darwin) ;;
windows)
	fail "Windows is not supported by this script.
  Download a release manually: ${RELEASES_PAGE}/latest"
	;;
*)
	fail "unsupported operating system: $(uname -s) ($OS)"
	;;
esac

case "$ARCH" in
amd64 | arm64) ;;
*)
	fail "unsupported architecture: $(uname -m) ($ARCH)"
	;;
esac

# Windows builds ship as zip; this script only handles tar.gz releases.
if [ "$OS" = "windows" ]; then
	fail "Windows builds are not installed by this script.
  Download a release manually: ${RELEASES_PAGE}/latest"
fi

need_cmd curl
need_cmd tar
need_cmd mkdir
need_cmd mktemp
need_cmd rm

# sha256sum is standard on Ubuntu; shasum is the macOS fallback.
if command -v sha256sum >/dev/null 2>&1; then
	SHA256_CMD=sha256sum
elif command -v shasum >/dev/null 2>&1; then
	SHA256_CMD=shasum
else
	fail "required command not found: sha256sum or shasum"
fi

sha256_file() {
	case "$SHA256_CMD" in
	sha256sum) sha256sum "$1" | awk '{print $1}' ;;
	shasum) shasum -a 256 "$1" | awk '{print $1}' ;;
	esac
}

http_download() {
	url=$1
	dest=$2
	log "GET $url"
	code=$(curl -w '%{http_code}' -fsSL -o "$dest" "$url" || true)
	if [ "$code" != "200" ]; then
		rm -f "$dest"
		fail "download failed (HTTP ${code}): $url"
	fi
}

# Parse "tag_name" from a GitHub releases API JSON body without jq.
parse_tag_name() {
	sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

resolve_tag() {
	if [ -n "$REQUESTED_TAG" ]; then
		echo "$REQUESTED_TAG"
		return
	fi

	json=$(curl -fsSL \
		-H "Accept: application/vnd.github+json" \
		-H "User-Agent: pindrop-install-script" \
		"${GITHUB_API}/repos/${OWNER}/${REPO}/releases/latest") \
		|| fail "could not fetch latest release from GitHub"

	tag=$(printf '%s\n' "$json" | parse_tag_name)
	[ -n "$tag" ] || fail "could not parse latest release tag from GitHub"
	echo "$tag"
}

TAG=$(resolve_tag)
# GoReleaser archive names use the version without a leading "v".
VERSION=${TAG#v}
ASSET="pindrop_${VERSION}_${OS}_${ARCH}.tar.gz"
CHECKSUMS=checksums.txt
DOWNLOAD_BASE="${GITHUB}/${OWNER}/${REPO}/releases/download/${TAG}"
TARBALL_URL="${DOWNLOAD_BASE}/${ASSET}"
CHECKSUMS_URL="${DOWNLOAD_BASE}/${CHECKSUMS}"

log "tag=$TAG asset=$ASSET bindir=$BINDIR"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

TARBALL="${TMPDIR}/${ASSET}"
CHECKSUMS_FILE="${TMPDIR}/${CHECKSUMS}"

http_download "$CHECKSUMS_URL" "$CHECKSUMS_FILE"
http_download "$TARBALL_URL" "$TARBALL"

# checksums.txt lines look like: "<hex>  <filename>" (GoReleaser / sha256sum format).
WANT=$(grep " ${ASSET}$" "$CHECKSUMS_FILE" | awk '{print $1}')
[ -n "$WANT" ] || fail "checksums.txt has no entry for ${ASSET}"

GOT=$(sha256_file "$TARBALL")
if [ "$WANT" != "$GOT" ]; then
	fail "checksum mismatch for ${ASSET}
  expected ${WANT}
  received ${GOT}
  Refusing to install. The download may be corrupt or tampered with."
fi

EXTRACT="${TMPDIR}/extract"
mkdir -p "$EXTRACT"
# --no-same-owner: release tarballs carry the CI user's uid/gid; extracting as
# root or in a sandbox must not fail on ownership.
tar --no-same-owner -xzf "$TARBALL" -C "$EXTRACT"

BINARY="${EXTRACT}/pindrop"
[ -f "$BINARY" ] || fail "archive ${ASSET} does not contain a pindrop binary"

mkdir -p "$BINDIR"
install -m 755 "$BINARY" "${BINDIR}/pindrop"

cat <<EOF

pindrop ${VERSION} installed to ${BINDIR}/pindrop

Ensure ${BINDIR} is on your PATH, then install the scanners and scan:

  pindrop setup
  pindrop scan .

If ${BINDIR} is not on your PATH yet, add this to your shell profile:

  export PATH="${BINDIR}:\$PATH"

EOF
