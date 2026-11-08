#!/bin/sh
# Install Shentu from a release archive. Usage:
#   curl -fsSL https://github.com/nt-neil/shentu/releases/latest/download/install.sh | sudo sh
# or, from an unpacked archive:  sudo ./install.sh
set -eu

main() {
	REPO="nt-neil/shentu"
	[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
	[ "$(uname -s)" = Linux ] || { echo "Shentu supports Linux only" >&2; exit 1; }
	case "$(uname -m)" in
		x86_64|amd64) ARCH=amd64 ;;
		aarch64|arm64) ARCH=arm64 ;;
		*) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
	esac

	# Use files next to this script only when it was run as a file from an unpacked
	# release archive; when piped into sh, $0 is "sh" and we always download.
	SRC=""
	case "$0" in
		*install.sh) [ -f "$0" ] && SRC=$(cd "$(dirname "$0")" && pwd) ;;
	esac
	if [ -n "$SRC" ] && [ -x "$SRC/shentu" ]; then
		echo "installing from $SRC"
	else
		TMP=$(mktemp -d)
		trap 'rm -rf "$TMP"' EXIT
		BASE="https://github.com/$REPO/releases/latest/download"
		curl -fsSL -o "$TMP/shentu.tar.gz" "$BASE/shentu_linux_$ARCH.tar.gz"
		curl -fsSL -o "$TMP/checksums.txt" "$BASE/checksums.txt"
		(cd "$TMP" && grep " shentu_linux_$ARCH.tar.gz\$" checksums.txt | sed "s/shentu_linux_$ARCH.tar.gz/shentu.tar.gz/" | sha256sum -c -)
		tar -xzf "$TMP/shentu.tar.gz" -C "$TMP"
		SRC="$TMP"
	fi

	install -m 0755 "$SRC/shentu" /usr/local/bin/shentu
	# RHEL-family sudo has no /usr/local/bin in secure_path, so `sudo shentu` would not be found.
	[ -e /usr/bin/shentu ] || ln -s /usr/local/bin/shentu /usr/bin/shentu
	install -d -m 0755 /etc/shentu
	install -d -m 0700 /var/lib/shentu
	[ -f /etc/shentu/shentu.toml ] || install -m 0644 "$SRC/packaging/shentu.toml" /etc/shentu/shentu.toml
	[ -f /etc/shentu/env ] || install -m 0600 /dev/null /etc/shentu/env
	for u in shentu-patrol.service shentu-patrol.timer shentu-daily.service shentu-daily.timer shentu-bot.service; do
		install -m 0644 "$SRC/packaging/$u" "/etc/systemd/system/$u"
	done
	systemctl daemon-reload
	command -v nft >/dev/null 2>&1 ||
		echo "Note: nftables is not installed, so block_ip will not work. Install it with apt/dnf install nftables."

	echo "Shentu installed."
	# Piped into sh, stdin is the script itself; the guided setup reads the terminal instead.
	# SHENTU_NO_SETUP=1 skips it (for scripts and images).
	if [ -f /etc/shentu/setup.toml ]; then
		echo "Settings kept. To change them: sudo shentu setup"
	elif [ -z "${SHENTU_NO_SETUP:-}" ] && [ -r /dev/tty ] && [ -w /dev/tty ] && (exec </dev/tty) 2>/dev/null; then
		# A fresh install, or an upgrade from a version without the guided setup: steps
		# that are already done (model, notifications, patrols) are offered as "keep".
		echo "Starting the guided setup (Ctrl-C to stop; run 'sudo shentu setup' any time)..."
		/usr/local/bin/shentu setup </dev/tty >/dev/tty 2>&1 || echo "Setup did not finish. Run: sudo shentu setup"
	else
		echo "Next: sudo shentu setup   (guided: model, notifications, survey, patrols)"
	fi
}

main "$@"
