#!/bin/sh
# Install Shentu from a release archive. Usage:
#   curl -fsSL https://github.com/nt-nerdtechnic/shentu/releases/latest/download/install.sh | sudo sh
# or, from an unpacked archive:  sudo ./install.sh
set -eu

main() {
	REPO="nt-nerdtechnic/shentu"
	[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
	[ "$(uname -s)" = Linux ] || { echo "Shentu supports Linux only" >&2; exit 1; }
	case "$(uname -m)" in
		x86_64|amd64) ARCH=amd64 ;;
		aarch64|arm64) ARCH=arm64 ;;
		*) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
	esac

	SRC=$(dirname "$0")
	if [ ! -x "$SRC/shentu" ]; then
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
	install -d -m 0755 /etc/shentu
	install -d -m 0700 /var/lib/shentu
	[ -f /etc/shentu/shentu.toml ] || install -m 0644 "$SRC/packaging/shentu.toml" /etc/shentu/shentu.toml
	[ -f /etc/shentu/env ] || install -m 0600 /dev/null /etc/shentu/env
	for u in shentu-patrol.service shentu-patrol.timer shentu-daily.service shentu-daily.timer; do
		install -m 0644 "$SRC/packaging/$u" "/etc/systemd/system/$u"
	done
	systemctl daemon-reload

	cat <<'MSG'
Shentu installed.

Next steps:
  1. Edit /etc/shentu/shentu.toml: choose the LLM and the notify channel.
     Put tokens in /etc/shentu/env, e.g. TG_BOT_TOKEN=...
  2. Try it:            sudo shentu chat
  3. Test a report:     sudo shentu patrol --daily --dry-run
  4. Turn on patrols:   sudo systemctl enable --now shentu-patrol.timer shentu-daily.timer
MSG
}

main "$@"
