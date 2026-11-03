# shellcheck shell=bash
# Sourced by CI steps that run `go tool` (yq) on the host, whose image may have
# no Go or an old one. Any Go from 1.21 on will do: GOTOOLCHAIN=auto has it
# fetch the toolchain go.mod asks for. Older Go does not know GOTOOLCHAIN, so it
# is treated as missing.
export GOTOOLCHAIN=auto

__go_minor="$(go env GOVERSION 2>/dev/null | sed -n 's/^go1\.\([0-9]*\).*/\1/p')"
if [ "${__go_minor:-0}" -lt 21 ]; then
  __repo_root="$(git rev-parse --show-toplevel)"
  __go_version="$(awk '/^go / {print $2; exit}' "${__repo_root}/go.mod")"
  case "$(uname -m)" in
    x86_64) __go_arch=amd64 ;;
    aarch64 | arm64) __go_arch=arm64 ;;
    *) __go_arch="$(uname -m)" ;;
  esac
  __go_root="${HOME}/sdk/go${__go_version}"
  if [ ! -x "${__go_root}/bin/go" ]; then
    "${__repo_root}/hack/fetch-file" \
      "https://dl.google.com/go/go${__go_version}.linux-${__go_arch}.tar.gz" \
      "${__go_root}.tar.gz"
    mkdir -p "${__go_root}"
    tar -xzf "${__go_root}.tar.gz" -C "${__go_root}" --strip-components=1
    rm -f "${__go_root}.tar.gz"
  fi
  export PATH="${__go_root}/bin:${PATH}"
  unset __repo_root __go_version __go_arch __go_root
fi
unset __go_minor

go version
