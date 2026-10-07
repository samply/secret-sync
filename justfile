set shell := ["bash", "-euo", "pipefail", "-c"]

arch := if arch() == "aarch64" { "arm64" } else { "amd64" }
cache := cache_directory() / "podman-builds"

# Build release binaries into artifacts/, laid out as in CI
binaries:
  mkdir -p {{ cache }}/cargo-registry {{ cache }}/cargo-git artifacts/binaries-{{ arch }}-
  podman run --rm -v {{ justfile_directory() }}:/src:Z -w /src \
    -v {{ cache }}/cargo-registry:/usr/local/cargo/registry:Z \
    -v {{ cache }}/cargo-git:/usr/local/cargo/git:Z \
    docker.io/library/rust:1-bookworm cargo build --release --bins
  cp target/release/local target/release/central artifacts/binaries-{{ arch }}-/

# Build both container images, tagged :localbuild
images: binaries
  for c in local central; do \
    podman build --build-arg COMPONENT=$c --build-arg FEATURE=- -t samply/secret-sync-$c:localbuild .; \
  done
