#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y \
  linux-image-$(uname -r) \
  linux-headers-$(uname -r) \
  make \
  docker.io \
  llvm \
  git \
  clang \
  gcc-multilib \
  zlib1g-dev \
  libelf-dev
