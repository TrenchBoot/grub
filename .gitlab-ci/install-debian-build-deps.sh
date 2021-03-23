#!/bin/bash

echo "deb http://ftp.de.debian.org/debian stretch main" \
>> /etc/apt/sources.list
apt-get update
apt-get -y install \
  build-essential \
  dh-make \
  flex \
  bison \
  help2man \
  texinfo \
  xfonts-unifont \
  libfreetype6-dev \
  libdevmapper-dev \
  libsdl1.2-dev \
  xorriso \
  qemu-system \
  cpio \
  parted \
  libfuse-dev \
  ttf-dejavu-core \
  liblzma-dev \
  dosfstools \
  mtools \
  wamerican \
  pkg-config \
  bash-completion \
  libefiboot-dev \
  libefivar-dev \
  patchutils \
  gcc-9-multilib \
  git
