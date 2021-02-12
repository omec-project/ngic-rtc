#!/bin/bash

#
# Directory Path
#
BASEDIR=$(pwd)
THIRDPARTY=$BASEDIR/third_party
EPCTOOLS=$THIRDPARTY/epctools
EPCTOOLPATCH=$BASEDIR/EPCTool.patch

install_pkg_deps() {
  $SUDO apt-get update && $SUDO apt-get -y install \
  build-essential \
  make \
  g++ \
  libpcap-dev \
  cmake	\
  libtool	\
  m4	\
  automake	\
  bison	\
  flex	\
  libsctp-dev	\
  libidn11-dev	\
  libgnutls-dev	\
  libgnutls28-dev	\
  libgcrypt-dev	\
  libcurl4-openssl-dev
}

install_pkg_deps
#
# Epctool Downloading
#
echo "Downloading Epctools ..."

mkdir -p $THIRDPARTY
pushd $THIRDPARTY
  git clone https://github.com/brianwaters3/epctools epctools
  echo "Downloading Complete."
popd

pushd $EPCTOOLS
  echo "Checkout Epctools to specific commit id..."
  git checkout 3f2e728bafd5111678794940e936d3f28a0540dc

  echo "Installing Epctools ..."
  ./configure
  make clean
  make
  if [ "$?" != 0 ]; then
    echo -e "Error while building epctools. Please check permission."
    exit 1
  fi

  make install
  if [ "$?" != 0 ]; then
    echo -e "Error while installing epctools. Please check permission."
    exit 1
  fi
  echo "Epctools installation is complete."

popd

