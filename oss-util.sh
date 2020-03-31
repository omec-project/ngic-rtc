#! /bin/bash

#Copyright (c) 2017 Sprint
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cd $(dirname ${BASH_SOURCE[0]})
export C3PO_DIR=$PWD
echo "------------------------------------------------------------------------------"
echo " C3PO_DIR exported as $C3PO_DIR"
echo "------------------------------------------------------------------------------"

OSDIST=`lsb_release -is`
OSVER=`lsb_release -rs`

#install_cmake()
#{
#  sudo apt-get -y purge cmake cmake-curses-gui
#  sudo apt-get -y install g++ make autotools-dev m4 libncurses-dev
#  pushd modules
#  rm -rf cmake-3.5.1
#  rm -rf cmake-3.5.1.tar.gz
#  wget https://cmake.org/files/v3.5/cmake-3.5.1.tar.gz
#  tar -xvf cmake-3.5.1.tar.gz
#  cd cmake-3.5.1
#  ./bootstrap && make -j4 && sudo make install
#  popd
#
#}

install_libtool()
{
  pushd modules
  rm -rf libtool-2.4.6
  rm -rf libtool-2.4.6.tar.gz
  wget http://ftp.gnu.org/gnu/libtool/libtool-2.4.6.tar.gz
  tar -xvf libtool-2.4.6.tar.gz
  cd libtool-2.4.6
  ./configure && make && sudo make install
  popd
  
}

install_libs()
{
  sudo apt-get -y update > /dev/null
  case $OSDIST in
    Ubuntu)
      case "$OSVER" in
        14.04) sudo apt-get -y install libuv-dev libssl-dev automake libmemcached-dev memcached gcc bison flex libsctp-dev libgnutls-dev libgcrypt-dev libidn11-dev nettle-dev ;;
        16.04) sudo apt-get -y install g++ make cmake libuv-dev libssl-dev autotools-dev libtool-bin m4 automake libmemcached-dev memcached cmake-curses-gui gcc bison flex libsctp-dev libgnutls-dev libgcrypt-dev libidn11-dev nettle-dev ;;
        *) echo "$OSDIST version $OSVER is unsupported." ; exit;;
      esac
      ;;
    *) echo "ERROR: Unsupported operating system distribution: $OSDIST"; exit 1;;
  esac

}

init_submodules()
{
  git submodule init
  git submodule update
  build_c_ares
  build_cpp_driver
  build_pistache
  build_rapidjson
  build_spdlog
  build_cli 
 
  sudo ldconfig
    
}

build_c_ares()
{
  pushd modules/c-ares
  ./buildconf
  ./configure
  make
  sudo make install
  popd
  
}

build_cpp_driver()
{
  pushd modules/cpp-driver
  rm -rf build
  mkdir -p build
  cd build
  cmake ..
  make
  sudo make install
  popd
  
}

build_pistache()
{
  pushd modules/pistache
  rm -rf build
  mkdir -p build
  cd build
  cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release ..
  make
  sudo make install
  popd
  
}

build_rapidjson()
{
  pushd modules/rapidjson
  rm -rf build
  mkdir -p build
  cd build
  cmake ..
  sudo make install
  popd
  
}

build_spdlog()
{
  pushd modules/spdlog
  rm -rf build
  mkdir -p build
  cd build
  cmake ..
  sudo make install
  popd
  
}

build_cli()
{
  pushd cli

  sudo apt-get -y install python-pip
  sudo pip install -r requirements.txt
  sudo apt-get -y install python-virtualenv
  virtualenv -p python3.5 venv
  source venv/bin/activate
  popd

}

build_c3po_util()
{

  make clean
  sudo make install

}

install_libtool
install_libs
init_submodules
build_c3po_util

