#! /bin/bash
# Copyright (c) 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PATH_WO_KNI=$PWD/wokni
PATH_NGIC_DP=$(dirname "$PWD")/dp
PATH_NGIC_CP=$(dirname "$PWD")/cp

echo -e "\nSwitching to without KNI base..."
echo "--------------------------------"
echo "Script directory= $PWD"
echo "PATH_WO_KNI=$PATH_WO_KNI"
echo "PATH_NGIC_DP=$PATH_NGIC_DP"
echo "PATH_NGIC_CP=$PATH_NGIC_CP"
echo "Switching wo/ kni Makefile..."
echo -e "\t$PATH_NGIC_DP will be over written. Any local changes will be lost"
read -p "Ok to overwrite Makefile: Y/N?" YN
if [[ $YN == "Y" || $YN == "y" ]]; then
	pushd $PATH_WO_KNI
	cp Makefile_wokni $PATH_NGIC_DP/Makefile
	popd
else
	echo "Aborting wo/ kni baseline switch..."
	exit
fi

echo "Coppying wokni support files..."
pushd $PATH_WO_KNI
cp epc_arp_wokni.c $PATH_NGIC_DP/pipeline/
cp epc_ul_wokni.c $PATH_NGIC_DP/pipeline/
cp epc_dl_wokni.c $PATH_NGIC_DP/pipeline/
cp init_wokni.c $PATH_NGIC_DP/
popd

echo -e "...\n"
pushd $PATH_NGIC_DP
source ../setenv.sh
echo  "Building dp..."
make clean; make
popd

echo -e "...\n"
pushd $PATH_NGIC_CP
echo  "Building cp..."
make clean; make
echo -e "\n**** System restored to kni support ****\n"
echo "DONE"
echo "--------------------------------"
echo "--------------------------------"

