#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation

PATH_WO_KNI=$PWD/wokni
PATH_NGIC_DP=$(dirname "$PWD")/dp
PATH_NGIC_CP=$(dirname "$PWD")/cp

echo -e "\nRestoring to KNI baseline..."
echo "--------------------------------"
echo "Script directory= $PWD"
echo "PATH_WO_KNI=$PATH_WO_KNI"
echo "PATH_NGIC_DP=$PATH_NGIC_DP"
echo "PATH_NGIC_CP=$PATH_NGIC_CP"
echo "Restoring kni Makefile..."
echo -e "\t$PATH_NGIC_DP will be over written. Any local changes will be lost"
read -p "Ok to restore kni Makefile: Y/N?" YN
if [[ $YN == "Y" || $YN == "y" ]]; then
	pushd $PATH_WO_KNI
	cp Makefile_wkni $PATH_NGIC_DP/Makefile
	popd
else
	echo "Aborting kni baseline restoration..."
	exit
fi

echo "Cleaning up wokni support files..."
pushd $PATH_NGIC_DP/pipeline
rm -f epc_arp_wokni.c
rm -f epc_ul_wokni.c
rm -f epc_dl_wokni.c
cd ..
rm -f init_wokni.c
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

