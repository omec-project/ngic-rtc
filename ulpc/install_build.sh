#!/bin/bash

#
# Directory Path
#
BASEDIR=$(pwd)
LEGACYADMF=$BASEDIR/legacy_admf
LEGACYADMFINTFC=$BASEDIR/legacy_admf_interface
ADMF=$BASEDIR/admf
DADMF=$BASEDIR/d_admf
DDF=$BASEDIR/d_df
DF=$BASEDIR/df
LEGACYDFINTFC=$BASEDIR/legacy_df_interface
LEGACYDF=$BASEDIR/legacy_df
BIN=bin
LIB=lib
INCDIR=/usr/local/include/
TARGETINCDIR=$INCDIR/legacy_admf_interface/


#
# Building Legacy ADMF
#
pushd $LEGACYADMF

	echo "Building Legacy ADMF..."

	mkdir -p $LEGACYADMF/$BIN
	if [ "$?" != 0 ]; then
		echo -e "Error while creating directory. Please check permission of directory."
		exit 1
	fi

	make clean
	if [ "$?" != 0 ]; then
		echo -e "Please check permission."
		exit 1
	fi

	make
	if [ "$?" != 0 ]; then
		echo -e "Error while build Legacy ADMF. Please check permission."
		exit 1
	fi

	echo "Legacy ADMF build successfully."

popd


#
# Building Legacy ADMF INTERFACE
#
pushd $LEGACYADMFINTFC

	echo "Building Legacy ADMF Interface..."

	mkdir -p $LEGACYADMFINTFC/$LIB
	if [ "$?" != 0 ]; then
		echo -e "Error while creating directory. Please check permission of directory."
		exit 1
	fi

	make clean
	if [ "$?" != 0 ]; then
		echo -e "Please check permission."
		exit 1
	fi

	make
	if [ "$?" != 0 ]; then
		echo -e "Error while build Legacy ADMF Interface. Please check permission."
		exit 1
	fi

	echo "Legacy ADMF Interface build successfully."

	echo "Copying libLegacyAdmfInterface to /usr/lib/"

	mkdir -p $ADMF/$LIB
	if [ "$?" != 0 ]; then
		echo -e "Error while creating directory. Please check permission of directory."
		exit 1
	fi

	cp $LEGACYADMFINTFC/$LIB/libLegacyAdmfInterface.so $ADMF/$LIB/

	echo "libLegacyAdmfInterface copied..."

	echo "Copying header files to /usr/local/include/legacy_admf_interface"

	mkdir -p $TARGETINCDIR
	if [ "$?" != 0 ]; then
		echo -e "Error while creating directory. Please check permission of directory."
		exit 1
	fi

	cp $LEGACYADMFINTFC/include/* $TARGETINCDIR

	echo "Header files copied.."

popd


#
# Building ADMF
#
pushd $ADMF

	echo "Building ADMF..."

	mkdir -p $ADMF/$BIN
	if [ "$?" != 0 ]; then
		echo -e "Error while creating directory. Please check permission of directory."
		exit 1
	fi

	make clean
	if [ "$?" != 0 ]; then
		echo -e "Please check permission."
		exit 1
	fi

	make
	if [ "$?" != 0 ]; then
		echo -e "Error while build ADMF. Please check permission."
		exit 1
	fi

	echo "ADMF build successfully."

popd


#
# Building DADMF
#
pushd $DADMF

	echo "Building DADMF..."

	mkdir -p $DADMF/$BIN
	if [ "$?" != 0 ]; then
		echo -e "Error while creating directory. Please check permission of directory."
		exit 1
	fi

	make clean
	if [ "$?" != 0 ]; then
		echo -e "Please check permission."
		exit 1
	fi

	make
	if [ "$?" != 0 ]; then
		echo -e "Error while build DADMF. Please check permission."
		exit 1
	fi

	echo "DADMF build successfully."

popd


#
# Building DDF
#
pushd $DDF

	echo "Building DDF..."

	mkdir -p $DDF/$BIN
	if [ "$?" != 0 ]; then
		echo -e "Error while creating directory. Please check permission of directory."
		exit 1
	fi

	make clean
	if [ "$?" != 0 ]; then
		echo -e "Please check permission."
		exit 1
	fi

	make
	if [ "$?" != 0 ]; then
		echo -e "Error while build DDF. Please check permission."
		exit 1
	fi

	echo "DDF build successfully."

popd


#
# Building Legacy DF INTERFACE
#
pushd $LEGACYDFINTFC

	echo "Building Legacy DF Interface..."

	mkdir -p $LEGACYDFINTFC/$LIB
	if [ "$?" != 0 ]; then
		echo -e "Error while creating directory. Please check permission of directory."
		exit 1
	fi

	make clean
	if [ "$?" != 0 ]; then
		echo -e "Please check permission."
		exit 1
	fi

	make
	if [ "$?" != 0 ]; then
		echo -e "Error while build Legacy DF Interface. Please check permission."
		exit 1
	fi

	echo "Legacy DF Interface build successfully."

	echo "Copying libLegacyDfInterface to /usr/lib/"

	mkdir -p $DF/$LIB
	if [ "$?" != 0 ]; then
		echo -e "Error while creating directory. Please check permission of directory."
		exit 1
	fi

	cp $LEGACYDFINTFC/$LIB/libLegacyInterface.so $DF/$LIB/

	echo "libLegacyDfInterface copied..."

popd


#
# Building DF
#
pushd $DF

	echo "Building DF..."

	mkdir -p $DF/$BIN
	if [ "$?" != 0 ]; then
		echo -e "Error while creating directory. Please check permission of directory."
		exit 1
	fi

	make clean
	if [ "$?" != 0 ]; then
		echo -e "Please check permission."
		exit 1
	fi

	make
	if [ "$?" != 0 ]; then
		echo -e "Error while build DF. Please check permission."
		exit 1
	fi

	echo "DF build successfully."

popd


#
# Building Legacy DF
#
pushd $LEGACYDF

	echo "Building Legacy DF..."

	mkdir -p $LEGACYDF/$BIN
	if [ "$?" != 0 ]; then
		echo -e "Error while creating directory. Please check permission of directory."
		exit 1
	fi

	make clean
	if [ "$?" != 0 ]; then
		echo -e "Please check permission."
		exit 1
	fi

	make
	if [ "$?" != 0 ]; then
		echo -e "Error while build Legacy DF. Please check permission."
		exit 1
	fi

	echo "Legacy DF build successfully."

popd

