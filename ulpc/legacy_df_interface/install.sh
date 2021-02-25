#!/bin/bash
RED='\033[0;41;30m'
STD='\033[0;0;39m'
BASEDIR=$(pwd)
DDFBIN=$BASEDIR/lib
TARGETLIBDIR=../df/lib/

pause(){
  read -p "Press enter to continue ..." fackEnterKey
}

LegacyInterface(){
	echo "Build Legacy Interface"

	mkdir -p $DDFBIN
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
          echo -e "Error while build d-df. Please check permission."
          exit 1
        fi

	echo "Legacy Interface build successfully."

	echo "Copying libLegacyInterface to ../df/lib/"

	mkdir -p $TARGETLIBDIR
	if [ "$?" != 0 ]; then
		echo -e "Error while creating directory. Please check permission of directory."
		exit 1
	fi

	cp $DDFBIN/libLegacyInterface.so $TARGETLIBDIR

	echo "libLegacyInterface.so copied.."



        pause
}

ShowMenu() {
	clear
	echo "~~~~~~~~~~~~~~~~~~~~~"
	echo " M A I N - M E N U"
	echo "~~~~~~~~~~~~~~~~~~~~~"
	echo "[1] Build Legacy Interface"
	echo "[2] Exit"
}

ReadOptions(){
	local choice
	read -p "Option: " choice
	case $choice in
		1) LegacyInterface ;;
		2) exit 0;;
		*) echo -e "${RED}Error...${STD}" && sleep 2
	esac
}

trap '' SIGINT SIGQUIT SIGTSTP

while true
do

	ShowMenu
	ReadOptions
done
