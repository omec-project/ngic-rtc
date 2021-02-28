#!/bin/bash
RED='\033[0;41;30m'
STD='\033[0;0;39m'
BASEDIR=$(pwd)
DDFBIN=$BASEDIR/bin

pause(){
  read -p "Press enter to continue ..." fackEnterKey
}

BuildDF(){
	echo "Build DF"

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
          echo -e "Error while build df. Please check permission."
          exit 1
        fi

	echo "DF build successfully."

        pause
}

ShowMenu() {
	clear
	echo "~~~~~~~~~~~~~~~~~~~~~"
	echo " M A I N - M E N U"
	echo "~~~~~~~~~~~~~~~~~~~~~"
	echo "[1] Build DF"
	echo "[2] Exit"
}

ReadOptions(){
	local choice
	read -p "Option: " choice
	case $choice in
		1) BuildDF ;;
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
