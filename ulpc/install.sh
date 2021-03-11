#!/bin/bash
RED='\033[0;41;30m'
STD='\033[0;0;39m'
BASEDIR=$(pwd)
THIRDPARTY=$BASEDIR/third_party
EPCTOOLS=$THIRDPARTY/epctools
DADMFBIN=$BASEDIR/bin

pause(){
  read -p "Press enter to continue ..." fackEnterKey
}

DownloadEpctools(){
	echo "Downloading Epctools ..."

	mkdir -p $THIRDPARTY
	if [ "$?" != 0 ]; then
          echo -e "Error while creating directory. Please check permission of directory."
          exit 1
        fi

	cd $THIRDPARTY
	if [ "$?" != 0 ]; then
          echo -e "Error while changing directory. Please check permission of directory."
          exit 1
        fi

  	git clone https://github.com/omec-project/epctools.git epctools
	if [ "$?" != 0 ]; then
          echo -e "Error while downloading epctools. Please check internet connection."
          exit 1
        fi

	echo "Downloading Complete."

	cd $EPCTOOLS
	if [ "$?" != 0 ]; then
          echo -e "Error while changing directory. Please check permission of directory."
          exit 1
        fi

        pause
}

InstallEpctools(){
	echo "Installing Epctools ..."

	cd $EPCTOOLS
	if [ "$?" != 0 ]; then
          echo -e "Error while changing directory. Please check permission of directory."
          exit 1
        fi

	echo "Checkout Epctools to specific commit id..."
  	git checkout e14e3788bc5dc88e58cd421fc144ca637a2027f7
	if [ "$?" != 0 ]; then
          echo -e "Error while checkout to specific commit."
          exit 1
        fi


	./configure
	if [ "$?" != 0 ]; then
          echo -e "Error while configuring epctools."
          exit 1
        fi

	make clean
	if [ "$?" != 0 ]; then
          echo -e "Please check permission."
          exit 1
        fi

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

        pause
}

BuildDADMF(){
	echo "Build D-ADMF"

	cd $BASEDIR
	if [ "$?" != 0 ]; then
          echo -e "Error while changing directory. Please check permission of directory."
          exit 1
        fi

	mkdir -p $DADMFBIN
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
          echo -e "Error while build d-admf. Please check permission."
          exit 1
        fi

	echo "D-ADMF build successfully."

        pause
}

ShowMenu() {
	clear
	echo "~~~~~~~~~~~~~~~~~~~~~"
	echo " M A I N - M E N U"
	echo "~~~~~~~~~~~~~~~~~~~~~"
	echo "[1] Download Epctools"
	echo "[2] Install Epctools"
	echo "[3] Exit"
}

ReadOptions(){
	local choice
	read -p "Option: " choice
	case $choice in
		1) DownloadEpctools ;;
		2) InstallEpctools ;;
		3) exit 0;;
		*) echo -e "${RED}Error...${STD}" && sleep 2
	esac
}

trap '' SIGINT SIGQUIT SIGTSTP

while true
do

	ShowMenu
	ReadOptions
done
