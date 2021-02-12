#!/bin/bash

# Copyright (c) 2020 Sprint
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



RED='\033[0;41;30m'
STD='\033[0;0;39m'
BASEDIR=$(pwd)
ADMFBIN=$BASEDIR/bin
 
pause(){
  read -p "Press enter to continue ..." fackEnterKey
}

BuildADMF(){
	echo "Build ADMF"
	
	cd $BASEDIR
	if [ "$?" != 0 ]; then
          echo -e "Error while changing directory. Please check permission of directory."
          exit 1
        fi

	mkdir -p $ADMFBIN
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
          echo -e "Error while build admf. Please check permission."
          exit 1
        fi

	echo "ADMF build successfully."

        pause
}

ShowMenu() {
	clear
	echo "~~~~~~~~~~~~~~~~~~~~~"	
	echo " M A I N - M E N U"
	echo "~~~~~~~~~~~~~~~~~~~~~"
	echo "[1] Build ADMF"
	echo "[2] Exit"
}

ReadOptions() {
	local choice
	read -p "Option: " choice
	case $choice in
		1) BuildADMF ;;
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
