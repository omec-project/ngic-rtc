#! /bin/bash
echo "------------------------------------------------------------------------------"
echo " Building and Clean CP, DP and DPDK "
echo "------------------------------------------------------------------------------"

if [[ ! -d "${NGIC_DIR}" ]];
then
	pushd ../
	SRC_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
	export NGIC_DIR=$SRC_DIR
	echo "NGIC_DIR:"$NGIC_DIR
	popd
fi

DPDK_DIR=$NGIC_DIR/dpdk

quit()
{
	QUIT=$1
}

q()
{
	quit
}

step_1()
{
    TITLE="Build CP and DP"
    CONFIG_NUM=1
    TEXT[1]="CP Clean and Build"
    FUNC[1]="cp_build"
	TEXT[2]="DP Clean and Build"
	FUNC[2]="dp_build"

}

step_2()
{
   TITLE="Build DPDK"
   CONFIG_NUM=1
   TEXT[1]="DPDK Clean"
   FUNC[1]="dpdk_clean"
   TEXT[2]="DPDK Build"
   FUNC[2]="dpdk_build"
}

dpdk_clean()
{
	echo "Clean DPDK"
	[[ -z "$RTE_TARGET" ]] && export RTE_TARGET=x86_64-native-linuxapp-gcc
	pushd "$DPDK_DIR"
	make -j config T="$RTE_TARGET" && make clean
	if [ $? -ne 0 ] ; then
		echo "Failed to clean dpdk, please check the errors."
		return
	fi
	popd
}

dpdk_build()
{
	echo "Build DPDK"
	[[ -z "$RTE_TARGET" ]] && export RTE_TARGET=x86_64-native-linuxapp-gcc

	pushd "$DPDK_DIR"
	#make -j config T="$RTE_TARGET" && make build
	make -j install T="$RTE_TARGET"
	if [ $? -ne 0 ] ; then
		echo "Failed to build dpdk, please check the errors."
		return
	fi
	popd
}

cp_build()
{
	pushd $NGIC_DIR
	source setenv.sh
		echo "Cleaning CP..."
		make clean-cp
		echo "Building CP..."
		make build-cp || { echo -e "\nCP: Make failed\n"; }
	popd
}

dp_build()
{

	pushd $NGIC_DIR
	source setenv.sh
		echo "Cleaning DP..."
		make clean-dp
		echo "Building DP..."
		make build-dp || { echo -e "\nDP: Make failed\n"; }
	popd
}

STEPS[1]="step_1"
STEPS[2]="step_2"

QUIT=0

clear

echo -n "Checking for user permission.. "
sudo -n true
if [ $? -ne 0 ]; then
   echo "Password-less sudo user must run this script" 1>&2
   exit 1
fi
echo "Done"
clear

while [ "$QUIT" == "0" ]; do
        OPTION_NUM=1
        for s in $(seq ${#STEPS[@]}) ; do
                ${STEPS[s]}

                echo "----------------------------------------------------------"
                echo " Step $s: ${TITLE}"
                echo "----------------------------------------------------------"

                for i in $(seq ${#TEXT[@]}) ; do
                        echo "[$OPTION_NUM] ${TEXT[i]}"
                        OPTIONS[$OPTION_NUM]=${FUNC[i]}
                        let "OPTION_NUM+=1"
                done

                # Clear TEXT and FUNC arrays before next step
                unset TEXT
                unset FUNC

                echo ""
        done

        echo "[$OPTION_NUM] Exit Script"
        OPTIONS[$OPTION_NUM]="quit"
        echo ""
        echo -n "Option: "
        read our_entry
        echo ""
        ${OPTIONS[our_entry]} ${our_entry}

        if [ "$QUIT" == "0" ] ; then
                echo
                echo -n "Press enter to continue ..."; read
                clear
                continue
                exit
        fi
        echo "CP, DP and DPDK Building completed...!!!!"
done

