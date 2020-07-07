#! /bin/bash

#Source/Set the Env variables(PATH, NG_CORE etc)
source ../setenv.sh

#VS: Check the GW configured STATIC or DYNAMIC ARP
dp_static_arp_flag="CFLAGS += -DSTATIC_ARP"

#Code to check if STATIC_ARP is enabled or disabled in DP Makefile
if grep -q -e "^$dp_static_arp_flag" ../dp/Makefile; then
	   echo -e ""
	   echo -e "WARNING: STATIC_ARP enabled in dp/Makefile,"\
		   "Enabling kni interfaces along with STATIC_ARP will cause duplicate ARP responses on the wire."
	   echo -e ""
	   while true; do
			   read -p "Do you wish to continue?" response
			   case $response in
			           [Yy]* ) break;;
			           [Nn]* ) exit;;
			           * ) echo "Please answer yes(y) or no(n)";;
			   esac
	   done
fi

echo "Setting IP Address for KNI WB and EB interfaces..."

#Pointing to the data-plane configuration file
file=$NG_CORE/config/dp.cfg
echo "Reading WB and EB IP address from DP config file:"$file

while IFS= read -r line
do
	if [[ "WB_IP" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		WB_IP=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "WB_LI_IP" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		WB_LI_IP=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "EB_IP" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		EB_IP=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "EB_LI_IP" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		EB_LI_IP=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "WB_MASK" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		WB_MASK=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "EB_MASK" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		EB_MASK=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "eNB_IP" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		eNB_IP=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "AS_IP" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		AS_IP=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "WB_IFACE" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		WB_IFACE=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "WB_LI_IFACE" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		WB_LI_IFACE=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "EB_IFACE" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		EB_IFACE=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "EB_LI_IFACE" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		EB_LI_IFACE=`echo $line | awk -F '=' '{printf $2}'`
	fi
done < $file

#Note: Commented the echo statements
#West Bound Interface: S1U/S5S8
if [[ "$WB_IP" == "" ]]; then
	echo "ERROR:West Bound(WB_IP:S1U/S5S8) IP Addr Not Configured."
	exit
#else
#	echo "WB_IP:"$WB_IP
fi

#VS: West Bound Logical Interface: S5S8
#if [[ "$WB_LI_IP" != "" ]]; then
#	echo "WB_LI_IP:"$WB_LI_IP
#fi

#East Bound Interface: S5S8/SGI
if [[ "$EB_IP" == "" ]]; then
	echo "ERROR:East Bound(EB_IP:S5S8/SGI) IP Addr Not Configured."
	exit
#else
#	echo "EB_IP:"$EB_IP
fi

#VS:East Bound Logical Interface: S5S8
#if [[ "$EB_LI_IP" != "" ]]; then
#	echo "EB_LI_IP:"$EB_LI_IP
#fi

#West Bound Interface Mask: S1U/S5S8
#if [[ "$WB_MASK" != "" ]]; then
#	echo "WB_MASK:"$WB_MASK
#fi

#East Bound Interface Mask: S5S8/SGI
#if [[ $EB_MASK != "" ]]; then
#	echo "EB_MASK:"$EB_MASK
#fi

#West Bound Interface Gateway Addr:eNB/SGW
#if [[ "$eNB_IP" != "" ]]; then
#	echo "eNB_IP:"$eNB_IP
#fi

#East Bound Interface Application Server Address
#if [[ "$AS_IP" != "" ]]; then
#	echo "AS_IP:"$AS_IP
#fi

#West Bound Interface Name: S1U/S5S8
if [[ "$WB_IFACE" == "" ]]; then
	echo "ERROR:West Bound(WB_IFACE) Interface Name Not Configured"
	exit
#else
#	echo "WB_IFACE:"$WB_IFACE
fi

#East Bound Interface Name: S5S8/SGI
if [[ "$EB_IFACE" == "" ]]; then
	echo "ERROR:East Bound(EB_IFACE) Interface Name Not Configured"
	exit
#else
#	echo "EB_IFACE:"$EB_IFACE
fi

#Configured the West Bound Interface
#ifconfig $WB_IFACE
ifconfig $WB_IFACE $WB_IP/24

#Uncomment below to add route entry for GW_IP
#if [ -n "${WB_GW_IP}" ]; then
#	route add default gw ${WB_GW_IP} dev $WB_IFACE
#fi

#Below usecase to be understood
#WB_SUBMASK=`echo $WB_MASK | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
#eNB_DEC=`echo $eNB_IP | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
#WB_DEC=`echo $WB_IP | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
#
#eNB_SUBMASK="$(($eNB_DEC & $WB_SUBMASK))"
#WB_SUBMASK="$(($WB_DEC & $WB_SUBMASK))"

#if [ "$WB_SUBMASK" -ne "$eNB_SUBMASK" ];then
#	route add -net $eNB_SUBMASK/24 dev $UL_IFACE
#fi
#VS:Check configured West Bound Interface
ifconfig $WB_IFACE

#VS:Configured the West Bound Logical Interface
if [[ "$WB_LI_IP" != "" ]]; then
	if [[ "$WB_LI_IFACE" == "" ]]; then
		echo "ERROR:West Bound(WB_LI_IFACE) S5S8 Logical Interface Name Not Configured"
		exit
	fi
	ifconfig $WB_LI_IFACE $WB_LI_IP/24
	ifconfig $WB_LI_IFACE
fi

#Configured the East Bound Interface
#ifconfig $EB_IFACE
ifconfig $EB_IFACE $EB_IP/24

#Uncomment below to add route entry for GW_IP
#if [ -n "${EB_GW_IP}" ]; then
#	route add default gw ${EB_GW_IP} dev $EB_IFACE
#fi

#Below usecase to be understood
#EB_SUBMASK=`echo $EB_MASK | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
#AS_DEC=`echo $AS_IP | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
#EB_DEC=`echo $EB_IP | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
#
#AS_SUBMASK="$(($AS_DEC & $EB_SUBMASK))"
#EB_SUBMASK="$(($EB_DEC & $EB_SUBMASK))"

#if [ "$EB_SUBMASK" -ne "$AS_SUBMASK" ];then
#	route add -net $AS_SUBMASK/24 dev $EB_IFACE
#fi
#Check configured East Bound Interface
ifconfig $EB_IFACE

#VS:Configured the East Bound Logical Interface
if [[ "$EB_LI_IP" != "" ]]; then
	if [[ "$EB_LI_IFACE" == "" ]]; then
		echo "ERROR:East Bound(EB_LI_IFACE) S5S8 Logical Interface Name Not Configured"
		exit
	fi
	ifconfig $EB_LI_IFACE $EB_LI_IP/24
	ifconfig $EB_LI_IFACE
fi
