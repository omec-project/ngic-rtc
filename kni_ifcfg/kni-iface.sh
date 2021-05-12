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
	if [[ "WB_IPv4" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		WB_IPv4=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "WB_IPv6" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		WB_IPv6=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "WB_LI_IPv4" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		WB_LI_IPv4=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "WB_LI_IPv6" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		WB_LI_IPv6=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "EB_IPv4" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		EB_IPv4=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "EB_IPv6" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		EB_IPv6=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "EB_LI_IPv4" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		EB_LI_IPv4=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "EB_LI_IPv6" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		EB_LI_IPv6=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "WB_IPv4_MASK" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		WB_IPv4_MASK=`echo $line | awk -F '=' '{printf $2}'`
	elif [[ "EB_IPv4_MASK" == `echo $line | awk -F '=' '{printf $1}'` ]];then
		EB_IPv4_MASK=`echo $line | awk -F '=' '{printf $2}'`
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
if [[ "$WB_IPv4" == "" ]]; then
	if [[ "$WB_IPv6" == "" ]]; then
		echo "ERROR:West Bound(WB_IPv4:S1U/S5S8) IPv4/IPv6 Address are not configured."
		exit
	fi
fi

#VS: West Bound Logical Interface: S5S8
#if [[ "$WB_LI_IPv4" != "" ]]; then
#	echo "WB_LI_IPv4:"$WB_LI_IPv4
#fi

#East Bound Interface: S5S8/SGI
if [[ "$EB_IPv4" == "" ]]; then
	if [[ "$EB_IPv6" == "" ]]; then
		echo "ERROR:East Bound(EB_IPv4:S5S8/SGI) IPv4/IPv6 Address are not configured."
		exit
	fi
fi

#VS:East Bound Logical Interface: S5S8
#if [[ "$EB_LI_IPv4" != "" ]]; then
#	echo "EB_LI_IPv4:"$EB_LI_IPv4
#fi

#West Bound Interface Mask: S1U/S5S8
#if [[ "$WB_IPv4_MASK" != "" ]]; then
#	echo "WB_IPv4_MASK:"$WB_IPv4_MASK
#fi

#East Bound Interface Mask: S5S8/SGI
#if [[ $EB_IPv4_MASK != "" ]]; then
#	echo "EB_IPv4_MASK:"$EB_IPv4_MASK
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
fi

#East Bound Interface Name: S5S8/SGI
if [[ "$EB_IFACE" == "" ]]; then
	echo "ERROR:East Bound(EB_IFACE) Interface Name Not Configured"
	exit
fi

#Configured the West Bound Interface
if [[ "$WB_IPv4" != "" ]]; then
	ifconfig $WB_IFACE $WB_IPv4/24
	if [[ "$WB_IPv6" != "" ]]; then
		ifconfig $WB_IFACE inet6 add $WB_IPv6
	fi
elif [[ "$WB_IPv6" != "" ]];then
	ifconfig $WB_IFACE inet6 add $WB_IPv6
	ifconfig $WB_IFACE up
fi

#Uncomment below to add route entry for GW_IP
#if [ -n "${WB_GW_IP}" ]; then
#	route add default gw ${WB_GW_IP} dev $WB_IFACE
#fi

#Below usecase to be understood
#WB_SUBMASK=`echo $WB_IPv4_MASK | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
#eNB_DEC=`echo $eNB_IP | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
#WB_DEC=`echo $WB_IPv4 | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
#
#eNB_SUBMASK="$(($eNB_DEC & $WB_SUBMASK))"
#WB_SUBMASK="$(($WB_DEC & $WB_SUBMASK))"

#if [ "$WB_SUBMASK" -ne "$eNB_SUBMASK" ];then
#	route add -net $eNB_SUBMASK/24 dev $UL_IFACE
#fi

#VS:Configured the West Bound Logical Interface

if [[ "$WB_LI_IPv4" != "" ]]; then
	if [[ "$WB_LI_IFACE" == "" ]]; then
		echo "ERROR:West Bound(WB_LI_IFACE) S5S8 Logical Interface Name Not Configured"
		exit
	fi
	ifconfig $WB_LI_IFACE $WB_LI_IPv4/24

	if [[ "$WB_LI_IPv6" != "" ]];then
		if [[ "$WB_IFACE" == "" ]]; then
			echo "ERROR:West Bound(WB_IFACE) S5S8 Interface Name Not Configured"
			exit
		fi
		ifconfig $WB_IFACE inet6 add $WB_LI_IPv6
		ifconfig $WB_IFACE up
	fi
elif [[ "$WB_LI_IPv6" != "" ]];then
	if [[ "$WB_IFACE" == "" ]]; then
		echo "ERROR:West Bound(WB_IFACE) S5S8 Interface Name Not Configured"
		exit
	fi
	ifconfig $WB_IFACE inet6 add $WB_LI_IPv6
	ifconfig $WB_IFACE up
fi

#VS:Check configured West Bound Interface
ifconfig $WB_IFACE

if [[ "$WB_LI_IPv4" != "" ]]; then
	ifconfig $WB_LI_IFACE
fi

#Configured the East Bound Interface
if [[ "$EB_IPv4" != "" ]]; then
	ifconfig $EB_IFACE $EB_IPv4/24
	if [[ "$EB_IPv6" != "" ]]; then
		ifconfig $EB_IFACE inet6 add $EB_IPv6
	fi
elif [[ "$EB_IPv6" != "" ]];then
	ifconfig $EB_IFACE inet6 add $EB_IPv6
	ifconfig $EB_IFACE up
fi

#Uncomment below to add route entry for GW_IP
#if [ -n "${EB_GW_IP}" ]; then
#	route add default gw ${EB_GW_IP} dev $EB_IFACE
#fi

#Below usecase to be understood
#EB_SUBMASK=`echo $EB_IPv4_MASK | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
#AS_DEC=`echo $AS_IP | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
#EB_DEC=`echo $EB_IPv4 | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
#
#AS_SUBMASK="$(($AS_DEC & $EB_SUBMASK))"
#EB_SUBMASK="$(($EB_DEC & $EB_SUBMASK))"

#if [ "$EB_SUBMASK" -ne "$AS_SUBMASK" ];then
#	route add -net $AS_SUBMASK/24 dev $EB_IFACE
#fi

#VS:Configured the East Bound Logical Interface
if [[ "$EB_LI_IPv4" != "" ]]; then
	if [[ "$EB_LI_IFACE" == "" ]]; then
		echo "ERROR:East Bound(EB_LI_IFACE) S5S8 Logical Interface Name Not Configured"
		exit
	fi
	ifconfig $EB_LI_IFACE $EB_LI_IPv4/24

	if [[ "$EB_LI_IPv6" != "" ]];then
		if [[ "$EB_IFACE" == "" ]]; then
			echo "ERROR:East Bound(EB_IFACE) S5S8 Interface Name Not Configured"
			exit
		fi
		ifconfig $EB_IFACE inet6 add $EB_LI_IPv6
		ifconfig $EB_IFACE up
	fi
elif [[ "$EB_LI_IPv6" != "" ]];then
	if [[ "$EB_IFACE" == "" ]]; then
		echo "ERROR:East Bound(EB_IFACE) S5S8 Interface Name Not Configured"
		exit
	fi
	ifconfig $EB_IFACE inet6 add $EB_LI_IPv6
	ifconfig $EB_IFACE up
fi

#Check configured East Bound Interface
ifconfig $EB_IFACE

if [[ "$EB_LI_IPv4" != "" ]]; then
	ifconfig $EB_LI_IFACE
fi
