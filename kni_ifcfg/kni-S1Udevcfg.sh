#! /bin/bash
source ../config/dp_config.cfg

dp_static_arp_flag="CFLAGS += -DSTATIC_ARP"

#Code to check if STATIC_ARP is enabled or disabled in DP Makefile
if grep -q -e "^$dp_static_arp_flag" ../dp/Makefile; then
	   echo -e ""
	   echo -e "WARNING: STATIC_ARP enabled in dp/Makefile. Enabling kni interfaces along with STATIC_ARP will cause duplicate ARP responses on the wire."
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

ifconfig $UL_IFACE
ifconfig $UL_IFACE $S1U_IP netmask $S1U_MASK
ifconfig $UL_IFACE

#Uncomment below to add route entry for GW_IP
#if [ -n "${S1U_GW_IP}" ]; then
#	route add default gw ${S1U_GW_IP} dev $UL_IFACE
#fi

#Below usecase to be understood
SUBMASK=`echo $S1U_MASK | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
eNB_DEC=`echo $eNB_IP | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
S1U_DEC=`echo $S1U_IP | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`

eNB_SUBMASK="$(($eNB_DEC & $SUBMASK))"
S1U_SUBMASK="$(($S1U_DEC & $SUBMASK))"

#if [ "$S1U_SUBMASK" -ne "$eNB_SUBMASK" ];then
#	route add -net $eNB_SUBMASK/24 dev $UL_IFACE
#fi
