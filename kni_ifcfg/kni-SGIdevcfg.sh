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

ifconfig $DL_IFACE
ifconfig $DL_IFACE $SGI_IP netmask $SGI_MASK
ifconfig $DL_IFACE

#Uncomment below to add route entry for GW_IP
#if [ -n "${SGI_GW_IP}" ]; then
#	route add default gw ${SGI_GW_IP} dev $DL_IFACE
#fi

#Below usecase to be understood
SUBMASK=`echo $SGI_MASK | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
AS_DEC=`echo $AS_IP | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`
SGI_DEC=`echo $SGI_IP | tr . '\n' | awk '{t = t*256 + $1} END{printf "%.f", t}'`

AS_SUBMASK="$(($AS_DEC & $SUBMASK))"
SGI_SUBMASK="$(($SGI_DEC & $SUBMASK))"

#if [ "$SGI_SUBMASK" -ne "$AS_SUBMASK" ];then
#	route add -net $AS_SUBMASK/24 dev $DL_IFACE
#fi
