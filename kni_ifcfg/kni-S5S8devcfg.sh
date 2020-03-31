#! /bin/bash
source ../config/dp_config.cfg
NET_MASK="255.255.255.0"

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


if [ "$SPGW_CFG" -eq "01" ]; then
	ifconfig $S5S8_IFACE
	ifconfig $S5S8_IFACE $S5S8_SGWU_IP/24
elif [ "$SPGW_CFG" -eq "02" ];
then
	ifconfig $S5S8_IFACE
	ifconfig $S5S8_IFACE $S5S8_PGWU_IP/24
else
	echo "Error: Set appropriate data-plane type.."
	exit
fi

ifconfig $S5S8_IFACE

SUBMASK=`echo $NET_MASK | tr . '\n' | awk '{t = t*256 + $1} END{print t}'`
eNB_DEC=`echo $eNB_IP | tr . '\n' | awk '{t = t*256 + $1} END{print t}'`
#eNB_SUBMASK="$(($eNB_DEC & $SUBMASK))"

if [ "$SPGW_CFG" -eq "01" ]; then
    SGWU_DEV=`echo $S5S8_SGWU_IP | tr . '\n' | awk '{t = t*256 + $1} END{print t}'`
#    SGWU_SUBMASK="$(($SGWU_DEV & $SUBMASK))"
elif [ "$SPGW_CFG" -eq "02" ];
then
    PGWU_DEV=`echo $S5S8_SGWU_IP | tr . '\n' | awk '{t = t*256 + $1} END{print t}'`
#    PGWU_SUBMASK="$(($PGWU_DEV & $SUBMASK))"
else
	echo "Error: Set appropriate data-plane type.."
	exit
fi


#Uncomment below to add route entry for GW_IP
#if [ "$SPGW_CFG" -eq "01" ]; then
#   if [ "$SGWU_SUBMASK" -ne "$eNB_SUBMASK" ];then
#   	route add -net $eNB_SUBMASK/24 dev $S5S8_IFACE
#   fi
#elif [ "$SPGW_CFG" -eq "02" ];
#then
#   if [ "$PGWU_SUBMASK" -ne "$eNB_SUBMASK" ];then
#   	route add -net $eNB_SUBMASK/24 dev $S5S8_IFACE
#   fi
#fi

