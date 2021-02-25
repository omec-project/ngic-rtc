#!/usr/bin/env python

####################################
#
# Redis Test Script
#
####################################

import redis
import sys
import pydoc
import os
import datetime
import pytz
import time
import csv


# Macros
CONNECTED_CP_KEY_NAME = "connected_cp"
NUM_CDR_PARAM = 55
CSV_FIELD_NAME = [
                    "cdr_seq_num",
                    "record_type",
                    "rat_type",
                    "selection_mode",
                    "imsi",
                    "LAI",
                    "TAI",
                    "ECGI",
                    "RAI(RAC)",
                    "RAI(LAC)",
                    "CGI(LAC)",
                    "CGI(CI)",
                    "SAI(LAC)",
                    "SAI(SAC)",
                    "Macro eNb (ID1)",
                    "Macro eNb (ID2)",
                    "Extended Macro eNb (ID1)",
                    "Extended Macro eNb (ID2)",
                    "unique_bearer_id",
                    "CP_SEID",
                    "DP_SEID",
                    "rule_name",
		    "seq_no_of_bearer",
                    "cause_for_record_closing",
                    "apn_name",
                    "QCI",
                    "preemption_vulnerability",
                    "priority_level",
                    "preemption_capability",
                    "ul_mbr",
                    "dl_mbr",
                    "ul_gbr",
                    "dl_gbr",
                    "start_time",
                    "end_time",
                    "data_start_time",
                    "data_end_time",
                    "mcc",
                    "mnc",
                    "UE_IP",
                    "CP_IP",
                    "DP_IP",
                    "S11_SGW_IP",
                    "S11_MME_IP",
                    "S5S8C_SGW_IP",
                    "S5S8C_PGW_IP",
                    "S1U_SGW_IP",
                    "S1U_ENB_IP",
                    "S5S8U_SGW_IP",
                    "S5S8U_PGW_IP",
                    "data_vol_uplink",
                    "data_vol_downlink",
                    "total_volume",
                    "duration_measurement",
                    "pdn_type"
                ]


class RedisDB:

    def __init__(self, host, port):
        # Establish a connection with Redis Server
        self._redis = redis.StrictRedis(host=host, port=port, db=0)
        if self._redis:
            print("\nConnection Established with the Redis Server... : %s\n" % host)

    @staticmethod
    def get_current_time():
        ret = datetime.datetime.now(pytz.timezone('Asia/Kolkata'))
        return str(ret).split(".")[0].replace(" ", '_')

    def get_connected_cp(self):
        """ Read Ip and CDR table
        """
        return self._redis.smembers(CONNECTED_CP_KEY_NAME)

    def cp_pretty_print(self, cp_list):
        print("-" * 30)
        for cp in range(len(cp_list)):
            print("{0}) {1}".format(cp + 1, cp_list[cp]))
        print("-" * 30)

    def get_cdr(self, cp_ip):
        return self._redis.lrange(str(cp_ip), 0, -1)

    def dump_data_into_csv(self, cp_ip):
        """ Dump the cdr list into CSV file
        """
        cdr_lst = self.get_cdr(cp_ip)

        # Prepare CSV file name
        file_name = "{ip}_{time}.csv".format(ip=cp_ip, time=RedisDB.get_current_time())
        # Open CSV and dump data into CSV
        with open("log/" + file_name, 'w') as csv_ptr:
            # Dump header data into csv
            csv_writer = csv.DictWriter(csv_ptr, fieldnames=CSV_FIELD_NAME)
            csv_writer.writeheader()

            # Start reading CDR data list
            for cdr in cdr_lst:
                cdr_data_lst = cdr.split(',')
                # Dump cdr entry into csv if it consist of expected number of 24  fields
                if len(cdr_data_lst) == NUM_CDR_PARAM:
                    csv_data_dict = { CSV_FIELD_NAME[index]: str(cdr_data_lst[index]) for index in range(len(CSV_FIELD_NAME))}
                    csv_writer.writerow(csv_data_dict)
                else:
                    print("\nThere is no enough field in cdr: %s" % cdr)
                    print("Skipping this CDR entry and do not dumping into CSV file...\n")
            print("\n{0}\nCDR data written into file : log/{1}\n{0}\n".format("*" * 80, file_name))

    def print_warning_msg(self):
        print('\n' + "*" * 42)
        print("You have selected invalid option...")
        print("valid choice number are in between: {0} - {1}".format(1, len(self.get_connected_cp())))
        print("*" * 42 + '\n')


# Entry Point
if __name__ == '__main__':

    # Validate cmd line arguments
    if len(sys.argv) < 3:
        help_str = """
        Please provide the IP and Port number as command line argument

        Example:
        --------
        python redis.py 10.73.80.113 6379
        """
        print(help_str)
        sys.exit()

    # Check for log directory availability
    if not os.path.isdir("log"):
        os.mkdir("log")

    # Redis Server configuration
    HOST_IP = sys.argv[1]
    PORT_NUM = sys.argv[2]

    # Create redis class object
    redis = RedisDB(HOST_IP, PORT_NUM)

    while True:
        # Get Cp list
        cp_lst = list(redis.get_connected_cp())

        # connected cp list pretty_print
        print("CP LIST")
        redis.cp_pretty_print(cp_lst)

        if not cp_lst:
            print("There is no CP in list...")
            time.sleep(30)
            continue

        try:
            input_num = input("\nPlease select CP to get CDR list : ")
        except Exception as err:
            redis.print_warning_msg()
            continue

        if not (str(input_num).isdigit()
                and int(input_num) <= len(cp_lst)):
            redis.print_warning_msg()
            continue
        else:
            redis.dump_data_into_csv(cp_lst[input_num-1])
            cnt_key = raw_input("Press Enter to continue or type quit to exit...\n")
            if cnt_key == "quit":
                break
            continue

