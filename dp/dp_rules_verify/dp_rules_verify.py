#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation

import csv
import sys
import os
import time
import pprint
from rules_parser import ParserManager

# Configuration file path
CONFIG = {
    "ADC_FILE_PATH": "adc_rules.cfg",
    "SDF_FILE_PATH": "sdf_rules.cfg",
    "PCC_FILE_PATH": "pcc_rules.cfg"
}

class Parser(ParserManager):

    def __init__(self, filename):
        super(Parser, self).__init__(CONFIG)
        self.filename = filename
        self.ue_ip = None
        self.app_ip = None
        self.actual_rule_list = {}
        self.fail_lines = []
        self.total_packets = 0
        self.uplink = 0
        self.downlink = 0
        self.direction = None

    def read_csv_file(self):
        """
        Description : Read csv file and do operation
        Agruments : None
        Return : None
        """
        with open(self.filename, 'r') as fobj:
            for data in csv.DictReader(fobj):
                self.ue_ip = data['ue_ip']
                self.app_ip = data['app_ip']
                self.direction = data['direction']
                # Count uplink, downlink and total packets
                self.total_packets += 1
                if self.direction == 'UL':
                    self.uplink += 1
                elif self.direction == 'DL':
                    self.downlink += 1
                # Creating dictionary of expected rules
                if not self.actual_rule_list.has_key((self.ue_ip, self.app_ip,
                                                      self.direction)):
                    if self.debugging_flag:
                        print "-" * 80
                        print "Finding Rule for ue_ip: {0} and app_ip: {1} - Direction: {2}"\
                            .format(self.ue_ip, self.app_ip, self.direction)
                        print "-" * 80
                    rule_filter = self.search_filter(
                        self.direction, self.ue_ip, self.app_ip)
                    self.actual_rule_list[(
                        self.ue_ip, self.app_ip, self.direction)] = rule_filter
                # Verify actual rule with expected rule
                self.verify_rules(data)

    def verify_rules(self, data):
        """
        Description : Function to verify actual rules with expected rules
        Agruments : data - Single packet from *.csv file
        Return : None
        """
        # Get actual rule list
        actual_val = self.actual_rule_list[(
            self.ue_ip, self.app_ip, self.direction)]

        # Verify adc rule
        if actual_val.has_key("RuleID"):
            # Get rule id of adc
            rule_id_adc = actual_val['RuleID'].split("_")[-1]
            # Get action value of adc
            action = None
            if bool(int(actual_val['Action'])):
                action = "CHARGED"
            else:
                action = "DROPPED"

            if data['pcc_rule_id'] != rule_id_adc or data['filter_type'] != \
                    actual_val['Filter_Type'] or data['pcc_rule_name'] != \
                    actual_val['Name'] or data['action'] != action:
                data['act_pcc_rule_id'] = rule_id_adc
                data['act_pcc_rule_id'] = rule_id_adc
                data['act_filter_type'] = actual_val['Filter_Type']
                data['act_rule_name'] = actual_val['Name']
                data['act_action'] = action
                self.fail_lines.append(data)

    def print_fail_rows(self):
        """
        Description : Function to print all uplink and downlink rules which
                      are failed
        Agruments : None
        Return : Fail uplink and downlink packets list
        """
        fail_uplink = 0
        fail_downlink = 0
        print "*" * 30 + "Fail Packets" + "*" * 30
        print "-" * 150
        print "{:<17}{:<17}{:<15}{:<15}{:<15}{:<15}{:<15}{:<15}{:<15}{}".\
            format('Actual', 'Actual', 'Actual', 'Actual', 'Actual', 'Actual',
                   'Expected', 'Expected', 'Expected', 'Expected')
        print "{:<17}{:<17}{:<15}{:<15}{:<15}{:<15}{:<15}{:<15}{:<15}{}".\
            format('ue_ip', 'app_ip', 'pcc_rule_id', 'filter_type', 'rule_name',
                   'action', 'pcc_rule_id', 'filter_type', 'rule_name', 'action')
        print "-" * 150
        for line in self.fail_lines:
            print "{:<17}{:<17}{:<15}{:<15}{:<15}{:<15}{:<15}{:<15}{:<15}{}".\
                format(line['ue_ip'], line['app_ip'], line['pcc_rule_id'],
                       line['filter_type'], line['pcc_rule_name'], line['action'],
                       line['act_pcc_rule_id'], line['act_filter_type'],
                       line['act_rule_name'], line['act_action'])
            # Count fail uplink packets
            if line['direction'] == 'UL':
                fail_uplink += 1
            # Count fail downling packets
            elif line['direction'] == 'DL':
                fail_downlink += 1
        print "-" * 150
        return fail_uplink, fail_downlink

    def print_result(self):
        """
        Description : Function to print PASS/FAIL downlink and uplink packets
                      count
        Agruments : None
        Return : None
        """
        if self.fail_lines:
            fail_uplink, fail_downlink = self.print_fail_rows()
            pass_uplink = self.uplink - fail_uplink
            pass_downlink = self.downlink - fail_downlink
            total_pass = pass_uplink + pass_downlink
            total_fail = fail_uplink + fail_downlink

            print "*" * 30 + "Summary" + "*" * 30
            print "Total Uplink Packets : {:10}    PASS: {:<5}  FAIL: {}".\
                format(self.uplink, pass_uplink, fail_uplink)
            print "Total Downlink Packets : {:8}    PASS: {:<5}  FAIL: {}".\
                format(self.downlink, pass_downlink, fail_downlink)
            print "Total Packets : {:>17}    PASS: {:<5}  FAIL: {}".\
                format(self.total_packets, total_pass, total_fail)
            print "*" * 67
        else:
            print "*" * 30
            print "Pass : All packets matched"
            print "*" * 30
            print "Total Uplink Packets : {:10}".format(self.uplink)
            print "Total Downlink Packets : {:8}".format(self.downlink)
            print "Total Packets : {:>17}".format(self.total_packets)
            print "*" * 30

if __name__ == "__main__":
    arguments = sys.argv[1:]
    if len(arguments) == 2:
        if arguments[0].endswith(".csv"):
            file_path = arguments[0]
        else:
            file_path = arguments[0] + ".csv"
    else:
        print "Please enter the valid arguments as following syntax:"
        print "python dp_rules_verify.py <Path to extended csv file> <Path to rules "\
            "configuration files>"
        sys.exit()
    # Creating config file path
    if not arguments[1].lower() == 'local':
        for key, val in CONFIG.iteritems():
            CONFIG[key] = arguments[1] + '/' + val
            if not os.path.isfile(CONFIG[key]):
                print "{} File Not Found".format(CONFIG[key])
                sys.exit()
     # Creating Class object
    obj = Parser(file_path)
    obj.debugging_flag = False
    obj.read_csv_file()
    obj.print_result()
