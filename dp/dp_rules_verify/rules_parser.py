# Copyright (c) 2017 Intel Corporation
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

import ipaddress
import pprint
from ConfigParser import SafeConfigParser


class Utility(object):
    """
     Helping library methods
    """
    @staticmethod
    def check_ip_range(source, ip_with_mask):
        """
        Description : Function to check the source in given ip range
        Agruments : source ip and ip with its mask
        Return : True if its in range else False
        """
        try:
            # Verify IP range
            return ipaddress.ip_address(unicode(source)) in ipaddress.\
                ip_network(unicode(ip_with_mask))
        except ValueError:
            # handling of case "ValueError: 13.1.1.112/24 has host bits set"
            # set ip to 13.1.1.0/24 then compare
            ip_with_mask = ip_with_mask.split("/")
            tmp = ip_with_mask[0].split(".")
            tmp[3] = "0"
            ip_with_mask = ".".join(tmp) + "/" + ip_with_mask[1]
            try:
                return ipaddress.ip_address(unicode(source)) in ipaddress.\
                    ip_network(unicode(ip_with_mask))
            except Exception, err:
                print "Exception in Utility.check_ip_range: %s" % (str(err))
        except Exception, err:
            print "Something weired exception: %s" % (str(err))
        return False


class ParserManager(object):
    """ parser manager
    """

    def __init__(self, config={}):
        self.config = config
        self.parser = None
        self.ADC_RULES = self.parse_adc()
        self.SDF_RULES = self.parse_sdf()
        self.PCC_RULES = self.parse_pcc()
        self.debugging_flag = False

    def parse_adc(self):
        """ 
        Description : Function to parse adc configuration file
        Agruments : None
        Return : Adc parse rules dictionary        
        """
        if not self.config.get('ADC_FILE_PATH'):
            print "Input error"
            return {}
        adc_rules = []
        self.parser = SafeConfigParser()
        self.parser.read(self.config.get('ADC_FILE_PATH'))
        for each_section in self.parser.sections():
            # parse only rules ignore rest
            if "ADC_RULE" in each_section:  
                res = {}
                adc_type = 0
                ue_ip = "0.0.0.0"
                app_ip = "0.0.0.0"
                src_port = "0:65535"
                dest_port = "0:65535"
                priority = "0x1/0x0"
                prefix = 0
                for (key, val) in self.parser.items(each_section):
                    if "adc_type" in key:
                        adc_type = val
                    if "ip" in key or "domain" in key:
                        app_ip = val
                    if "prefix" in key:
                        prefix = val
                if prefix:
                    app_ip += "/" + str(prefix)
                res = {
                    'RuleID': each_section,
                    'Ue_Ip': ue_ip,
                    'App_Ip': app_ip,
                    'Src_Port': src_port,
                    'Dest_Port': dest_port,
                    'Priority': priority,
                    'Adc_Type': adc_type
                }
                adc_rules.append(res)
        return adc_rules

    def parse_sdf(self):
        """ 
        Description : Function to parse sdf configuration file
        Agruments : None
        Return : Sdf parse rules dictionary   
        """
        self.parser = SafeConfigParser()
        self.parser.read(self.config.get('SDF_FILE_PATH'))
        PCC_RULE_ID = 0
        sdf_rules = []
        for val in self.parser.sections():
            DIRECTION = 'bidirectional'
            LOCAL_IP = '0.0.0.0'
            LOCAL_IP_MASK = 0
            IPV4_REMOTE = '0.0.0.0'
            IPV4_REMOTE_MASK = 0
            LOCAL_LOW_LIMIT_PORT = 0
            LOCAL_HIGH_LIMIT_PORT = 65535
            REMOTE_LOW_LIMIT_PORT = 0
            REMOTE_HIGH_LIMIT_PORT = 65535
            PROTOCOL = hex(0)
            PROTOCOL_MASK = hex(0)

            if val != 'GLOBAL':
                PCC_RULE_ID += 1
                if PCC_RULE_ID > 1:
                    PROTOCOL_MASK = '0xff'
                if self.parser.has_option(val, 'DIRECTION'):
                    DIRECTION = str(self.parser.get(val,
                                                    'DIRECTION'))

                if self.parser.has_option(val, 'IPV4_LOCAL'):
                    LOCAL_IP = str(self.parser.get(val,
                                                   'IPV4_LOCAL'))

                if self.parser.has_option(val, 'IPV4_LOCAL_MASK'):
                    LOCAL_IP_MASK = str(self.parser.get(val,
                                                        'IPV4_LOCAL_MASK'))

                if self.parser.has_option(val, 'IPV4_REMOTE'):
                    IPV4_REMOTE = str(self.parser.get(val,
                                                      'IPV4_REMOTE'))

                if self.parser.has_option(val, 'IPV4_REMOTE_MASK'):
                    IPV4_REMOTE_MASK = self.parser.get(
                        val,  'IPV4_REMOTE_MASK')

                if self.parser.has_option(val, 'PROTOCOL'):
                    PROTOCOL = hex(int(self.parser.get(val,
                                                       'PROTOCOL')))

                if self.parser.has_option(val, 'PROTOCOL_MASK'):
                    PROTOCOL_MASK = int(self.parser.get(val,
                                                        'PROTOCOL_MASK'))

                if self.parser.has_option(val, 'LOCAL_LOW_LIMIT_PORT'):
                    LOCAL_LOW_LIMIT_PORT = int(self.parser.get(val,
                                                        'LOCAL_LOW_LIMIT_PORT'))

                if self.parser.has_option(val, 'LOCAL_HIGH_LIMIT_PORT'):
                    LOCAL_HIGH_LIMIT_PORT = int(self.parser.get(val,
                                                    'LOCAL_HIGH_LIMIT_PORT'))

                if self.parser.has_option(val, 'REMOTE_LOW_LIMIT_PORT'):
                    REMOTE_LOW_LIMIT_PORT = int(self.parser.get(val,
                                                    'REMOTE_LOW_LIMIT_PORT'))

                if self.parser.has_option(val, 'REMOTE_HIGH_LIMIT_PORT'):
                    REMOTE_HIGH_LIMIT_PORT = int(self.parser.get(val,
                                                    'REMOTE_HIGH_LIMIT_PORT'))
                if LOCAL_IP_MASK == '255.255.255.255':
                    LOCAL_IP_MASK = 32

                if IPV4_REMOTE_MASK == '255.255.255.255':
                    IPV4_REMOTE_MASK = 32

                sdf_rules.append({
                    'RuleID': val,
                    'Direction': DIRECTION,
                    'Local_IP': LOCAL_IP + "/" + str(LOCAL_IP_MASK),
                    'Local_High_Port': LOCAL_HIGH_LIMIT_PORT,
                    'Local_Low_Port': LOCAL_LOW_LIMIT_PORT,
                    'Local_High_Port': LOCAL_HIGH_LIMIT_PORT,
                    'Remote_IP': IPV4_REMOTE + "/" + str(IPV4_REMOTE_MASK),
                    'Remote_Low_Port': REMOTE_LOW_LIMIT_PORT,
                    'Remote_High_Port': REMOTE_HIGH_LIMIT_PORT,
                    'Protocol': PROTOCOL,
                    'Protocol_Mask': PROTOCOL_MASK
                })

                if DIRECTION == 'bidirectional':
                    sdf_rules.append({
                        'RuleID': val,
                        'Direction': DIRECTION,
                        'Local_IP': IPV4_REMOTE + "/" + str(IPV4_REMOTE_MASK),
                        'Local_Low_Port': LOCAL_LOW_LIMIT_PORT,
                        'Local_High_Port': LOCAL_HIGH_LIMIT_PORT,
                        'Remote_IP': LOCAL_IP + "/" + str(LOCAL_IP_MASK),
                        'Remote_Low_Port': REMOTE_LOW_LIMIT_PORT,
                        'Remote_High_Port': REMOTE_HIGH_LIMIT_PORT,
                        'Protocol': PROTOCOL,
                        'Protocol_Mask': PROTOCOL_MASK
                    })
        return sdf_rules

    def parse_pcc(self):
        """
        Description : Function to parse pcc configuration file
        Agruments : None
        Return : Pcc parse rules dictionary   
        """
        self.parser = SafeConfigParser()
        self.parser.read(self.config.get('PCC_FILE_PATH'))
        PRECEDENCE = 0
        Name = ""
        pcc_rules = []
        for val in self.parser.sections():
            if "PCC_FILTER" in val:
                SDF_FILTER_IDX = None
                ADC_FILTER_IDX = None
                if self.parser.has_option(val, 'SDF_FILTER_IDX'):
                    SDF_FILTER_IDX = str(
                        self.parser.get(val, 'SDF_FILTER_IDX'))
                    SDF_FILTER_IDX = [id.strip()
                                      for id in SDF_FILTER_IDX.split(",") if id]

                if self.parser.has_option(val, 'ADC_FILTER_IDX'):
                    ADC_FILTER_IDX = str(self.parser.get(val, 'ADC_FILTER_IDX'))

                if self.parser.has_option(val, 'PRECEDENCE'):
                    PRECEDENCE = str(self.parser.get(val, 'PRECEDENCE'))

                if self.parser.has_option(val, 'Rule_Name'):
                    Name = str(self.parser.get(val, 'Rule_Name'))

                if self.parser.has_option(val, 'GATE_STATUS'):
                    action1 = str(self.parser.get(val, 'GATE_STATUS'))
                pcc_rules.append({
                    'RuleID': val,
                    'Sdf_ID': SDF_FILTER_IDX,
                    'Adc_ID': ADC_FILTER_IDX,
                    'Precedence': PRECEDENCE,
                    'Name': Name,
                    'Action': action1
                })
        return pcc_rules

    def search_adc(self, direction, ue_ip, app_ip=None):
        """
        Description : Function to search rule in adc config file
        Arguments : direction - packet direction (uplink or downlink)
                    ue_ip - user equipment ip
                    app_ip - application ip
        Result : Matched pcc rule
        """
        if self.debugging_flag:
            print "-------- Searching in ADC -----------"
        filter_adc_rule = []
        for conf in self.ADC_RULES:
            # Check exact ip match
            if conf['Adc_Type'] == '1':
                if app_ip == conf['App_Ip']:
                    filter_adc_rule.append(conf)
            # Check in range
            if conf['Adc_Type'] == '2':
                if Utility.check_ip_range(app_ip, conf['App_Ip']):
                    filter_adc_rule.append(conf)
            # Check for domain
            if conf['Adc_Type'] == '0':
                if app_ip == conf['App_Ip']:
                    filter_adc_rule.append(conf)

        if self.debugging_flag:
            pprint.pprint(filter_adc_rule)

        priority = -1
        filter_pcc = None
        for filter_adc in filter_adc_rule:
            # Get the rule number and search it in pcc rule
            rule_id = filter_adc['RuleID'].split("ADC_RULE_")[1]
            for conf in self.PCC_RULES:
                # check the highest precedence and assign to filter_pcc from pcc
                # rules
                if rule_id == conf['Adc_ID']:
                    if priority == -1:
                        priority = int(conf['Precedence'])
                        filter_pcc = conf
                    else:
                        if priority > int(conf['Precedence']):
                            priority = int(conf['Precedence'])
                            filter_pcc = conf

        if filter_pcc:
            if self.debugging_flag:
                print "Found rule in PCC configration"
            filter_pcc['Filter_Type'] = "ADC"
            if self.debugging_flag:
                pprint.pprint(filter_pcc)
            return filter_pcc
        return {}

    def search_sdf(self, direction, ue_ip=None, app_ip=None):
        """
        Description : Function to search rule in sdf config file
        Arguments : direction - packet direction (uplink or downlink)
                    ue_ip - user equipment ip
                    app_ip - application ip
        Result : Matched sdf rule
        """
        if self.debugging_flag:
            print "-------- Searching in SDF -----------"
        result = []
        tmp = []
        # Verify SDF rule of Uplink direction
        if direction == 'UL':
            for conf in self.SDF_RULES:
                if conf['Direction'] == "uplink_only":
                    if Utility.check_ip_range(ue_ip, conf['Local_IP']):
                        if app_ip:
                            if Utility.check_ip_range(app_ip, conf['Remote_IP']):
                                if not conf['RuleID'] in tmp:
                                    tmp.append(conf['RuleID'])
                                    result.append(conf)
        # Verify SDF rule of downling direction
        if direction == "DL":
            ue_ip, app_ip = app_ip, ue_ip
            for conf in self.SDF_RULES:
                if conf['Direction'] == "downlink_only":
                    if Utility.check_ip_range(ue_ip, conf['Remote_IP']):
                        if app_ip:
                            if Utility.check_ip_range(app_ip, conf['Local_IP']):
                                if not conf['RuleID'] in tmp:
                                    tmp.append(conf['RuleID'])
                                    result.append(conf)
        if self.debugging_flag:
            pprint.pprint(result)
        filter_pcc = []
        for conf in self.PCC_RULES:
            for res in result:
                rule_id = res['RuleID'].split("SDF_FILTER_")[1]
                flag = True
                if conf['Sdf_ID']:
                    for tmp_rule_id in conf['Sdf_ID']:
                        if rule_id != tmp_rule_id:
                            flag = False
                    if flag:
                        filter_pcc.append(conf)
        # Check the highest precedence
        precedence = -1
        res = None
        if filter_pcc:
            if self.debugging_flag:
                print "Found rule in SDF configration"
            for pcc in filter_pcc:
                if precedence == -1 or precedence > int(pcc['Precedence']):
                    res = pcc
                    precedence = int(pcc['Precedence'])
            res['Filter_Type'] = "SDF"
        if self.debugging_flag:
            pprint.pprint(res)
        return res

    def search_filter(self, direction, ue_ip, app_ip=None):
        """
        Description : Function to calculate actual matched rule with the basis 
                      of adc and sdc rule precedence 
        Arguments : direction - packet direction (uplink or downlink)
                    ue_ip - user equipment ip
                    app_ip - application ip
        Result : Matched rule        
        """
        adc_filter = None
        sdf_filter = None
        try:
            adc_filter = self.search_adc(direction, ue_ip, app_ip)
        except Exception, err:
            print str(err)

        try:
            sdf_filter = self.search_sdf(direction, ue_ip, app_ip)
        except Exception, err:
            print str(err)
        # Compare adc and sdf precedence
        if adc_filter and sdf_filter:
            if int(adc_filter['Precedence']) == int(sdf_filter['Precedence']) \
                    or int(adc_filter['Precedence']) < int(sdf_filter['Precedence']):
                return adc_filter
            elif int(adc_filter['Precedence']) > int(sdf_filter['Precedence']):
                return sdf_filter
        if adc_filter:
            return adc_filter
        if sdf_filter:
            return sdf_filter
        return {}