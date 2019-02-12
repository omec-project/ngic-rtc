#!/usr/bin/env python
#
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
#

import sys
import csv
import locale

locale.setlocale(locale.LC_ALL,'')

adcsumflag = False
if '-adcsum' in sys.argv:
  adcsumflag = True
  sys.argv.remove('-adcsum')
checktotalflag = False
check_ul_dl_flag = False
if '-checktotal' in sys.argv:
  checktotalflag = True
  index = sys.argv.index('-checktotal')
  expected_total = int(sys.argv[index+1])
  del(sys.argv[index])
  del(sys.argv[index])
elif '-check_ul_dl' in sys.argv:
  check_ul_dl_flag = True
  index = sys.argv.index('-check_ul_dl')
  expected_ul_total = int(sys.argv[index+1])
  expected_dl_total = int(sys.argv[index+2])
  del(sys.argv[index])
  del(sys.argv[index])
  del(sys.argv[index])
if len(sys.argv)<2:
  print 'Usage: %s [-adcsum] [-checktotal <expected total pkt> | -check_ul_dl <expected ul pkt> <expected dl pkt> ] <cdr csv file name>'%(sys.argv[0])
  sys.exit(1)
filename = sys.argv[1]

print filename
reader = csv.reader(open(filename, "rb"), delimiter=',', quoting=csv.QUOTE_NONE)
header = reader.next()
['#time', 'ue_ip', 'dl_pkt_cnt', 'dl_bytes', 'ul_pkt_cnt', 'ul_bytes', 'rule_id', 'rule_type', 'rule', 'action', 'sponsor_id', 'service_id', 'rate_group', 'tarriff_group', 'tarriff_time']
dl_pkt_cnt_col = header.index('dl_pkt_cnt')
ul_pkt_cnt_col = header.index('ul_pkt_cnt')
rate_group_col = header.index('rate_group')
rule_type_col = header.index('rule_type')

#line = reader.next()
#print line[dl_pkt_cnt_col],line[rate_group_col]
#print line[ul_pkt_cnt_col],line[rate_group_col]

dl_rate_group_count_dict = {}
ul_rate_group_count_dict = {}
for line in reader:
  rule_type = line[rule_type_col]
  rate_group = line[rate_group_col]
  if adcsumflag and rule_type == 'ADC':
      rate_group = 'ADC'
  dl_pkt_cnt = int(line[dl_pkt_cnt_col])
  ul_pkt_cnt = int(line[ul_pkt_cnt_col])
  #print line[dl_pkt_cnt_col],line[rate_group_col]
  #print line[ul_pkt_cnt_col],line[rate_group_col]
  try:
    dl_rate_group_count_dict[rate_group]+=dl_pkt_cnt
  except KeyError:
    dl_rate_group_count_dict.update({rate_group:dl_pkt_cnt})
  try:
    ul_rate_group_count_dict[rate_group]+=ul_pkt_cnt
  except KeyError:
    ul_rate_group_count_dict.update({rate_group:ul_pkt_cnt})

dl_totalcount = 0
ul_totalcount = 0
for key in dl_rate_group_count_dict:
  #print 'Traffic type: %s, pkt count: %d'%(key, dl_rate_group_count_dict[key])
  print 'Traffic type: %s, DL pkt count: %s'%(key, locale.format("%d", dl_rate_group_count_dict[key], grouping=True))
  dl_totalcount+=dl_rate_group_count_dict[key]

for key in ul_rate_group_count_dict:
  #print 'Traffic type: %s, pkt count: %d'%(key, ul_rate_group_count_dict[key])
  print 'Traffic type: %s, UL pkt count: %s'%(key, locale.format("%d", ul_rate_group_count_dict[key], grouping=True))
  ul_totalcount+=ul_rate_group_count_dict[key]

print 'Total pkt DL count: %s'%(locale.format("%d", dl_totalcount, grouping=True))
print 'Total pkt UL count: %s'%(locale.format("%d", ul_totalcount, grouping=True))

if check_ul_dl_flag:
  if expected_dl_total == dl_totalcount and expected_ul_total == ul_totalcount:
    verdict = 'pass'
    result = 0
  else:
    verdict = 'fail'
    result = 1
  print('CDR total pkt count check: %s'%(verdict))
  sys.exit(result)



if checktotalflag:
  if expected_total == dl_totalcount:
    verdict = 'pass'
    result = 0
  else:
    verdict = 'fail'
    result = 1
  print('CDR total pkt count check: %s'%(verdict))
  sys.exit(result)


