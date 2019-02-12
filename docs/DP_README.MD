Copyright (c) 2017 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

NGIC Data Plane
===============

1. CDR flush to file.
---------------------
The API ue_cdr_flush(), flush the CDR of any session to a file.
This API accepts session id as key parameters and flush the CDR records.
The field cdr type can be set for specific type of records,
which can be one of CDR_TYPE_BEARER, CDR_TYPE_ADC, CDR_TYPE_FLOW,
CDR_TYPE_RG(rating group) or CDR_TYPE_ALL.
An action field can be set to append or replace the log file.
Please refer "struct msg_ue_cdr" for details.
Charging stats are exported without resetting CDRs in DP.
The file to which stats are dumped is located at "/var/log/dpn/session_cdr.csv".
