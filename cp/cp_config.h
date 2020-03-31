/*
 * Copyright (c) 2019 Sprint
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cp.h"

#ifdef C3PO_OSS
#include "cp_adapter.h"
#include "clogger.h"
#include "cstats.h"
#endif /* C3PO_OSS */


/**
* @brief  parse the SGWU/PGWU/SAEGWU IP from config file
*
**/
void
config_cp_ip_port(pfcp_config_t *pfcp_config);

void parse_apn_args(char *temp,char *ptr[3]);

#ifdef C3PO_OSS
void
init_cli_module(pfcp_config_t *pfcp_config);
#endif /* C3PO_OSS */
