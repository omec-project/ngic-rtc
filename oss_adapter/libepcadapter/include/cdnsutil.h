/*
* Copyright (c) 2017 Sprint
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef __CDNSUTIL_H
#define __CDNSUTIL_H

#include <stdint.h>

#define MAX_HOSTNAME_LEN 256

#define MAX_PROTO_LEN 16

typedef struct dns_query_result_t {
	char hostname[MAX_HOSTNAME_LEN];

	uint8_t ipv4host_count;
	char **ipv4_hosts;
	uint8_t ipv6host_count;
	char **ipv6_hosts;
} dns_query_result_t;

typedef struct canonical_result_t {
	char cano_name1[MAX_HOSTNAME_LEN];
	dns_query_result_t host1_info;
	char cano_name2[MAX_HOSTNAME_LEN];
	dns_query_result_t host2_info;

} canonical_result_t;

#endif /* __CDNSUTIL_H */
