/*
 * Copyright (c) 2017 Intel Corporation
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

#ifndef _EPC_SPONSDN_H
#define _EPC_SPONSDN_H

#include <netinet/in.h>

/**
 * Initialize sponsored DN
 *
 * @return
 *  - 0: on success
 *  - <0: Error code
 */
int epc_sponsdn_create(uint32_t max_dn);

/**
 * Free sponsored DN resources
 *
 * @return
 *  - None
 */
void epc_sponsdn_free(void);

/**
 * Add single sponsored DNs
 *
 * @param dn
 *	Domain name to add.
 * @param rule
 *	Associated rule identfier.
 * @return
 *  - 0: Success
 *  - <0: Error code on failure
 *
 */
int epc_sponsdn_dn_add_single(char *dn, const unsigned int rule);

/**
 * Add multiple sponsored DNs
 *
 * @param dn
 *	Domain names to add.
 * @param rule_id
 *	Associated rule identfiers.
 * @param num
 *	Number of DNs.
 * @return
 *  - 0: Success
 *  - <0: Error code on failure
 *
 */
int epc_sponsdn_dn_add_multi(char **dn, const unsigned int *rule_id, uint32_t num);

/**
 * Delete sponsored DN
 *
 * @param dn
 *	Domain names to delete
 * @param num
 *	Num of DNs
 *
 * @return
 *  - 0: Success
 *  - <0: Error code on failure
 *
 */
int epc_sponsdn_dn_del(char **dn, unsigned int num);

/**
 * Scan a DNS response for any matching DNs
 *
 * @param resp
 *	DNS response to scan
 * @param len
 *	Response length.
 * @param hname
 *	Host name
 * @param rule_id
 *	Rule identifier.
 * @addr4
 *	Array of IP addresses returned
 * @addr4_cnt
 *	Size of addr4, also return value indicates the number of valid entries
 *	in addr4, addr4_cnt could be larger than the size of addr4
 * @addr6
 *	Array of IP addresses returned
 * @addr6_cnt
 *	Size of addr6, also return value indicates the number of valid entries
 *	in addr6, addr6_cnt could be larger than the size of addr6
 *
 * @return
 *	none
 *
 */
int epc_sponsdn_scan(const char *resp, unsigned len, char *hname,
		     unsigned int *rule_id, struct in_addr *addr4,
		     int *addr4_cnt, char **hname_6, struct in6_addr *addr6,
		     int *addr6_cnt);

#endif	/* _EPC_SPONSDN_H */
