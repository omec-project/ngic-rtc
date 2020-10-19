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

#include <limits.h>

#include "hiredis.h"
#include "hiredis_ssl.h"
#include "clogger.h"

#define REDIS_CONN_TIMEOUT 3
#define IP_STR_LEN 16

typedef enum redis_conn_type_t {
	REDIS_TCP,
	REDIS_TLS
} redis_conn_type_t;

/**
 * @brief  : Maintains redis configuration data
 */
typedef struct redis_config_t {

	redis_conn_type_t type;
	char cp_ip[IP_STR_LEN];

	union conf {
		struct tcp {
			char host[IP_STR_LEN];
			int port;
			struct timeval timeout;
		} tcp;
		struct tls {
			char host[IP_STR_LEN];
			int port;
			char ca_cert_path[PATH_MAX];
			char cert_path[PATH_MAX];
			char key_path[PATH_MAX];
			struct timeval timeout;
		} tls;
	} conf;
} redis_config_t;

/**
 * @brief  : Api to connect to redis server
 * @param  : cfg, configuration data
 * @return : Returns pointer to redis context in case of successs, NULL otherwise
 */
redisContext* redis_connect(redis_config_t *cfg);

/**
 * @brief  : Function to store generated cdr to redis server
 * @param  : ctx, redis context pointer
 * @param  : cp_ip, control plane ip , used as a key
 * @param  : cdr, generated cdr data
 * @return : Returns 0 in case of success, -1 otherwise
 */
int redis_save_cdr(redisContext* ctx, char *cp_ip, char* cdr);

/**
 * @brief  : Api to disconnect from redis server
 * @param  : ctx, redis context pointer
 * @return : Returns 0 in case of success, -1 otherwise
 */
int redis_disconnect(redisContext* ctx);

extern redisContext *ctx;
