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

#include <stdio.h>

#include "redis_client.h"

redisContext *ctx = NULL;

redisContext* redis_connect(redis_config_t* cfg)
{
	redisContext *ctx = NULL;

	if (cfg->type == REDIS_TCP) {
		ctx = redisConnectWithTimeout(cfg->conf.tcp.host,
				cfg->conf.tcp.port, cfg->conf.tcp.timeout);
	} else if (cfg->type == REDIS_SSL) {

	} else {
		/* TODO: Add log*/;
	}

	if (ctx == NULL) {
		/* TODO: Add log and remove printf */
		return NULL;
	} else if (ctx->err) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Connection error: %s\n", ctx->errstr);
		/* TODO: Add log and remove printf */
		redisFree(ctx);
		return NULL;
	}

	redisCommand(ctx, "SADD connected_cp %s", cfg->cp_ip);
	return ctx;
}

int redis_save_cdr(redisContext* ctx, char *cp_ip, char* cdr)
{
	redisCommand(ctx,"LPUSH %s %s", cp_ip, cdr);
	return 0;
}

int redis_disconnect(redisContext* ctx)
{
	redisFree(ctx);
	return 0;
}
