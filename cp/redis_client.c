/*
 * Copyright (c) 2019 Sprint
 * Copyright (c) 2020 T-Mobile
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

extern int clSystemLog;
redisContext *ctx = NULL;
redisSSLContext *ssl = NULL;

redisContext* redis_connect(redis_config_t* cfg)
{
	redisContext *ctx = NULL;
	redisSSLContextError ssl_error = 0;

	if ( redisInitOpenSSL() != REDIS_OK ) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to initialize SSL connection "
				"with redis server", LOG_VALUE);
		return NULL;
	}

	if (cfg->type == REDIS_TCP) {
		ctx = redisConnectWithTimeout(cfg->conf.tcp.host,
				cfg->conf.tcp.port, cfg->conf.tcp.timeout);
	} else if (cfg->type == REDIS_TLS) {

		redisOptions options = {0};
		REDIS_OPTIONS_SET_TCP(&options, cfg->conf.tls.host,
				cfg->conf.tls.port);
		options.timeout = &cfg->conf.tls.timeout;
		options.endpoint.tcp.source_addr = cfg->cp_ip;

		ctx = redisConnectWithOptions(&options);
		 if (ctx == NULL || ctx->err) {
			if (ctx) {
				clLog(clSystemLog, eCLSeverityCritical,
						"Connection error: %s\n", ctx->errstr);
				redisFree(ctx);
			} else {
				clLog(clSystemLog, eCLSeverityCritical,
						"Connection error: can't allocate"
						 "redis context\n");
			}
			return NULL;
		 }

		 ssl = redisCreateSSLContext(cfg->conf.tls.ca_cert_path, NULL,
				 cfg->conf.tls.cert_path, cfg->conf.tls.key_path, NULL, &ssl_error);
		 if (!ssl) {
			 clLog(clSystemLog, eCLSeverityCritical,
					 "Error: %s\n", redisSSLContextGetError(ssl_error));
			 redisFree(ctx);
			 return NULL;
		 }

		 if (redisInitiateSSLWithContext(ctx, ssl) != REDIS_OK) {
			 clLog(clSystemLog, eCLSeverityCritical,
					"Couldn't initialize SSL!\n");
			clLog(clSystemLog, eCLSeverityCritical,
					 "Error: %s\n", ctx->errstr);
			redisFree(ctx);
			redisFreeSSLContext(ssl);
			return NULL;
		}
	} else {
		clLog(clSystemLog, eCLSeverityCritical,"Invalid"
				"Connection Type.only TCP and"
				"TLS is supported");
		return NULL;
	}

	if (ctx == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,"Connection"
				"Failed\n");
		return NULL;
	} else if (ctx->err) {
		clLog(clSystemLog, eCLSeverityCritical,
			"Connection error: %s\n", ctx->errstr);
		redisFree(ctx);
		redisFreeSSLContext(ssl);
		return NULL;
	}

	redisCommand(ctx, "SADD connected_cp %s", cfg->cp_ip);
	return ctx;
}

int redis_save_cdr(redisContext* ctx, char *cp_ip, char* cdr)
{
	redisCommand(ctx, "LPUSH %s %s", cp_ip, cdr);
	return 0;
}

int redis_disconnect(redisContext* ctx)
{
	redisFree(ctx);
	redisFreeSSLContext(ssl);
	return 0;
}
