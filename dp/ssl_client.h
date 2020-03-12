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

#ifndef _SSL_CLIENT_H_
#define _SSL_CLIENT_H_

#include <openssl/ssl.h>

#define SSL_CONN_FAIL -1

/**
 * @brief  : Initialize ssl connection and verify SGX's parameter from certificate
 * @param  : hostname, hostname or ip of remote host.
 * @param  : portnum, port number of remote host.
 * @param  : client_cert_path, path of client certificate.
 * @param  : priv_key_path, path of private key.
 * @param  : mrenclave, mrenclave value read from file
 * @param  : mrsigner, mrsigner value read from file
 * @param  : isvsvn, isvsvn value read from file
 * @return : Returns ssl handle on success, -1 otherwise
 */
SSL *
sgx_cdr_channel_init(const char *hostname, const char *portnum,
			const char *client_cert_path, const char *priv_key_path,
			const char *mrenclave, const char *mrsigner, const char *isvsvn);

/**
 * @brief  : Free ssl context and close the connection
 * @param  : ssl, ssl handle.
 * @return : Return nothing
 */
void
sgx_cdr_channel_close(SSL *ssl);

#endif /* _SSL_CLIENT_H_ */

