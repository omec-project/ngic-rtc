/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _SSL_CLIENT_H_
#define _SSL_CLIENT_H_

#include <openssl/ssl.h>

#define SSL_CONN_FAIL -1

/**
 * Initialize ssl connection and verify SGX's parameter
 * from certificate
 * @param hostname
 *	hostname or ip of remote host.
 * @param portnum
 *	port number of remote host.
 * @param client_cert_path
 *	path of client certificate.
 * @param priv_key_path
 *	path of private key.
 * @param mrenclave
 *	mrenclave value read from file
 * @param mrsigner
 *	mrsigner value read from file
 * @param isvsvn
 *	isvsvn value read from file
 *
 * @return
 *	ssl handle - on success
 *	-1 - on failure
 */
SSL *
sgx_cdr_channel_init(const char *hostname, const char *portnum,
			const char *client_cert_path, const char *priv_key_path,
			const char *mrenclave, const char *mrsigner, const char *isvsvn);

/**
 * Free ssl context and close the connection
 * @param ssl
 *	ssl handle.
 */
void
sgx_cdr_channel_close(SSL *ssl);

#endif /* _SSL_CLIENT_H_ */

