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

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/err.h>
#include <arpa/inet.h>

#include <rte_log.h>

#include "sgx_quote.h"

#include "main.h"
#include "ssl_client.h"

#define OID(N) {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, N}
#define ENCLAVE_QUOTE "\"isvEnclaveQuoteBody\":\""
#define REPORT_LENGTH 2048

const uint8_t ias_response_body_oid[] = OID(0x02);

/**
 * @brief  : Maintains attestation verification report data
 */
typedef struct {
	uint8_t ias_report[2*1024];
	uint32_t ias_report_len;
	uint8_t ias_sign_ca_cert[2*1024];
	uint32_t ias_sign_ca_cert_len;
	uint8_t ias_sign_cert[2*1024];
	uint32_t ias_sign_cert_len;
	uint8_t ias_report_signature[2*1024];
	uint32_t ias_report_signature_len;
} attestation_verification_report_t;

/**
 * @brief  : Open socket connection
 * @param  : hostname, remote host name or ip.
 * @param  : port, remote host port.
 * @return : Retruns socket handle in case of success, -1 otherwise
 */
int
openconnection(const char *hostname, int port)
{
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;

	if ((host = gethostbyname(hostname)) == NULL)
		return -1;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long *)(host->h_addr);

	if (connect(sd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(sd);
		return -1;
	}
	return sd;
}


/**
 * @brief  : Initialize ssl context
 * @param  : No param
 * @return : Returns ssl context on success, NULL otherwise
 */
SSL_CTX *
InitCTX(void)
{
	SSL_CTX *ctx;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL)
		return NULL;

	return ctx;
}


/**
 * @brief  : Find the value of oid from certificate extension
 * @param  : ext, certificate extension.
 * @param  : ext_len, certificate extension length.
 * @param  : oid, oid to search.
 * @param  : oid_len, oid length.
 * @param  : val, value of oid.
 * @param  : len, value length.
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
find_oid(const unsigned char *ext, size_t ext_len,
		const unsigned char *oid, size_t oid_len,
		unsigned char **val, size_t *len)
{
	uint8_t *p = (uint8_t *) memmem(ext, ext_len, oid, oid_len);

	if (p == NULL)
		return -1;

	p += oid_len;

	int i = 2;

	*len  =  p[i++] << 8;
	*len +=  p[i++];
	*val  = &p[i++];

	return 0;
}

/**
 * @brief  : EVP decode block
 * @param  : out, output buffer
 * @param  : in, input buffer
 * @param  : in_len , input buffer length
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
EVP_DecodeBlock_wrapper(unsigned char *out,
	const unsigned char *in, int in_len)
{
	unsigned char buf[in_len];

	int ret = EVP_DecodeBlock(buf, in, in_len);

	if (ret == -1)
		return ret;

	if (in[in_len-1] == '=' && in[in_len-2] == '=')
		ret -= 2;
	else if (in[in_len-1] == '=')
		ret -= 1;

	memcpy(out, buf, ret);
	return ret;
}

/**
 * @brief  : Get extension
 * @param  : crt, certificate
 * @param  : oid
 * @param  : oid_len , oid buffer length
 * @param  : data, output buffer
 * @param  : data_len , output buffer length
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
get_extension(const X509 *crt, const unsigned char *oid,
		int oid_len, const unsigned char **data,
		int *data_len)
{
	STACK_OF(X509_EXTENSION) *exts = crt->cert_info->extensions;

	int num_of_exts;

	if (exts)
		num_of_exts = sk_X509_EXTENSION_num(exts);
	else
		num_of_exts = 0;

	if (num_of_exts < 0)
		return -1;

	for (int i = 0; i < num_of_exts; i++) {
		X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);

		if (ex == NULL)
			return -1;

		ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);

		if (obj == NULL)
			return -1;

		if (oid_len != obj->length)
			continue;

		if (memcmp(obj->data, oid, obj->length) == 0) {
			*data = ex->value->data;
			*data_len = ex->value->length;
			break;
		}
	}
	return 0;
}

/**
 * @brief  : Get quote from report
 * @param  : report, report info
 * @param  : report_len, report length
 * @param  : quote, output structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
get_quote_from_report(const uint8_t *report,
		const int report_len, sgx_quote_t *quote)
{
	char buf[report_len + 1];

	memcpy(buf, report, report_len);
	buf[report_len] = '\0';

	const char *json_string = "\"isvEnclaveQuoteBody\":\"";
	char *p_begin = strstr(buf, json_string);

	if (p_begin == NULL)
		return -1;

	p_begin += strlen(json_string);

	const char *p_end = strchr(p_begin, '"');

	if (p_end == NULL)
		return -1;

	const int quote_base64_len = p_end - p_begin;
	uint8_t *quote_bin = malloc(quote_base64_len);
	uint32_t quote_bin_len = quote_base64_len;

	int ret = EVP_DecodeBlock(quote_bin,
			(unsigned char *) p_begin, quote_base64_len);

	if (ret == -1)
		return -1;

	quote_bin_len = ret;

	if (quote_bin_len > sizeof(sgx_quote_t))
		return -1;

	memset(quote, 0, sizeof(sgx_quote_t));
	memcpy(quote, quote_bin, quote_bin_len);
	free(quote_bin);

	return 0;
}

/**
 * @brief  : Get and decode extension
 * @param  : crt, certificate
 * @param  : oid
 * @param  : oid_len , oid buffer length
 * @param  : data, output buffer
 * @param  : data_max_len, data max size
 * @param  : data_len , output buffer length
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
get_and_decode_ext(const X509 *crt, const unsigned char *oid,
		int oid_len, unsigned char *data, int data_max_len,
		unsigned int *data_len)
{
	const unsigned char *ext = NULL;
	int ext_len = 0;

	if (get_extension(crt, oid, oid_len, &ext, &ext_len) != 0)
		return -1;

	if (ext_len * 3 > data_max_len * 4)
		return -1;

	int ret = EVP_DecodeBlock_wrapper(data, ext, ext_len);

	if (ret == -1)
		return -1;

	*data_len = ret;
	return 0;
}

/**
 * @brief  : Extract x509 extension
 * @param  : crt, certificate
 * @param  : attn_report, attestation verification report info
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
extract_x509_extensions(const X509 *crt,
		attestation_verification_report_t *attn_report)
{
	bzero(attn_report, sizeof(*attn_report));
	size_t ias_oid_len = sizeof(ias_response_body_oid);

	if (get_and_decode_ext(crt,
			ias_response_body_oid + 2, ias_oid_len - 2,
			attn_report->ias_report, sizeof(attn_report->ias_report),
			&attn_report->ias_report_len) != 0)
		return -1;

	return 0;
}

/**
 * @brief  : Verifies SGX's parameter from certificate
 * @param  : crt, certificate.
 * @param  : mrenclave, mrenclave value read from file
 * @param  : mrsigner, mrsigner value read from file
 * @param  : isvsvn, isvsvn value read from file
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
verify_sgx_crt_info(X509 *crt, const char *mrenclave,
		const char *mrsigner, const char *isvsvn)
{
	int der_len = i2d_X509(crt, NULL);

	if (der_len <= 0)
		return -1;

	attestation_verification_report_t attn_report;

	if (extract_x509_extensions(crt, &attn_report) != 0)
		return -1;

	sgx_quote_t quote = {0, };

	if (get_quote_from_report(attn_report.ias_report,
			attn_report.ias_report_len, &quote) != 0)
		return -1;

	sgx_report_body_t *body = &quote.report_body;

#if 1
	clLog(clSystemLog, eCLSeverityDebug,"Certificate's SGX information: \n");
	clLog(clSystemLog, eCLSeverityDebug,"MRENCLAVE = ");

	for (int i = 0; i < SGX_HASH_SIZE; ++i)
		clLog(clSystemLog, eCLSeverityDebug,"%02x", body->mr_enclave.m[i]);
	clLog(clSystemLog, eCLSeverityDebug,"\n");

	clLog(clSystemLog, eCLSeverityDebug,"MRSIGNER  = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i)
		clLog(clSystemLog, eCLSeverityDebug,"%02x", body->mr_signer.m[i]);
	clLog(clSystemLog, eCLSeverityDebug,"\n");

	clLog(clSystemLog, eCLSeverityDebug,"ISVSVN  = ");
	clLog(clSystemLog, eCLSeverityDebug,"%02x\n", body->isv_svn);
	clLog(clSystemLog, eCLSeverityDebug,"\n");
#endif

	char cert_mr_enclave[SGX_HASH_SIZE * 2 + 1] = {0,};
	char cert_mr_signer[SGX_HASH_SIZE * 2 + 1] = {0,};

	for (int i = 0; i < SGX_HASH_SIZE; ++i) {
		sprintf(cert_mr_enclave + i*2, "%02x", body->mr_enclave.m[i]);
		sprintf(cert_mr_signer + i*2, "%02x", body->mr_signer.m[i]);
	}

	if ((strncmp(cert_mr_enclave, mrenclave, SGX_HASH_SIZE * 2) != 0) ||
			(strncmp(cert_mr_signer, mrsigner, SGX_HASH_SIZE * 2) != 0) ||
			(body->isv_svn != atoi(isvsvn))) {
			clLog(clSystemLog, eCLSeverityCritical, "Not a trusted DealerIn, Disconnecting\n");
			return -1;
	}

	return 0;
}


/**
 * @brief  : Verify SGX's parameter from certificate
 * @param  : ssl, certificate.
 * @param  : mrenclave, mrenclave value read from file
 * @param  : mrsigner, mrsigner value read from file
 * @param  : isvsvn, isvsvn value read from file
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
verify_cert(SSL *ssl, const char *mrenclave,
		const char *mrsigner, const char *isvsvn)
{
	X509 *cert;

	cert = SSL_get_peer_certificate(ssl);

	if (cert == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "DealerIn failed to produce certificate\n");
		return -1;
	}

	if (mrenclave == NULL || mrsigner == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				"SGX certificate of DealerIn will be ignored\n");
		X509_free(cert);
		return 0;
	}

	if (verify_sgx_crt_info(cert, mrenclave,
				mrsigner, isvsvn) == -1) {
		clLog(clSystemLog, eCLSeverityCritical,
				"SGX certificate verification of DealerIn failed\n");
		X509_free(cert);
		return -1;
	}
	clLog(clSystemLog, eCLSeverityDebug,"Connected to trusted SGX Dealer\n");

	X509_free(cert);

	return 0;
}


/**
 * Free ssl context and close the connection
 * @param ssl
 *	ssl handle.
 */
void
sgx_cdr_channel_close(SSL *ssl)
{
	if (ssl != NULL) {
		close(SSL_get_fd(ssl));
		SSL_free(ssl);
		SSL_CTX_free(ssl->ctx);
	}
}

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
		const char *mrenclave, const char *mrsigner, const char *isvsvn)
{
	SSL *sslhandle;
	SSL_CTX *ctx;
	int server;

	if ((ctx = InitCTX()) == NULL)
		return NULL;

	if ((server = openconnection(hostname, atoi(portnum))) <= 0)
		return NULL;

	if (SSL_CTX_use_certificate_file(ctx, client_cert_path,
				SSL_FILETYPE_PEM) <= 0) {
		clLog(clSystemLog, eCLSeverityCritical, "Error in loading ssl certificate\n");
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, priv_key_path,
				SSL_FILETYPE_PEM) <= 0) {
		clLog(clSystemLog, eCLSeverityCritical, "Error in loading private key\n");
		return NULL;
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		clLog(clSystemLog, eCLSeverityCritical, "Private key and Certificate do not match\n");
		return NULL;
	}

	sslhandle = SSL_new(ctx);
	SSL_set_fd(sslhandle, server);

	if (SSL_connect(sslhandle) == SSL_CONN_FAIL) {
		clLog(clSystemLog, eCLSeverityCritical, "Connection to DealerIn failed.");
		return NULL;
	}

	if (verify_cert(sslhandle, mrenclave, mrsigner, isvsvn) != 0) {
		sgx_cdr_channel_close(sslhandle);
		return NULL;
	}

	return sslhandle;
}

