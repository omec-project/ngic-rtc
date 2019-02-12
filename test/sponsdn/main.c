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

#include <sponsdn.h>
#include <rte_eal.h>
#include <rte_config.h>
#include <rte_common.h>
#include <arpa/inet.h>
#include <sponsdn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <pcap/pcap.h>

#include <rte_cfgfile.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

#define MAX_DN 10
#define MAX_DNS_NAME_LEN 256
int cnt;

static unsigned char *handler(const unsigned char *bytes)
{
	static unsigned char ether_frame[1500];
	const struct udp_hdr *udp_hdr = (const struct udp_hdr *)(bytes + 34);

	if (rte_be_to_cpu_16(udp_hdr->src_port) == 53) {
		memcpy(ether_frame, bytes, 1500);
		return ether_frame;
	}
	return NULL;
}

static unsigned char *map_resp(char *fname)
{
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	unsigned char *p;
	const unsigned char *packet;
	struct pcap_pkthdr header;

	handle = pcap_open_offline(fname, error_buffer);
	if (!handle)
		return NULL;

	p = NULL;
	packet = pcap_next(handle, &header);

	while (!p && packet) {
		p = handler(packet);
		packet = pcap_next(handle, &header);
	}

	return p;
}

static int read_host_names(char *host_names[], const char *cfg_file)
{
	struct rte_cfgfile *file;
	const char *fname;
	int fd;
	ssize_t len;
	char *buf;
	unsigned i;

	file = rte_cfgfile_load(cfg_file, 0);
	if (!file) {
		printf("[%s()] rte_cfgfile_load failed\n", __func__);
		return -1;
	}

	fname = rte_cfgfile_get_entry(file, "0", "dns_file_name");
	if (!fname) {
		printf("[%s()] failed to get dns_file entry\n", __func__);
		return -1;
	}

	fd = open(fname, O_RDONLY);
	if (fd == -1) {
		printf("[%s()] failed to open file %s\n", __func__, fname);
		return -1;
	}

	len = lseek(fd, 0, SEEK_END);
	if (len == -1) {
		printf("[%s()] lseek failed\n", __func__);
		return -1;
	}

	buf = mmap(0, len, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		printf("[%s()] failed to mmap file %s\n", __func__, fname);
		return -1;
	}

	for (i = 0; i < MAX_DN; i++) {
        strncpy(host_names[i], buf, strlen(buf));
		buf += strlen(host_names[i]);
		if (!buf[0] || !buf[1])
			break;
		buf++;
	}

	return i + 1;
}

static void scan_and_print(unsigned char *pkt, char (*hname)[MAX_DNS_NAME_LEN])
{
	int addr4_cnt, addr6_cnt;
	struct in_addr addr4[100];
	int i;
	unsigned match_id;

	addr4_cnt = 0;
	epc_sponsdn_scan((const char *)pkt, 1500, NULL, &match_id, NULL,
			 &addr4_cnt, NULL, NULL, &addr6_cnt);
	if (addr4_cnt) {
		epc_sponsdn_scan((const char *)pkt, 1500, NULL, &match_id, addr4,
				 &addr4_cnt, NULL, NULL, &addr6_cnt);
		printf("Host name %s\n",  hname[match_id]);
		for (i = 0; i < addr4_cnt; i++)
			printf("IP address %s\n", inet_ntoa(addr4[i]));

	} else {
		printf("Domain name not found\n");
	}

}

int main(int argc, char **argv)
{
	int rc;
	int ret;
	char hname[MAX_DN][MAX_DNS_NAME_LEN];
	char *hname_tbl[MAX_DN];
	unsigned int id[MAX_DN];
	int i, n;
	unsigned char *pkt10;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	ret++;

	for (i = 0; i < MAX_DN; i++)
		hname_tbl[i] = (char *)&hname[i];

	n = read_host_names(hname_tbl, argv[ret]);

	ret++;
	pkt10 = map_resp(argv[ret]);

	rc = epc_sponsdn_create(n);
	if (rc) {
		printf("error allocating sponsored DN context %d\n", rc);
		return EXIT_FAILURE;
	}

	for (i = 0; i < n; i++)
		id[i] = i;

	for (i = 0; i < n; i++)
		printf("Hostname %s\n", hname_tbl[i]);

	rc = epc_sponsdn_dn_add_multi(hname_tbl, id, n);
	if (rc) {
		printf("failed to add DN error code %d\n", rc);
		return rc;
	}
	scan_and_print(pkt10 + 0x2a, hname);

	printf("Deleting %s\n", hname_tbl[0]);
	epc_sponsdn_dn_del(hname_tbl, 1);
	scan_and_print(pkt10 + 0x2a, hname);

	printf("Deleting %s\n", hname_tbl[1]);
	epc_sponsdn_dn_del(&hname_tbl[1], 1);
	scan_and_print(pkt10 + 0x2a, hname);

	epc_sponsdn_free();
	return 0;
}
