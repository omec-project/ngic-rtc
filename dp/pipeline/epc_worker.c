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

#include <string.h>
#include <sched.h>

#include <rte_string_fns.h>
#include <rte_ring.h>
#include <rte_pipeline.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_port_ring.h>
#include <rte_port_ethdev.h>
#include <rte_table_hash.h>
#include <rte_table_stub.h>
#include <rte_byteorder.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_port_ring.h>

#include "epc_packet_framework.h"
#include "main.h"

#define BUILD_WK_ARG(x, y) ((x << 8) | (y & 0xff))
#define WK_GET_PORT(x) (x >> 8)
#define WK_GET_INDEX(x) (x & 0xff)

static epc_packet_handler epc_worker_func[NUM_SPGW_PORTS];

/**
 * @brief  : Packet handler for epc
 * @param  : p, rte pipeline pointer
 * @param  : pkts, rte mbuf
 * @param  : n, number of packets
 * @param  : arg_p, wk_index
 * @return : Returns 0 in case of success , -1 otherwise
 */
static inline int port_in_func(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n, void *arg_p)
{
	RTE_SET_USED(p);
	int arg = (uintptr_t) arg_p;
	int port = WK_GET_PORT(arg);
	int wk_index = WK_GET_INDEX(arg);
	epc_packet_handler f = epc_worker_func[port];

	return f(p, pkts, n, wk_index);
}

void epc_worker_core_init(struct epc_worker_params *param, int core,
		int worker_index)
{
	unsigned i;
	struct rte_pipeline *p;
	char name[32];

	memset(param, 0, sizeof(*param));

	snprintf((char *)param->name, PIPE_NAME_SIZE, "epc_worker_%d", core);
	param->pipeline_params.socket_id = rte_socket_id();
	param->pipeline_params.name = param->name;

	p = rte_pipeline_create(&param->pipeline_params);
	if (p == NULL)
		rte_panic("Unable to configure the pipeline\n");
	snprintf(name, sizeof(name), "notify_%d", core);

	param->notify_ring =
		rte_ring_create(name, NOTIFY_RING_SIZE,
			rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ);

	snprintf(name, sizeof(name), "ring_container_%d", core);
	param->dl_ring_container =
		rte_ring_create(name, DL_RING_CONTAINER_SIZE,
			rte_socket_id(), RING_F_SC_DEQ);
	param->num_dl_rings = 0;
	snprintf(name, sizeof(name), "notify_msg_pool_%d", core);
	param->notify_msg_pool = rte_pktmbuf_pool_create(name, DL_PKT_POOL_SIZE,
				DL_PKT_POOL_CACHE_SIZE, 0,
				RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_port_ring_reader_params port_ring_params = {
			.ring = epc_app.epc_work_rx[core][i],
		};

		int arg = BUILD_WK_ARG(i, worker_index);
		struct rte_pipeline_port_in_params port_params = {
			.ops = &rte_port_ring_reader_ops,
			.arg_create = (void *)&port_ring_params,
			.f_action = port_in_func,
			.arg_ah = (void *)(uintptr_t)arg,
			.burst_size = epc_app.burst_size_worker_read
		};

		if (rte_pipeline_port_in_create
				(p, &port_params, &param->port_in_id[i])) {
			rte_panic
				("Unable to configure input port\n"
					" for ring %d\n", i);
		}
	}
	struct rte_port_ring_reader_params port_ring_params = {
		.ring = epc_app.worker[worker_index].notify_ring,
	};
	struct rte_pipeline_port_in_params port_params = {
		.ops = &rte_port_ring_reader_ops,
		.arg_create = (void *)&port_ring_params,
		.f_action = notification_handler,
		.arg_ah = (void *)(uintptr_t)worker_index,
		.burst_size = epc_app.burst_size_worker_read
	};

	if (rte_pipeline_port_in_create
			(p, &port_params, &param->port_in_id[NUM_SPGW_PORTS])) {
		rte_panic
			("Unable to configure input port notify ring\n");
	}

	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_port_ring_writer_params port_ring_params = {
			.ring = epc_app.ring_tx[core][i],
			.tx_burst_sz = epc_app.burst_size_worker_write,
		};

		struct rte_pipeline_port_out_params port_params = {
			.ops = &rte_port_ring_writer_ops,
			.arg_create = (void *)&port_ring_params,
		};

		if (rte_pipeline_port_out_create
				(p, &port_params, &param->port_out_id[i])) {
			rte_panic
				("%s: Unable to configure output port\n"
					" for ring tx %i\n",
				 __func__, i);
		}
	}

	for (i = 0; i < epc_app.n_ports + 1; i++) {
		struct rte_pipeline_table_params table_params = {
			.ops = &rte_table_stub_ops,
		};
		int status = rte_pipeline_table_create(p,
				&table_params,
				&param->table_id[i]);

		if (status) {
			rte_pipeline_free(p);
			rte_panic("%s: Unable to create the pipeline table\n",
					__func__);
		}
	}

	for (i = 0; i < epc_app.n_ports + 1; i++) {
		int status = rte_pipeline_port_in_connect_to_table(p,
				i,
				param->
				table_id[i]);

		if (status) {
			rte_pipeline_free(p);
			rte_panic
			    ("%s: Unable to add default entry to table %u\n",
			     __func__, param->table_id[i]);
		}
	}

	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_pipeline_table_entry default_entry = {
			.action = RTE_PIPELINE_ACTION_PORT,
			{.port_id = !i},
		};

		struct rte_pipeline_table_entry *default_entry_ptr;

		int status = rte_pipeline_table_default_entry_add(p,
				param->
				table_id[i],
				&default_entry,
				&default_entry_ptr);

		if (status) {
			rte_pipeline_free(p);
			rte_panic
			    ("%s: Unable to add default entry to table %u\n",
			     __func__, param->table_id[i]);
		}
	}

	for (i = 0; i < epc_app.n_ports + 1; i++) {
		int status = rte_pipeline_port_in_enable(p, i);

		if (status) {
			rte_pipeline_free(p);
			rte_panic("%s: Unable to enable in port\n", __func__);
		}
	}

	if (rte_pipeline_check(p) < 0) {
		rte_pipeline_free(p);
		rte_panic("%s: Pipeline consistency check failed\n", __func__);
	}

	param->pipeline = p;
	param->flush_max = EPC_PIPELINE_FLUSH_MAX;
}

void epc_worker_core(void *args)
{
	struct epc_worker_params *param = (struct epc_worker_params *)args;

	rte_pipeline_run(param->pipeline);
	if (++param->flush_count >= param->flush_max) {
		rte_pipeline_flush(param->pipeline);
		param->flush_count = 0;
	}
}

void register_worker(epc_packet_handler f, int port)
{
	unsigned i;

	for (i = 0; i < epc_app.num_workers; i++)
		epc_worker_func[port] = f;
}
