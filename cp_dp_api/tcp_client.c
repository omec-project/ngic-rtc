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



#include "tcp_client.h"
#include "gw_adapter.h"
#ifdef CP_BUILD
extern pfcp_config_t config;
#endif
extern int clSystemLog;
#ifdef DP_BUILD
extern struct app_params app;
#endif

void
insert_fd(int *sock_arr, uint32_t *arr_size, int fd){

	if(*arr_size == 0){
		sock_arr[*arr_size] = fd;
		*arr_size = *arr_size + 1;
		return;
	}

	for(uint32_t i =0 ; i < *arr_size; i++){
		if(sock_arr[i] == fd)
			return;
	}

	sock_arr[*arr_size] = fd;
	*arr_size = *arr_size + 1;
	return;
}
