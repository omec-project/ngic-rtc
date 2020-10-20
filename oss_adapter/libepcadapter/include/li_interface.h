/*
 * Copyright (c) 2020 Sprint
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

#ifndef __LI_INTERFACE_H__
#define __LI_INTERFACE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int32_t init_ddf(void);
void *create_ddf_tunnel(char *ddf_ip, uint16_t port, char *ddf_local_ip, const uint8_t *mode);
uint32_t send_li_data_pkt(void *obj, uint8_t *packet, uint32_t len);
void deinit_ddf(void);

#ifdef __cplusplus
}
#endif

#endif  /* __NGIC_GW_ADAPTER_H__ */
