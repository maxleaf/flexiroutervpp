/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DPI_PLUGIN_UTIL_H_
#define DPI_PLUGIN_UTIL_H_

#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

typedef struct {
  ip46_address_t server_ip;
  u8 ip_prefix;
  u16 start_port;
  u16 end_port;
} dpi_rule_args_t;

int dpi_enable_disable (u32 sw_if_index, int enable_disable);
int vnet_dpi_app_add_del(u8 * name, u8 add);

int vnet_dpi_rule_add_del(u8 * app_name, u32 rule_index, u8 add,
                          dpi_rule_args_t * args);

#endif /* DPI_PLUGIN_UTIL_H_ */
