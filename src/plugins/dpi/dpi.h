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

#ifndef DPI_PLUGIN_DPI_H_
#define DPI_PLUGIN_DPI_H_

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <plugins/acl/exports.h>

typedef struct {
  u32 id;
  ip46_address_t server_ip;
  u16 start_port;
  u16 end_port;
  u8 ip_prefix;
} dpi_rule_t;

typedef struct {
  u8 * name;
  uword * rules_by_id;
  dpi_rule_t * rules;
  u32 acl_id;
} dpi_app_t;

typedef struct {
  /* apps hash */
  uword* dpi_app_by_name;
  /* apps vector */
  dpi_app_t *dpi_apps;
  /* acl to app hash */
  uword * app_by_acl;

  /**
   * API dynamically registered base ID.
   */
  u16 msg_id_base;

  u32 acl_user_id;
  int acl_lc_id;
  u32 *acl_vec;
  acl_plugin_methods_t acl_plugin;

  volatile u32 *writer_lock;
} dpi_main_t;

extern dpi_main_t dpi_main;

#endif /* DPI_PLUGIN_DPI_H_ */
