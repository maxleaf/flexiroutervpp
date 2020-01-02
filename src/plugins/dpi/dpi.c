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

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/api_errno.h>
#include <vnet/udp/udp.h>

#include <dpi/dpi.h>
#include <dpi/flowtable.h>

#define DPI_APP_BY_NAME_INIT_LENGTH 32

dpi_main_t dpi_main;

clib_error_t *
dpi_init (vlib_main_t * vm)
{
  dpi_main_t *sm = &dpi_main;
  clib_error_t * error;

  sm->dpi_app_by_name = hash_create_vec (DPI_APP_BY_NAME_INIT_LENGTH,
                                         sizeof (u8), sizeof (uword));

  error = flowtable_init(vm);
  if (error)
    return error;

  error = acl_plugin_exports_init (&sm->acl_plugin);
  if (error)
    return error;

  return NULL;
}

VLIB_INIT_FUNCTION (dpi_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "DPI",
};
/* *INDENT-ON* */
