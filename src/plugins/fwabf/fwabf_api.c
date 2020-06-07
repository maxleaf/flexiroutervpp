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

/*
 *  Copyright (C) 2020 flexiWAN Ltd.
 *  This file is part of the FWABF plugin.
 *  The FWABF plugin is fork of the FDIO VPP ABF plugin.
 *  It enhances ABF with functionality required for Flexiwan Multi-Link feature.
 *  For more details see official documentation on the Flexiwan Multi-Link.
 */

#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <fwabf/fwabf_policy.h>
#include <fwabf/fwabf_itf_attach.h>
#include <vnet/mpls/mpls_types.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_api.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>


#ifdef FWABF_API_MESSAGES_ARE_SUPPORTED  /* python bindings are not supported yet */

/* define message IDs */
#include <fwabf/fwabf_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <fwabf/fwabf_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <fwabf/fwabf_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <fwabf/fwabf_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <fwabf/fwabf_all_api_h.h>
#undef vl_api_version


/**
 * Base message ID fot the plugin
 */
static u32 abf_base_msg_id;

#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

#define foreach_abf_plugin_api_msg                    \
_(FWABF_PLUGIN_GET_VERSION, fwabf_plugin_get_version)     \
_(FWABF_POLICY_ADD_DEL, fwabf_policy_add_del)             \
_(FWABF_POLICY_DUMP, fwabf_policy_dump)                   \
_(FWABF_ITF_ATTACH_ADD_DEL, fwabf_itf_attach_add_del)     \
_(FWABF_ITF_ATTACH_DUMP, fwabf_itf_attach_dump)

static void
vl_api_fwabf_plugin_get_version_t_handler (vl_api_fwabf_plugin_get_version_t * mp)
{
  vl_api_fwabf_plugin_get_version_reply_t *rmp;
  int msg_size = sizeof (*rmp);
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_FWABF_PLUGIN_GET_VERSION_REPLY + abf_base_msg_id);
  rmp->context = mp->context;
  rmp->major = htonl (FWABF_PLUGIN_VERSION_MAJOR);
  rmp->minor = htonl (FWABF_PLUGIN_VERSION_MINOR);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_fwabf_policy_add_del_t_handler (vl_api_fwabf_policy_add_del_t * mp)
{
  vl_api_fwabf_policy_add_del_reply_t *rmp;
  fib_route_path_t *paths = NULL, *path;
  int rv = 0;
  u8 pi;

  vec_validate (paths, mp->policy.n_paths - 1);

  for (pi = 0; pi < mp->policy.n_paths; pi++)
    {
      path = &paths[pi];
      rv = fib_path_api_parse (&mp->policy.paths[pi], path);

      if (0 != rv)
	{
	  goto done;
	}
    }

  if (mp->is_add)
    {
      abf_policy_update (ntohl (mp->policy.policy_id),
			 ntohl (mp->policy.acl_index), paths);
    }
  else
    {
      fwabf_policy_delete (ntohl (mp->policy.policy_id), paths);
    }
done:
  vec_free (paths);

  REPLY_MACRO (VL_API_FWABF_POLICY_ADD_DEL_REPLY + abf_base_msg_id);
}

static void
vl_api_fwabf_itf_attach_add_del_t_handler (vl_api_fwabf_itf_attach_add_del_t * mp)
{
  vl_api_fwabf_itf_attach_add_del_reply_t *rmp;
  fib_protocol_t fproto = (mp->attach.is_ipv6 ?
			   FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
  int rv = 0;

  if (mp->is_add)
    {
      fwabf_itf_attach (fproto,
		      ntohl (mp->attach.policy_id),
		      ntohl (mp->attach.priority),
		      ntohl (mp->attach.sw_if_index));
    }
  else
    {
      fwabf_itf_detach (fproto,
		      ntohl (mp->attach.policy_id),
		      ntohl (mp->attach.sw_if_index));
    }

  REPLY_MACRO (VL_API_FWABF_ITF_ATTACH_ADD_DEL_REPLY + abf_base_msg_id);
}

typedef struct abf_dump_walk_ctx_t_
{
  unix_shared_memory_queue_t *q;
  u32 context;
} abf_dump_walk_ctx_t;

static int
abf_policy_send_details (u32 pi, void *args)
{
  fib_route_path_encode_t *api_rpaths = NULL, *api_rpath;
  vl_api_fwabf_policy_details_t *mp;
  abf_dump_walk_ctx_t *ctx;
  vl_api_fib_path_t *fp;
  size_t msg_size;
  fwabf_policy_t *p;
  u8 n_paths;

  ctx = args;
  p = fwabf_policy_get (pi);
  n_paths = fib_path_list_get_n_paths (p->ap_pl);
  msg_size = sizeof (*mp) + sizeof (mp->policy.paths[0]) * n_paths;

  mp = vl_msg_api_alloc (msg_size);
  clib_memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_FWABF_POLICY_DETAILS + abf_base_msg_id);

  /* fill in the message */
  mp->context = ctx->context;
  mp->policy.n_paths = n_paths;
  mp->policy.acl_index = htonl (p->acl);
  mp->policy.policy_id = htonl (p->id);

  fib_path_list_walk_w_ext (p->ap_pl, NULL, fib_path_encode, &api_rpaths);

  fp = mp->policy.paths;
  vec_foreach (api_rpath, api_rpaths)
  {
    fib_api_path_encode (api_rpath, fp);
    fp++;
  }

  vl_msg_api_send_shmem (ctx->q, (u8 *) & mp);

  return (1);
}

static void
vl_api_fwabf_policy_dump_t_handler (vl_api_fwabf_policy_dump_t * mp)
{
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  abf_dump_walk_ctx_t ctx = {
    .q = q,
    .context = mp->context,
  };

  abf_policy_walk (abf_policy_send_details, &ctx);
}

static int
abf_itf_attach_send_details (u32 fiai, void *args)
{
  vl_api_fwabf_itf_attach_details_t *mp;
  abf_dump_walk_ctx_t *ctx;
  fwabf_itf_attach_t *fia;
  fwabf_policy_t *p;

  ctx = args;
  fia = fwabf_itf_attach_get (fiai);
  p = fwabf_policy_get (fia->fia_policy);

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_FWABF_ITF_ATTACH_DETAILS + abf_base_msg_id);

  mp->context = ctx->context;
  mp->attach.policy_id = htonl (p->id);
  mp->attach.sw_if_index = htonl (fia->fia_sw_if_index);
  mp->attach.priority = htonl (fia->fia_prio);
  mp->attach.is_ipv6 = (fia->fia_proto == FIB_PROTOCOL_IP6);

  vl_msg_api_send_shmem (ctx->q, (u8 *) & mp);

  return (1);
}

static void
vl_api_fwabf_itf_attach_dump_t_handler (vl_api_fwabf_itf_attach_dump_t * mp)
{
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  abf_dump_walk_ctx_t ctx = {
    .q = q,
    .context = mp->context,
  };

  abf_itf_attach_walk (abf_itf_attach_send_details, &ctx);
}

#define vl_msg_name_crc_list
#include <fwabf/fwabf_all_api_h.h>
#undef vl_msg_name_crc_list

/* Set up the API message handling tables */
static clib_error_t *
abf_plugin_api_hookup (vlib_main_t * vm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + abf_base_msg_id),     \
                            #n,					\
                            vl_api_##n##_t_handler,             \
                            vl_noop_handler,                    \
                            vl_api_##n##_t_endian,              \
                            vl_api_##n##_t_print,               \
                            sizeof(vl_api_##n##_t), 1);
  foreach_abf_plugin_api_msg;
#undef _

  return 0;
}

static void
setup_message_id_table (api_main_t * apim)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (apim, #n "_" #crc, id + abf_base_msg_id);
  foreach_vl_msg_name_crc_fwabf;
#undef _
}

static clib_error_t *
abf_api_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  u8 *name = format (0, "abf_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  abf_base_msg_id = vl_msg_api_get_msg_ids ((char *) name,
					    VL_MSG_FIRST_AVAILABLE);

  error = abf_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (&api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (abf_api_init);

#endif //#ifdef (FWABF_API_MESSAGES_ARE_SUPPORTED)  /* python bindings are not supported yet */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Flexiwan Access Control List (ACL) Based Forwarding",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
