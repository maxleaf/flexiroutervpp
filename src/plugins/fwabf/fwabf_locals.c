/*
 * flexiWAN SD-WAN software - flexiEdge, flexiManage.
 * For more information go to https://flexiwan.com
 *
 * Copyright (C) 2019  flexiWAN Ltd.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// nnoww - DOCUMENT

#include <plugins/fwabf/fwabf_locals.h>
#include <vnet/ip/ip6_packet.h>

#define FWABF_LOCALS_MAX_ADDRESSES (24000)  /* 10.000 tunnels x 2 (10.100.X.X, 10.101.X.X) + 100 VLAN-s */

static void fwabf_locals_add(const ip46_address_t * addr)
{
  clib_bihash_kv_8_8_t  kv_ip4;
  clib_bihash_kv_16_8_t kv_ip6;

  if (ip46_address_is_ip4(addr))
    {
      kv_ip4.key = addr->ip4.as_u32;
      clib_bihash_add_del_8_8 (&fwabf_locals_ip4, &kv_ip4, 1 /* 1=add, 0=delete */);
    }
  else
    {
      kv_ip6.key[0] = addr->ip6.as_u64[0];
      kv_ip6.key[1] = addr->ip6.as_u64[1];
      clib_bihash_add_del_16_8 (&fwabf_locals_ip6, &kv_ip6, 1 /* 1=add, 0=delete */);
    }
}

static void fwabf_locals_del(const ip46_address_t * addr)
{
  clib_bihash_kv_8_8_t  kv_ip4;
  clib_bihash_kv_16_8_t kv_ip6;

  if (ip46_address_is_ip4(addr))
    {
      kv_ip4.key = addr->ip4.as_u32;
      clib_bihash_add_del_8_8 (&fwabf_locals_ip4, &kv_ip4, 0 /* 1=add, 0=delete */);
    }
  else
    {
      kv_ip6.key[0] = addr->ip6.as_u64[0];
      kv_ip6.key[1] = addr->ip6.as_u64[1];
      clib_bihash_add_del_16_8 (&fwabf_locals_ip6, &kv_ip6, 0 /* 1=add, 0=delete */);
    }
}

static
clib_error_t * fwabf_locals_cmd (
                  vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip46_address_t addr;
  u32            is_add        = 0;
  u32            is_del        = 0;
  u32            is_lookup     = 0;
  u32            addr_provided = 0;
  int            addr_found;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	      is_add = 1;
      else if (unformat (input, "del"))
	      is_del = 1;
      else if (unformat (input, "lookup"))
	      is_lookup = 1;
      else if (unformat (input, "%U", unformat_ip46_address, &addr, IP46_TYPE_ANY))
        addr_provided = 1;
      else
        {
          return (clib_error_return (0, "unknown input '%U'",
                                    format_unformat_error, input));
        }
    }

  if (addr_provided == 0)    /* we need via for DEL also as it brings us sw_if_index */
    {
      vlib_cli_output (vm, "specify a valid ip4/ip6 address");
      return (NULL);
    }
  if ( (is_add + is_del + is_lookup) > 1)
    {
      vlib_cli_output (vm, "[add|del|lookup] are mutually exclusive");
      return (NULL);
    }

  if (is_add)
    {
      fwabf_locals_add(&addr);
    }
  if (is_del)
    {
      fwabf_locals_del(&addr);
    }
  if (is_lookup)
    {
      addr_found = ip46_address_is_ip4(&addr) ?
                        fwabf_locals_ip4_exists(&addr.ip4) :
                        fwabf_locals_ip6_exists(&addr.ip6);
      vlib_cli_output (vm, "%sfound", (addr_found?"":"not "));
    }
  return (NULL);
}

/* *INDENT-OFF* */
/**
 * Add/delete link local address.
 */
VLIB_CLI_COMMAND (fwabf_locals_cmd_node, static) = {
  .path = "fwabf locals",
  .function = fwabf_locals_cmd,
  .short_help = "fwabf locals [add|del|lookup] <address>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static int fwabf_locals_ip46_address_cmp (ip46_address_t * a0, ip46_address_t * a1)
{
  return (ip46_address_cmp (a0, a1));
}

static void fwabf_locals_show_ip4_callback_fn (clib_bihash_kv_8_8_t * kv, void * ctx)
{
  ip46_address_t** vec_addrs = (ip46_address_t**)ctx;
  ip46_address_t   addr;
  ip4_address_t    ip4;

  ip4.as_u32 = (u32)kv->key;
  ip46_address_mask_ip4(&addr);
  ip46_address_set_ip4(&addr, &ip4);

  vec_add1(*vec_addrs, addr);
}

static void fwabf_locals_show_ip6_callback_fn (clib_bihash_kv_16_8_t * kv, void * ctx)
{
  ip46_address_t ** vec_addrs = (ip46_address_t**)ctx;
  ip46_address_t    addr;

  addr.as_u64[0] = kv->key[0];
  addr.as_u64[1] = kv->key[1];
  vec_add1(*vec_addrs, addr);
}

static clib_error_t *
fwabf_locals_show_cmd (
        vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip46_address_t  addr;
  u32             is_ip4        = 1;
  u32             addr_provided = 0;
  int             addr_found;
  ip46_address_t* vec_addrs     = (NULL);
  ip46_address_t* paddr;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ip6"))
	      is_ip4 = 0;
      else if (unformat (input, "%U", unformat_ip46_address, &addr, IP46_TYPE_ANY))
        addr_provided = 1;
      else
        {
          return (clib_error_return (0, "unknown input '%U'",
                                    format_unformat_error, input));
        }
    }

  if (addr_provided)
    {
      if (ip46_address_is_ip4(&addr))
          addr_found = fwabf_locals_ip4_exists (&addr.ip4);
      else
          addr_found = fwabf_locals_ip6_exists (&addr.ip6);

      if (addr_found)
        vlib_cli_output (vm, "%U", format_ip46_address, &addr, IP46_TYPE_ANY);
      else
        vlib_cli_output (vm, "<not found>");
      return (NULL);
    }

  if (is_ip4)
    {
      clib_bihash_foreach_key_value_pair_8_8 (&fwabf_locals_ip4, fwabf_locals_show_ip4_callback_fn, &vec_addrs);
    }
  else
    {
      clib_bihash_foreach_key_value_pair_16_8 (&fwabf_locals_ip6, fwabf_locals_show_ip6_callback_fn, &vec_addrs);
    }

  vec_sort_with_function(vec_addrs, fwabf_locals_ip46_address_cmp);
  vec_foreach (paddr, vec_addrs)
    {
      vlib_cli_output (vm, " %U", format_ip46_address, paddr, IP46_TYPE_ANY);
    }
  vec_free(vec_addrs);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (fwabf_locals_show_cmd_node, static) = {
  .path = "show fwabf locals",
  .function = fwabf_locals_show_cmd,
  .short_help = "show fwabf locals [ip6] [address]",
};
/* *INDENT-ON* */

static
clib_error_t * fwabf_locals_init (vlib_main_t * vm)
{
  u32             number_of_buckets = FWABF_LOCALS_MAX_ADDRESSES / BIHASH_KVP_PER_PAGE;
  uword           memory_size       = FWABF_LOCALS_MAX_ADDRESSES << 4; /* provide enough memory for records every of which is 4 bytes (aligned to 8 bytes :) - the smallest hash we have in clib - << 3) and take in account collisions (<< 1) */
  ip46_address_t  addr_broadcast;
  ip4_address_t   ip4_broadcast;

  clib_bihash_init_8_8 (&fwabf_locals_ip4,  "fwabf_locals_ip4", number_of_buckets, memory_size);
  clib_bihash_init_16_8 (&fwabf_locals_ip6, "fwabf_locals_ip6", number_of_buckets, memory_size * 2);  /*ip6 size is twice as 8 bytes used for ip4 */

  ip4_broadcast.as_u32 = 0xFFFFFFFF;
  ip46_address_set_ip4(&addr_broadcast, &ip4_broadcast);
  fwabf_locals_add(&addr_broadcast);

  return (NULL);
}

VLIB_INIT_FUNCTION (fwabf_locals_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
