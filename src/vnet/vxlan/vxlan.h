/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 *  List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *   - enable enforcement of interface, where VXLAN tunnel should send unicast
 *     packets from. This is need for the FlexiWAN Multi-link feature.
 *   - Add destination port for vxlan tunnel, if remote device is behind NAT. Port is
 *     provisioned by flexiManage when creating the tunnel.
 *   - added escaping natting for flexiEdge-to-flexiEdge vxlan tunnels.
 *     These tunnels do not need NAT, so there is no need to create NAT session
 *     for them. That improves performance on multi-core machines,
 *     as NAT session are bound to the specific worker thread / core.
 *
 *  List of fixes made for FlexiWAN (demoted by FLEXIWAN_FIX flag):
 *  - For none vxlan packet received on port 4789, add ipx_punt node to next_nodes.
 */

#ifndef included_vnet_vxlan_h
#define included_vnet_vxlan_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_24_8.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/vtep.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan/vxlan_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#ifdef FLEXIWAN_FEATURE
#include <vnet/fib/fib_path_list.h>
#endif

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;	/* 20 bytes */
  udp_header_t udp;	/* 8 bytes */
  vxlan_header_t vxlan;	/* 8 bytes */
}) ip4_vxlan_header_t;

typedef CLIB_PACKED (struct {
  ip6_header_t ip6;	/* 40 bytes */
  udp_header_t udp;	/* 8 bytes */
  vxlan_header_t vxlan;	/* 8 bytes */
}) ip6_vxlan_header_t;
/* *INDENT-ON* */

/*
* Key fields: remote ip, vni on incoming VXLAN packet
* all fields in NET byte order
*/
typedef clib_bihash_kv_16_8_t vxlan4_tunnel_key_t;

/*
* Key fields: remote ip, vni and fib index on incoming VXLAN packet
* ip, vni fields in NET byte order
* fib index field in host byte order
*/
typedef clib_bihash_kv_24_8_t vxlan6_tunnel_key_t;

typedef union
{
  struct
  {
    u32 sw_if_index;		/* unicast - input interface / mcast - stats interface */
    union
    {
      struct			/* unicast action */
      {
	u16 next_index;
	u8 error;
      };
      ip4_address_t local_ip;	/* used as dst ip for mcast pkts to assign them to unicast tunnel */
    };
  };
  u64 as_u64;
} vxlan_decap_info_t;

typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* FIB DPO for IP forwarding of VXLAN encap packet */
  dpo_id_t next_dpo;

  /* vxlan VNI in HOST byte order */
  u32 vni;

  /* tunnel src and dst addresses */
  ip46_address_t src;
  ip46_address_t dst;

  /* mcast packet output intfc index (used only if dst is mcast) */
  u32 mcast_sw_if_index;

  /* decap next index */
  u16 decap_next_index;

  /* The FIB index for src/dst addresses */
  u32 encap_fib_index;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /*
   * The FIB entry for (depending on VXLAN tunnel is unicast or mcast)
   * sending unicast VXLAN encap packets or receiving mcast VXLAN packets
   */
  fib_node_index_t fib_entry_index;
  adj_index_t mcast_adj_index;

#ifdef FLEXIWAN_FEATURE
  /*
   * Enforce specific tx interface for tunnel packets, if next hop for tunnel
   * was provided by user on tunnel creation. In this case no FIB LOOKUP is
   * needed. Just use the path of attached-next-hop type to get the adjacency
   * to be used for forwarding.
   */
  fib_node_index_t      fib_pl_index;
  fib_path_list_flags_t pl_flags;
  fib_route_path_t      rpath;
#endif
#ifdef FLEXIWAN_FEATURE
  u16 dest_port;
#endif

  /**
   * The tunnel is a child of the FIB entry for its destination. This is
   * so it receives updates when the forwarding information for that entry
   * changes.
   * The tunnels sibling index on the FIB entry's dependency list.
   */
  u32 sibling_index;

  u32 flow_index;		/* infra flow index */
  u32 dev_instance;		/* Real device instance in tunnel vector */
  u32 user_instance;		/* Instance name being shown to user */

    VNET_DECLARE_REWRITE;
} vxlan_tunnel_t;

#ifdef FLEXIWAN_FIX
#define foreach_vxlan_input_next        \
_(DROP, "error-drop")                   \
_(L2_INPUT, "l2-input")                 \
_(PUNT4, "ip4-punt")                    \
_(PUNT6, "ip6-punt")
#else
#define foreach_vxlan_input_next        \
_(DROP, "error-drop")                   \
_(L2_INPUT, "l2-input")
#endif

typedef enum
{
#define _(s,n) VXLAN_INPUT_NEXT_##s,
  foreach_vxlan_input_next
#undef _
    VXLAN_INPUT_N_NEXT,
} vxlan_input_next_t;

typedef enum
{
#define vxlan_error(n,s) VXLAN_ERROR_##n,
#include <vnet/vxlan/vxlan_error.def>
#undef vxlan_error
  VXLAN_N_ERROR,
} vxlan_input_error_t;

typedef struct
{
  /* vector of encap tunnel instances */
  vxlan_tunnel_t *tunnels;

  /* lookup tunnel by key */
  clib_bihash_16_8_t vxlan4_tunnel_by_key;	/* keyed on ipv4.dst + fib + vni */
  clib_bihash_24_8_t vxlan6_tunnel_by_key;	/* keyed on ipv6.dst + fib + vni */

  /* local VTEP IPs ref count used by vxlan-bypass node to check if
     received VXLAN packet DIP matches any local VTEP address */
  vtep_table_t vtep_table;

  /* mcast shared info */
  uword *mcast_shared;		/* keyed on mcast ip46 addr */

  /* Mapping from sw_if_index to tunnel index */
  u32 *tunnel_index_by_sw_if_index;

  /* graph node state */
  uword *bm_ip4_bypass_enabled_by_sw_if;
  uword *bm_ip6_bypass_enabled_by_sw_if;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* Record used instances */
  uword *instance_used;
  u32 flow_id_start;
} vxlan_main_t;

extern vxlan_main_t vxlan_main;

extern vlib_node_registration_t vxlan4_input_node;
extern vlib_node_registration_t vxlan6_input_node;
extern vlib_node_registration_t vxlan4_encap_node;
extern vlib_node_registration_t vxlan6_encap_node;
extern vlib_node_registration_t vxlan4_flow_input_node;

u8 *format_vxlan_encap_trace (u8 * s, va_list * args);

typedef struct
{
  u8 is_add;

  /* we normally use is_ip4, but since this adds to the
   * structure, this seems less of a breaking change */
  u8 is_ip6;
  u32 instance;
  ip46_address_t src, dst;
  u32 mcast_sw_if_index;
  u32 encap_fib_index;
  u32 decap_next_index;
  u32 vni;
#ifdef FLEXIWAN_FEATURE
  fib_route_path_t next_hop;
#endif
#ifdef FLEXIWAN_FEATURE
  /* adding dest port for vxlan tunnel in case destination behind NAT */
  u16 dest_port;
#endif
} vnet_vxlan_add_del_tunnel_args_t;

int vnet_vxlan_add_del_tunnel
  (vnet_vxlan_add_del_tunnel_args_t * a, u32 * sw_if_indexp);

void vnet_int_vxlan_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable);

int vnet_vxlan_add_del_rx_flow (u32 hw_if_index, u32 t_imdex, int is_add);

u32 vnet_vxlan_get_tunnel_index (u32 sw_if_index);

#ifdef FLEXIWAN_FEATURE
typedef vxlan4_tunnel_key_t last_tunnel_cache4;

static const vxlan_decap_info_t decap_not_found = {
  .sw_if_index = ~0,
  .next_index = VXLAN_INPUT_NEXT_DROP,
  .error = VXLAN_ERROR_NO_SUCH_TUNNEL
};

static const vxlan_decap_info_t decap_bad_flags = {
  .sw_if_index = ~0,
  .next_index = VXLAN_INPUT_NEXT_DROP,
  .error = VXLAN_ERROR_BAD_FLAGS
};

static const vxlan_decap_info_t decap_invalid_next_l2 = {
  .sw_if_index = ~0,
  .next_index = VXLAN_INPUT_NEXT_DROP,
  .error = VXLAN_ERROR_INVALID_NEXT_L2
};

always_inline vxlan_decap_info_t
vxlan4_find_tunnel (vxlan_main_t * vxm, last_tunnel_cache4 * cache, u16 * cache_port,
		    u32 fib_index, ip4_header_t * ip4_0, udp_header_t * udp0,
		    vxlan_header_t * vxlan0, u32 * stats_sw_if_index)
{
  if (PREDICT_FALSE (vxlan0->flags != VXLAN_FLAGS_I))
    return decap_bad_flags;

  /* Make sure VXLAN tunnel exist according to packet S/D IP, VRF, and VNI */
  u32 dst = ip4_0->dst_address.as_u32;
  u32 src = ip4_0->src_address.as_u32;
  u16 src_port = clib_net_to_host_u16(udp0->src_port);
  vxlan4_tunnel_key_t key4 = {
    .key[0] = ((u64) dst << 32) | src,
    .key[1] = ((u64) fib_index << 32) | vxlan0->vni_reserved,
  };

  if (PREDICT_TRUE
      (key4.key[0] == cache->key[0] && key4.key[1] == cache->key[1]
        && src_port == *cache_port))
    {
      /* cache hit */
      vxlan_decap_info_t di = {.as_u64 = cache->value };
      *stats_sw_if_index = di.sw_if_index;
      return di;
    }

  int rv = clib_bihash_search_inline_16_8 (&vxm->vxlan4_tunnel_by_key, &key4);
  if (PREDICT_TRUE (rv == 0))
    {
      vxlan_decap_info_t di = {.as_u64 = key4.value };
      u32 instance = vxm->tunnel_index_by_sw_if_index[di.sw_if_index];
      vxlan_tunnel_t *t0 = pool_elt_at_index (vxm->tunnels, instance);
      /* Validate VXLAN tunnel destination port against packet source port */
      if (PREDICT_FALSE (t0->dest_port != src_port))
        return decap_not_found;

      *cache = key4;
      *cache_port = src_port;
      *stats_sw_if_index = di.sw_if_index;
      return di;
    }

  /* try multicast */
  if (PREDICT_TRUE (!ip4_address_is_multicast (&ip4_0->dst_address)))
    return decap_not_found;

  /* search for mcast decap info by mcast address */
  key4.key[0] = dst;
  rv = clib_bihash_search_inline_16_8 (&vxm->vxlan4_tunnel_by_key, &key4);
  if (rv != 0)
    return decap_not_found;

  /* search for unicast tunnel using the mcast tunnel local(src) ip */
  vxlan_decap_info_t mdi = {.as_u64 = key4.value };
  key4.key[0] = ((u64) mdi.local_ip.as_u32 << 32) | src;
  rv = clib_bihash_search_inline_16_8 (&vxm->vxlan4_tunnel_by_key, &key4);
  if (PREDICT_FALSE (rv != 0))
    return decap_not_found;

  u32 instance = vxm->tunnel_index_by_sw_if_index[mdi.sw_if_index];
  vxlan_tunnel_t *mcast_t0 = pool_elt_at_index (vxm->tunnels, instance);
  /* Validate VXLAN tunnel destination port against packet source port */
  if (PREDICT_FALSE (mcast_t0->dest_port != src_port))
    return decap_not_found;

  /* mcast traffic does not update the cache */
  *stats_sw_if_index = mdi.sw_if_index;
  vxlan_decap_info_t di = {.as_u64 = key4.value };
  return di;
}

always_inline void
vnet_vxlan4_set_escape_feature_group_x1(vnet_feature_group_t g, vlib_buffer_t *b0)
{
  void            *cur0   = vlib_buffer_get_current (b0);
  ip4_header_t    *ip40   = cur0;
  udp_header_t    *udp0   = cur0 + sizeof(ip4_header_t);
  vxlan_header_t  *vxlan0 = cur0 + sizeof(ip4_header_t) + sizeof(udp_header_t);
  u32             fi0    = vlib_buffer_get_ip4_fib_index (b0);

  u32                 sw_if_index;
  u16                 last_src_port = 0;
  last_tunnel_cache4  last4;
  vxlan_decap_info_t  di;

  clib_memset (&last4, 0xff, sizeof last4);
  last_src_port = 0;

  if (ip40->protocol == IP_PROTOCOL_UDP  &&  udp0->dst_port == clib_host_to_net_u16(4789))
  {
    di = vxlan4_find_tunnel (&vxlan_main, &last4, &last_src_port, fi0, ip40, udp0, vxlan0, &sw_if_index);
    if (di.sw_if_index != ~0)
      vnet_buffer(b0)->escape_feature_groups |= g;
  }
}

always_inline void
vnet_vxlan4_set_escape_feature_group_x2(vnet_feature_group_t g,
                                        vlib_buffer_t *b0, vlib_buffer_t *b1)
{
  void                *cur0   = vlib_buffer_get_current (b0);
  ip4_header_t        *ip40   = cur0;
  udp_header_t        *udp0   = cur0 + sizeof(ip4_header_t);
  vxlan_header_t      *vxlan0 = cur0 + sizeof(ip4_header_t) + sizeof(udp_header_t);
  u32                 fi0    = vlib_buffer_get_ip4_fib_index (b0);

  void                *cur1   = vlib_buffer_get_current (b1);
  ip4_header_t        *ip41   = cur1;
  udp_header_t        *udp1   = cur1 + sizeof(ip4_header_t);
  vxlan_header_t      *vxlan1 = cur1 + sizeof(ip4_header_t) + sizeof(udp_header_t);
  u32                 fi1    = vlib_buffer_get_ip4_fib_index (b1);

  u32                 sw_if_index;
  u16                 last_src_port = 0;
  last_tunnel_cache4  last4;
  vxlan_decap_info_t  di;

  clib_memset (&last4, 0xff, sizeof last4);
  last_src_port = 0;

  if (ip40->protocol == IP_PROTOCOL_UDP  &&  udp0->dst_port == clib_host_to_net_u16(4789))
  {
    di = vxlan4_find_tunnel (&vxlan_main, &last4, &last_src_port, fi0, ip40, udp0, vxlan0, &sw_if_index);
    if (di.sw_if_index != ~0)
      vnet_buffer(b0)->escape_feature_groups |= g;
  }
  if (ip41->protocol == IP_PROTOCOL_UDP  &&  udp1->dst_port == clib_host_to_net_u16(4789))
  {
    di = vxlan4_find_tunnel (&vxlan_main, &last4, &last_src_port, fi1, ip41, udp1, vxlan1, &sw_if_index);
    if (di.sw_if_index != ~0)
      vnet_buffer(b1)->escape_feature_groups |= g;
  }
}

always_inline void vnet_vxlan4_set_escape_feature_group_x4(vnet_feature_group_t g,
            vlib_buffer_t *b0, vlib_buffer_t *b1, vlib_buffer_t *b2, vlib_buffer_t *b3)
{
  void                *cur0   = vlib_buffer_get_current (b0);
  ip4_header_t        *ip40   = cur0;
  udp_header_t        *udp0   = cur0 + sizeof(ip4_header_t);
  vxlan_header_t      *vxlan0 = cur0 + sizeof(ip4_header_t) + sizeof(udp_header_t);
  u32                 fi0    = vlib_buffer_get_ip4_fib_index (b0);

  void                *cur1   = vlib_buffer_get_current (b1);
  ip4_header_t        *ip41   = cur1;
  udp_header_t        *udp1   = cur1 + sizeof(ip4_header_t);
  vxlan_header_t      *vxlan1 = cur1 + sizeof(ip4_header_t) + sizeof(udp_header_t);
  u32                 fi1    = vlib_buffer_get_ip4_fib_index (b1);

  void                *cur2   = vlib_buffer_get_current (b2);
  ip4_header_t        *ip42   = cur2;
  udp_header_t        *udp2   = cur2 + sizeof(ip4_header_t);
  vxlan_header_t      *vxlan2 = cur2 + sizeof(ip4_header_t) + sizeof(udp_header_t);
  u32                 fi2    = vlib_buffer_get_ip4_fib_index (b2);

  void                *cur3   = vlib_buffer_get_current (b3);
  ip4_header_t        *ip43   = cur3;
  udp_header_t        *udp3   = cur3 + sizeof(ip4_header_t);
  vxlan_header_t      *vxlan3 = cur3 + sizeof(ip4_header_t) + sizeof(udp_header_t);
  u32                 fi3    = vlib_buffer_get_ip4_fib_index (b3);

  u32                 sw_if_index;
  u16                 last_src_port = 0;
  last_tunnel_cache4  last4;
  vxlan_decap_info_t  di;

  clib_memset (&last4, 0xff, sizeof last4);
  last_src_port = 0;

  if (ip40->protocol == IP_PROTOCOL_UDP  &&  udp0->dst_port == clib_host_to_net_u16(4789))
  {
    di = vxlan4_find_tunnel (&vxlan_main, &last4, &last_src_port, fi0, ip40, udp0, vxlan0, &sw_if_index);
    if (di.sw_if_index != ~0)
      vnet_buffer(b0)->escape_feature_groups |= g;
  }
  if (ip41->protocol == IP_PROTOCOL_UDP  &&  udp1->dst_port == clib_host_to_net_u16(4789))
  {
    di = vxlan4_find_tunnel (&vxlan_main, &last4, &last_src_port, fi1, ip41, udp1, vxlan1, &sw_if_index);
    if (di.sw_if_index != ~0)
      vnet_buffer(b1)->escape_feature_groups |= g;
  }
  if (ip42->protocol == IP_PROTOCOL_UDP  &&  udp2->dst_port == clib_host_to_net_u16(4789))
  {
    di = vxlan4_find_tunnel (&vxlan_main, &last4, &last_src_port, fi2, ip42, udp2, vxlan2, &sw_if_index);
    if (di.sw_if_index != ~0)
      vnet_buffer(b2)->escape_feature_groups |= g;
  }
  if (ip43->protocol == IP_PROTOCOL_UDP  &&  udp3->dst_port == clib_host_to_net_u16(4789))
  {
    di = vxlan4_find_tunnel (&vxlan_main, &last4, &last_src_port, fi3, ip43, udp3, vxlan3, &sw_if_index);
    if (di.sw_if_index != ~0)
      vnet_buffer(b3)->escape_feature_groups |= g;
  }
}
#endif /*#ifdef FLEXIWAN_FEATURE*/


#endif /* included_vnet_vxlan_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
