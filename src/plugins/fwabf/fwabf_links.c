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

#include <plugins/fwabf/fwabf_links.h>

#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_walk.h>
#include <vnet/interface_funcs.h>

/**
 * An extension of the 'vnet_sw_interface_t' interface for FWABF needs:
 * binds tunnel or WAN interface into FIB.
 * The 'via' of tunnel is remote peer address, e.g. 10.100.0.4,
 * the 'via' of WAN interface is default GW, e.g. 192.168.1.1.
 *
 * The FWABF uses path labels to route packets. User can assign labels to WAN
 * interfaces or to tunnel loopback interfaces. Than he can add FWABF policy
 * that choose interface for forwarding by label.
 * For now (March 2020) relation between labels and interfaces is 1:1.
 * WAN interfaces can be labeled for Direct Internet Access (DIA) only.
 */
typedef struct fwabf_sw_interface_t_
{
  /**
   * Linkage into the FIB graph
   */
  fib_node_t fnode;

  /**
   * The DPO actually used for forwarding
   */
  dpo_id_t dpo;

  /**
   * ip4/ip6/whatever.
   * For now (March 2020) we don't enable mixed IPv4/6 tunnels and WAN-s.
   */
  dpo_proto_t dpo_proto;

  /**
   * The path-list describing how to forward using this interface
   */
  fib_node_index_t pathlist;

  /**
   * Sibling index on the path-list
   */
  u32 pathlist_sibling;

  /*
   * The index of vnet_sw_interface_t interface served by this object.
   */
  u32 sw_if_index;
} fwabf_sw_interface_t;


/**
 * FIB node type for the fwabf_sw_interface object.
 */
fib_node_type_t fwabf_sw_interface_fib_node_type;

/**
 * DB of fwabf_sw_interfaces, where label is index.
 * We use labels as index to implement fast fetch of DPO by label in dataplane.
 * For now (March 2020) label to interface relation is 1:1.
 */
static fwabf_sw_interface_t* fwabf_sw_interface_db = NULL;

/**
 * Map of sw_if_index to it's label.
 * For now (March 2020) we assume that interface has no more than one label.
 */
static fwabf_label_t* fwabf_label_by_sw_if_index_db = NULL;

/**
 * FWABF nodes.
 * They are initialized in abf_itf_attach.
 * They are enabled on unicast-ip4/6 arc and get traffic before ip4-lookup node.
 */
extern vlib_node_registration_t fwabf_ip4_node;
extern vlib_node_registration_t fwabf_ip6_node;

#define FWABF_SW_INTERFACE_FREE(aif)         ((aif)->sw_if_index = INDEX_INVALID)
#define FWABF_SW_INTERFACE_IS_VALID(index)   ((index) < vec_len(fwabf_sw_interface_db) && \
                                              fwabf_sw_interface_db[(index)].sw_if_index != INDEX_INVALID)
#define FWABF_SW_INTERFACE_IS_INVALID(index) ((index) >= vec_len(fwabf_sw_interface_db) || \
                                              fwabf_sw_interface_db[(index)].sw_if_index == INDEX_INVALID)

#define FWABF_SW_IF_INDEX_FREE(sw_if_index)       (fwabf_label_by_sw_if_index_db[(sw_if_index)] = FWABF_INVALID_LABEL)
#define FWABF_SW_IF_INDEX_IS_INVALID(sw_if_index) ((sw_if_index) >= vec_len(fwabf_label_by_sw_if_index_db) || \
                                                   fwabf_label_by_sw_if_index_db[(sw_if_index)] == FWABF_INVALID_LABEL)


/*
 * Forward declarations
 */
static void
fwabf_sw_interface_refresh_dpo(fwabf_sw_interface_t * aif);
static fwabf_sw_interface_t*
fwabf_sw_interface_find(u32 sw_if_index);


u32 fwabf_links_add_interface (
                        const u32               sw_if_index,
                        const fwabf_label_t     fwlabel,
                        const fib_route_path_t* rpath)
{
  fwabf_sw_interface_t* aif;
  u32                   old_len;

  /*
   * Allocate new element only if there is no entry for fwlabel yet.
   * Otherwise reuse existing one. For now (March 2020) we permit only one
   * interface per label, so the fwabf_sw_interface_db[] represents vector of
   * interfaces instances.
   * As well the vector is never shrinked. The label type is u8, so no more than
   * 255 elements are possible.
   */
  if (fwlabel >= FWABF_INVALID_LABEL)
    {
      clib_warning ("label %d is too big, should be less than %d",
        fwlabel, FWABF_INVALID_LABEL);
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }
  if (fwlabel >= vec_len(fwabf_sw_interface_db))
    {
      old_len = vec_len(fwabf_sw_interface_db);
      vec_resize(fwabf_sw_interface_db, (fwlabel+1) - old_len);
      for (u32 i = old_len; i < vec_len(fwabf_sw_interface_db); i++)
        {
          FWABF_SW_INTERFACE_FREE(&fwabf_sw_interface_db[i]);
        }
      aif = &fwabf_sw_interface_db[fwlabel];
    }
  else if (FWABF_SW_INTERFACE_IS_INVALID(fwlabel))
    {
      aif = &fwabf_sw_interface_db[fwlabel];
    }
  else
    {
      clib_warning ("label %d is already assigned (sw_if_index=%d)",
        fwlabel, fwabf_sw_interface_db[fwlabel].sw_if_index);
      return VNET_API_ERROR_VALUE_EXIST;
    }

  fib_node_init (&aif->fnode, fwabf_sw_interface_fib_node_type);
  aif->pathlist = fib_path_list_create (
          (FIB_PATH_LIST_FLAG_SHARED), rpath);

  /*
   * Become a child of the path list so we get poked when the forwarding changes.
   */
  aif->pathlist_sibling = fib_path_list_child_add (
          aif->pathlist, fwabf_sw_interface_fib_node_type, fwlabel);

  /*
   * Update forwarding info of the pathlist, so it will be bound to the right
   * DPO to be used for forwarding according this pathlist,
   * and attach the fwabf_sw_interface object to this DPO.
   */
  ASSERT((rpath->frp_proto==DPO_PROTO_IP4 || rpath->frp_proto==DPO_PROTO_IP6));
  aif->dpo_proto = rpath->frp_proto;
  fwabf_sw_interface_refresh_dpo(aif);

  /*
   * Store the sw_if_index -> label mapping.
   * Resize db if needed.
   */
  if (sw_if_index >= vec_len(fwabf_label_by_sw_if_index_db))
    {
      old_len = vec_len(fwabf_label_by_sw_if_index_db);
      vec_resize(fwabf_label_by_sw_if_index_db, (sw_if_index+1) - old_len);
      for (u32 i = old_len; i < vec_len(fwabf_label_by_sw_if_index_db); i++)
        {
          FWABF_SW_IF_INDEX_FREE(i);
        }
    }
  ASSERT(FWABF_SW_IF_INDEX_IS_INVALID(sw_if_index));
  fwabf_label_by_sw_if_index_db[sw_if_index] = fwlabel;

  aif->sw_if_index = sw_if_index;
  return 0;
}

u32 fwabf_links_del_interface (const u32 sw_if_index)
{
  fwabf_sw_interface_t* aif;

  aif = fwabf_sw_interface_find(sw_if_index);
  if (aif == NULL)
    {
      return 0;
    }

  /*
   * Free (invalidate) object as soon as possible, so datapath will not use it.
   * nnoww - think of locks . or order for free() and rest resets (use local variables?)!
   */
  FWABF_SW_INTERFACE_FREE(aif);
  FWABF_SW_IF_INDEX_FREE(sw_if_index);

  /*
   * Copied from ABF, but do we really need this?
   * Looks like the dpo is not accessable anymore and it has no effect on vlib graph!
   */
  dpo_reset (&aif->dpo);

  /*
   * No explict call to fib_path_list_destroy!
   * It will be destroyed automatically on no more children!
   * nnoww - ensure this!
   */
  fib_path_list_child_remove(aif->pathlist, aif->pathlist_sibling);

  return 0;
}

dpo_id_t fwabf_links_get_dpo (fwabf_label_t fwlabel, dpo_proto_t dpo_proto)
{
  fwabf_sw_interface_t* aif;
  dpo_id_t              dpo;
  dpo_id_t              invalid_dpo = DPO_INVALID;


  /**
   * The label might have no assigned interfaces yet.
   */
  if (PREDICT_FALSE(FWABF_SW_INTERFACE_IS_INVALID(fwlabel)))
    return invalid_dpo;

  aif = &fwabf_sw_interface_db[fwlabel];

  /**
   * For now (March 2020) fwabf_sw_interface_t can be either ip4 or ip6,
   * but now both of them. We anticipate only one type of traffic by ACL rule.
   *
   * To crack correct usage of PREDICT_X optimization just keep in mind that
   *    PREDICT_TRUE(<condition that is likely to be true>)
   * enters into 'if' block if condition is true.
   * So PREDICT_FALSE should be used with !<condition that is likely to be true> :)
   */
  if (PREDICT_FALSE(dpo_proto != aif->dpo_proto))
    return invalid_dpo;

  dpo = fwabf_sw_interface_db[fwlabel].dpo;

  /**
   * If remote end of tunnel is not on air, the arp will be needed to resolve
   * adjacency DPO. In this case the interface is not usable.
   */
  if (PREDICT_FALSE(dpo.dpoi_type == DPO_ADJACENCY_INCOMPLETE))
    return invalid_dpo;

  return dpo;
}

static fwabf_sw_interface_t * fwabf_sw_interface_find(u32 sw_if_index)
{
  fwabf_label_t fwlabel;

  if (FWABF_SW_IF_INDEX_IS_INVALID(sw_if_index))
    {
      clib_warning ("sw_if_index %d not found", sw_if_index);
      return NULL;
    }

  fwlabel = fwabf_label_by_sw_if_index_db[sw_if_index];
  ASSERT(FWABF_SW_INTERFACE_IS_VALID(fwlabel));
  return &fwabf_sw_interface_db[fwlabel];
}

static
clib_error_t * fwabf_link_cmd (
                  vlib_main_t * vm, unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_route_path_t  rpath;
  fib_route_path_t* rpath_vec    = 0;
  u32               sw_if_index  = INDEX_INVALID;
  u32               fwlabel      = FWABF_INVALID_LABEL;
  u32               is_add       = 0;

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return (NULL);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "label %d", &fwlabel))
        {
          if (fwlabel >= FWABF_INVALID_LABEL)
            {
              if (rpath_vec)
                vec_free(rpath_vec);
              return (clib_error_return (0, "illegal label %d, should be in range [0-254]", fwlabel));
            }
        }
      else if (unformat (line_input, "via %U", unformat_fib_route_path, &rpath))
        {
          if (rpath_vec != 0)
            {
              return (clib_error_return (0, "no more than one 'via' is allowed"));
            }
          /*
           * Ensure the path & dpo will be of FIB_PATH_TYPE_ATTACHED_NEXT_HOP type.
           */
          if (rpath.frp_sw_if_index == ~0)
            {
              return (clib_error_return (0, "interface name was not specified for via"));
            }
          vec_add1(rpath_vec, rpath);
          sw_if_index = rpath.frp_sw_if_index;
        }
      else if (unformat (line_input, "add"))
	      is_add = 1;
      else if (unformat (line_input, "del"))
	      is_add = 0;
      else
        {
          if (rpath_vec)
            vec_free(rpath_vec);
          return (clib_error_return (0, "unknown input '%U'",
                                    format_unformat_error, line_input));
        }
    }

  if (rpath_vec == 0)    /* we need via for DEL also as it brings us sw_if_index */
    {
      vlib_cli_output (vm, "specify a via");
      return (NULL);
    }
  if (sw_if_index == INDEX_INVALID)
    {
      vlib_cli_output (vm, "specify a sw_if_index");
      vec_free(rpath_vec);
      return (NULL);
    }
  if (is_add)
    {
      if (fwlabel == FWABF_INVALID_LABEL)
        {
          vlib_cli_output (vm, "specify a label");
          vec_free(rpath_vec);
          return (NULL);
        }
    }

  // nnoww - TODO - add validation that interface is WAN or loopback

  if (is_add)
    {
      fwabf_links_add_interface (sw_if_index, fwlabel, rpath_vec);
    }
  else
    {
      fwabf_links_del_interface (sw_if_index);
    }

  unformat_free (line_input);
  vec_free(rpath_vec);
  return (NULL);
}

/* *INDENT-OFF* */
/**
 * Add/delete link with label.
 */
VLIB_CLI_COMMAND (fwabf_link_cmd_node, static) = {
  .path = "fwabf link",
  .function = fwabf_link_cmd,
  .short_help = "fwabf link [add|del] label <[0..254]> via <address> <if name>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static u8 *
format_fwabf_link (u8 * s, va_list * args)
{
  fwabf_sw_interface_t* aif     = va_arg (*args, fwabf_sw_interface_t*);
  vnet_main_t*          vnm     = va_arg (*args, vnet_main_t*);
  u32                   fwlabel = (aif - fwabf_sw_interface_db);

  s = format (s, " %U: sw_if_index=%d, label=%d\n",
	                  format_vnet_sw_if_index_name, vnm, aif->sw_if_index,
                    aif->sw_if_index, fwlabel);
  s = fib_path_list_format(aif->pathlist, s);
  return (s);
}

static clib_error_t *
fwabf_link_show_cmd (
        vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32          sw_if_index = INDEX_INVALID;
  vnet_main_t* vnm         = vnet_get_main ();
  fwabf_sw_interface_t * aif;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sw_if_index %d", &sw_if_index))
        ;
      else if (unformat (input, "%U",
                         unformat_vnet_sw_interface, vnm, &sw_if_index))
        ;
      else
        return (clib_error_return (0, "unknown input '%U'",
				                           format_unformat_error, input));
    }

  if (sw_if_index == INDEX_INVALID)
    {
      vec_foreach(aif, fwabf_sw_interface_db)
        {
          if (aif->sw_if_index != INDEX_INVALID)
            {
              vlib_cli_output(vm, "%U", format_fwabf_link, aif, vnm);
            }
        };
    }
  else
    {
      aif = fwabf_sw_interface_find(sw_if_index);
      if (aif == NULL)
        {
          vlib_cli_output (vm, "Invalid sw_if_index %d", sw_if_index);
          return (NULL);
        }
      vlib_cli_output (vm, "%U", format_fwabf_link, aif, vnm);
    }
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (fwabf_link_show_cmd_node, static) = {
  .path = "show fwabf link",
  .function = fwabf_link_show_cmd,
  .short_help = "show fwabf link [sw_if_index <sw_if_index> | <if name>]",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/**
 * Updates forwarding info of the pathlist, so the pathlist will resolve
 * to the right DPO to be used for forwarding according this pathlist,
 * saves this DPO into the fwabf_sw_interface_t object for fast use
 * and attaches the FWABF node to it. The attachment is called 'stack on dpo'
 * in terms of vpp. It creates edge in vlib graph from FWABF node to the node
 * bound to the forwarding DPO, e.g. ip4-rewrite.
 */
static
void fwabf_sw_interface_refresh_dpo(fwabf_sw_interface_t * aif)
{
  dpo_id_t                 via_dpo = DPO_INVALID;
  fib_forward_chain_type_t fwd_chain_type;
  u32                      fwabf_node_index;

  if (aif->dpo_proto == DPO_PROTO_IP4)
    {
      fwabf_node_index = fwabf_ip4_node.index;
      fwd_chain_type   = FIB_FORW_CHAIN_TYPE_UNICAST_IP4;
    }
  else
    {
      fwabf_node_index = fwabf_ip6_node.index;
      fwd_chain_type   = FIB_FORW_CHAIN_TYPE_UNICAST_IP6;
    }

  fib_path_list_contribute_forwarding (
      aif->pathlist, fwd_chain_type, FIB_PATH_LIST_FWD_FLAG_COLLAPSE, &via_dpo);
  dpo_stack_from_node (fwabf_node_index, &aif->dpo, &via_dpo);
  dpo_reset (&via_dpo);
}

// nnoww - document
static
fwabf_sw_interface_t * fwabf_sw_interface_get_from_node (fib_node_t * node)
{
  return ((fwabf_sw_interface_t *)
    (((char *) node) - STRUCT_OFFSET_OF (fwabf_sw_interface_t, fnode)));
}

// nnoww - document
static
fib_node_t * fwabf_sw_interface_fnv_get_node (fib_node_index_t index)
{
  fwabf_sw_interface_t* aif;
  ASSERT((FWABF_SW_INTERFACE_IS_VALID(index)));
  aif = &fwabf_sw_interface_db[index];
  return (&(aif->fnode));
}

// nnoww - document
static
void fwabf_sw_interface_fnv_last_lock_gone (fib_node_t * node)
{
  // nnoww - not in use for now, as no one is attached to the fwabf_sw_inteface object by FIB graph
  // abf_policy_destroy (fwabf_policy_get_from_node (node));
}

/*
 * A back walk has reached this fwabf_sw_interface_t instance.
 * That means forwarding information got updated. Most probable due to tunnel /
 * route removal/adding or due to change in NIC state (UP/DOWN).
 * We have to update our DPO with the currently available DPO.
 * If no route exists,it will be updated to DPO_DROP.
 */
static
fib_node_back_walk_rc_t fwabf_sw_interface_fnv_back_walk_notify (
                            fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  fwabf_sw_interface_t *aif = fwabf_sw_interface_get_from_node(node);

  /*
   * Update DPO with the new current forwarding info.
   */
  fwabf_sw_interface_refresh_dpo(aif);

  // nnoww - not in use for now, as no one is attached to the fwabf_sw_inteface object by FIB graph
  /*
   * propagate further up the graph.
   * we can do this synchronously since the fan out is small.
   */
  // fib_walk_sync (abf_policy_fib_node_type, fwabf_policy_get_index (abf), ctx);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The FIB graph node virtual function table.
 * It is used for walking on graph to propagate forwarding information updates.
 */
static const fib_node_vft_t fwabf_sw_interface_vft = {
  .fnv_get       = fwabf_sw_interface_fnv_get_node,
  .fnv_last_lock = fwabf_sw_interface_fnv_last_lock_gone,
  .fnv_back_walk = fwabf_sw_interface_fnv_back_walk_notify,
};

static
clib_error_t * fwabf_links_init (vlib_main_t * vm)
{
  fwabf_sw_interface_fib_node_type = fib_node_register_new_type (&fwabf_sw_interface_vft);

  return (NULL);
}

VLIB_INIT_FUNCTION (fwabf_links_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
