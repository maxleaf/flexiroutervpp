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

#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/load_balance_map.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_walk.h>
#include <vnet/interface_funcs.h>

/**
 * An extension of the 'vnet_sw_interface_t' interface:
 * binds tunnel or WAN interface into FIB.
 * The 'via' of tunnel is remote peer address, e.g. 10.100.0.4,
 * the 'via' of WAN interface is default GW, e.g. 192.168.1.1.
 *
 * The FWABF uses path labels to route packets. User can assign labels to WAN
 * interfaces or to tunnel loopback interfaces. Than he can add FWABF policy
 * rule with packet classification and labels. The FWABF will check if packet
 * matches the policy classification. If there is match, it will choose
 * interface for packet forwarding by policy label.
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
  fib_node_index_t      pathlist_index;
  fib_path_list_flags_t pathlist_flags;
  fib_route_path_t      pathlist_rpath;

  /**
   * Sibling index on the path-list
   */
  u32 pathlist_sibling;

  /*
   * The index of vnet_sw_interface_t interface served by this object.
   */
  u32 sw_if_index;

  /*
   * The FlexiWAN multilink label.
   */
  fwabf_label_t fwlabel;

} fwabf_sw_interface_t;


/**
 * An auxiliary structure that unites various data related to label,
 * like list of interfaces with same label, label usage statistics, etc.
 */
typedef struct fwabf_label_data_t_
{
  u32* interfaces;
  u32  counter_hits;
  u32  counter_misses;
} fwabf_label_data_t;

/**
 * FIB node type for the fwabf_sw_interface object.
 */
fib_node_type_t fwabf_link_fib_node_type;

/**
 * Database of fwabf_sw_interface_t objects. Vector.
 * sw_if_index is index in this array. The vector is never shrinks.
 */
static fwabf_sw_interface_t* fwabf_links = NULL;

/**
 * Map of labels to fwabf_sw_interfaces.
 * Label is index, element is structure with list of sw_if_index-s.
 */
static fwabf_label_data_t* fwabf_labels = NULL;

/**
 * Map of adjacencies to labels.
 * Adjacencies are represented by indexes (as all other object in vpp).
 * Adjacencies are referenced by DPO-s kept by fwabf_sw_interface_t objects.
 * As any fwabf_sw_interface_t object stands for one tunnel or WAN interface,
 * and tunnel / WAN interafce might have one label only, relation between
 * adjacencies and labels are 1:1.
 * As adjacencies are identified by interfaces and VLIB graph nodes that use
 * these adjacencies, like ip4-rewrite, we assume number of adjacency objects
 * can't overcome the 0xFFFF. Thus 0xFFFF is considered to be a practical limit
 * for size of {interfaces x vlib graph nodes} set.
 * The 0xFFFF limit makes it possible to use array for adjacancy->label mapping,
 * which is best option for dapatplane path.
 */
static u32* adj_indexes_to_labels = NULL;
#define FWABF_MAX_ADJ_INDEX  0xFFFF

/**
 * FWABF nodes.
 * They are initialized in abf_itf_attach.
 * They are enabled on unicast-ip4/6 arc and get traffic before ip4-lookup node.
 */
extern vlib_node_registration_t fwabf_ip4_node;
extern vlib_node_registration_t fwabf_ip6_node;

#define FWABF_SW_INTERFACE_IS_VALID(_sw_if_index) \
                ((_sw_if_index) < vec_len(fwabf_links) && \
                fwabf_links[(_sw_if_index)].sw_if_index != INDEX_INVALID)

#define FWABF_SW_INTERFACE_IS_INVALID(_sw_if_index) \
                ((_sw_if_index) >= vec_len(fwabf_links) || \
                fwabf_links[(_sw_if_index)].sw_if_index == INDEX_INVALID)

/*
 * Forward declarations
 */
static void fwabf_link_refresh_dpo(fwabf_sw_interface_t* link);
static fwabf_sw_interface_t* fwabf_links_find_link(u32 sw_if_index);


u32 fwabf_links_add_interface (
                        const u32               sw_if_index,
                        const fwabf_label_t     fwlabel,
                        const fib_route_path_t* rpath)
{
  fwabf_sw_interface_t* link;
  u32                   old_len;
  dpo_id_t              dpo_invalid = DPO_INVALID;

  if (fwlabel >= FWABF_INVALID_LABEL)
    {
      clib_warning ("label %d is too big, should be less than %d",
        fwlabel, FWABF_INVALID_LABEL);
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  /*
   * Allocate new fwabf_sw_interface_t and new label only if there is no entry yet.
   * Otherwise reuse existing one. Pool never shrinks.
   */
  if (sw_if_index >= vec_len(fwabf_links))
    {
      old_len = vec_len(fwabf_links);
      vec_resize(fwabf_links, (sw_if_index+1) - old_len);
      for (u32 i = old_len; i < vec_len(fwabf_links); i++)
        {
          fwabf_links[i].sw_if_index = INDEX_INVALID;
        }
      link = &fwabf_links[sw_if_index];
    }
  else if (fwabf_links[sw_if_index].sw_if_index == INDEX_INVALID)
    {
      link = &fwabf_links[sw_if_index];
    }
  else
    {
      clib_warning ("sw_if_index=%d exists", sw_if_index);
      return VNET_API_ERROR_VALUE_EXIST;
    }

  /*
   * Labels are preallocated on bootup. No need to allocate now.
   * Just go and update label>->interface mapping.
   */
  vec_add1 (fwabf_labels[fwlabel].interfaces, sw_if_index);

  /*
   * Initialize new fwabf_sw_interface_t now.
   */

  link->fwlabel     = fwlabel;
  link->sw_if_index = sw_if_index;

  /*
   * Create pathlist object and become it's child, so we get updates when
   * forwarding changes. link->fnode is needed to become a part of FIB tree,
   * so we could get updates from parent object.
   */
  fib_node_init (&link->fnode, fwabf_link_fib_node_type);
  link->pathlist_flags   = FIB_PATH_LIST_FLAG_SHARED;
  link->pathlist_rpath   = *rpath;
  link->pathlist_index   = fib_path_list_create (link->pathlist_flags, &link->pathlist_rpath);
  link->pathlist_sibling = fib_path_list_child_add (
          link->pathlist_index, fwabf_link_fib_node_type, sw_if_index);

  /*
   * Update forwarding info of the pathlist, so it will be bound to the right
   * DPO to be used for forwarding according this pathlist,
   * and attach the fwabf_sw_interface object to this DPO.
   */
  ASSERT((rpath->frp_proto==DPO_PROTO_IP4 || rpath->frp_proto==DPO_PROTO_IP6));
  link->dpo_proto = rpath->frp_proto;
  link->dpo       = dpo_invalid;
  fwabf_link_refresh_dpo(link);

  return 0;
}

u32 fwabf_links_del_interface (const u32 sw_if_index)
{
  fwabf_sw_interface_t* link;
  fwabf_label_t         fwlabel;
  u32                   index;

  if (FWABF_SW_INTERFACE_IS_INVALID(sw_if_index))
    {
      return 0;
    }

  /*
   * Free (invalidate) object as soon as possible, so datapath will not use it.
   */
  link    = &fwabf_links[sw_if_index];
  fwlabel = link->fwlabel;
  link->sw_if_index = INDEX_INVALID;

  /*
   * Remove label->interface mapping.
   */
  index = vec_search (fwabf_labels[fwlabel].interfaces, sw_if_index);
  ASSERT (index !=INDEX_INVALID);
  vec_del1 (fwabf_labels[fwlabel].interfaces, index);

  /*
   * Release adjacency if our link is the last owner.
   */
  dpo_reset (&link->dpo);

  /*
   * No explict call to fib_path_list_destroy!
   * It is destroyed by fib_path_list_copy_and_path_remove() on removal last path.
   * As we have only one path - path to remote tunnel end or to wan gateway,
   * the path removal should cause list destroy.
   */
  fib_path_list_child_remove(link->pathlist_index, link->pathlist_sibling);
  link->pathlist_index =
  fib_path_list_copy_and_path_remove(link->pathlist_index, link->pathlist_flags, &link->pathlist_rpath);
  ASSERT(link->pathlist_index==INDEX_INVALID);

  return 0;
}

dpo_id_t fwabf_links_get_dpo (fwabf_label_t fwlabel, const load_balance_t* lb)
{
  const dpo_id_t* lookup_dpo;
  dpo_id_t        invalid_dpo = DPO_INVALID;
  u32             i;

  /*
   * lb - is DPO of Load Balance type. It is the object returned by the FIB
   * lookup, so it reflects adjacency and correspondent VLIB graph node to be
   * used for forwarding packet.
   * Note the FIB lookup result DPO doesn't point to final DPO directly.
   * Instead it might point to either single final DPO or to multiple mapped DPO-s.
   * Final DPO is DPO that is bound to adjacency. Mapped DPO-s are used in case
   * of Equal Cost MultiPath (ECMP). They reflect multiple available paths to
   * reach destination. Mapped DPO can be of final type in simple case, or it
   * can be a recursive Load Balalance type, or even other type.
   * To get final DPO of it, the load_balance_get_fwd_bucket() function should
   * be used.
   */

  if (PREDICT_FALSE (lb->lb_n_buckets == 1))
    {
       /*
        * The 'lb' DPO points to the final one.
        */

      lookup_dpo = load_balance_get_bucket_i (lb, 0);

      /*
       * Intersect lookup DPO with labeled DPO-s.
       * To do that just check if the adjacency pointed by the FIB lookup final
       * DPO exists in adjacency-to-label map and the map brings the label.
       * Note the adjacency-to-label map is updated based on labeled DPO-s,
       * so if lookup DPO has label in the map, it is same DPO that we labeled.
       * Note labeled DPO-s are kept in correspondent fwabf_sw_interface_t object
       * and are managed by FWABF module. See fwabf_link_refresh_dpo()
       * for details.
       */
      ASSERT(lookup_dpo->dpoi_index < FWABF_MAX_ADJ_INDEX);
      if (PREDICT_TRUE(adj_indexes_to_labels[lookup_dpo->dpoi_index] == fwlabel))
        {
          fwabf_labels[fwlabel].counter_hits++;
          return *lookup_dpo;
        }
    }
  else
    {
       /*
        * The 'lb' DPO points to the mapped DPO-s.
        * Go over them and find the first one with the provided label.
        */
      for (i=0; i<lb->lb_n_buckets; i++)
        {
          lookup_dpo = load_balance_get_fwd_bucket (lb, i);
          ASSERT(lookup_dpo->dpoi_index < FWABF_MAX_ADJ_INDEX);
          if (PREDICT_TRUE(adj_indexes_to_labels[lookup_dpo->dpoi_index] == fwlabel))
            {
              fwabf_labels[fwlabel].counter_hits++;
              return *lookup_dpo;
            }
        }
    }

  /*
   * No match between lookup DPO and labeled DPO-s.
   */
  fwabf_labels[fwlabel].counter_misses++;
  return invalid_dpo;
}

static fwabf_sw_interface_t * fwabf_links_find_link(u32 sw_if_index)
{
  if (FWABF_SW_INTERFACE_IS_INVALID(sw_if_index))
    {
      return NULL;
    }
  return &fwabf_links[sw_if_index];
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

  if (is_add)
    {
      /*
       * It was decided not to validate if interface is WAN or loopback.
       * So just go and add it.
       */
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
  fwabf_sw_interface_t* link = va_arg (*args, fwabf_sw_interface_t*);
  vnet_main_t*          vnm = va_arg (*args, vnet_main_t*);

  s = format (s, " %U: sw_if_index=%d, label=%d\n",
	                  format_vnet_sw_if_index_name, vnm, link->sw_if_index,
                    link->sw_if_index, link->fwlabel);
  s = fib_path_list_format(link->pathlist_index, s);
  return (s);
}

static clib_error_t *
fwabf_link_show_cmd (
        vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32          sw_if_index = INDEX_INVALID;
  vnet_main_t* vnm         = vnet_get_main ();
  fwabf_sw_interface_t * link;

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
      vec_foreach(link, fwabf_links)
        {
          if (link->sw_if_index != INDEX_INVALID)
            {
              vlib_cli_output(vm, "%U", format_fwabf_link, link, vnm);
            }
        };
    }
  else
    {
      link = fwabf_links_find_link(sw_if_index);
      if (link == NULL)
        {
          vlib_cli_output (vm, "Invalid sw_if_index %d", sw_if_index);
          return (NULL);
        }
      vlib_cli_output (vm, "%U", format_fwabf_link, link, vnm);
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

static clib_error_t *
fwabf_link_show_labels_cmd (
        vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32                   verbose = 0;
  vnet_main_t*          vnm     = vnet_get_main();
  fwabf_sw_interface_t* link;
  u32                   i;
  u32*                  sw_if_index;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
        verbose = 1;
      else
        return (clib_error_return (0, "unknown input '%U'",
				                           format_unformat_error, input));
    }

  for (i=0; i<FWABF_MAX_LABEL; i++)
    {
      if (vec_len(fwabf_labels[i].interfaces) == 0)
        continue;

      vlib_cli_output(vm, "%d (hits:%d misses:%d):",
          i, fwabf_labels[i].counter_hits, fwabf_labels[i].counter_misses);
      vec_foreach (sw_if_index, fwabf_labels[i].interfaces)
        {
          link = &fwabf_links[*sw_if_index];
          if (verbose)
            {
              vlib_cli_output(vm, "  %U", format_fwabf_link, link, vnm);
            }
          else
            {
              vlib_cli_output(vm, "  %U (sw_if_index=%d)",
                format_vnet_sw_if_index_name, vnm, link->sw_if_index,
                link->sw_if_index);
            }
        }
    }
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (fwabf_link_show_labels_cmd_node, static) = {
  .path = "show fwabf labels",
  .function = fwabf_link_show_labels_cmd,
  .short_help = "show fwabf labels [verbose]",
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
void fwabf_link_refresh_dpo(fwabf_sw_interface_t * link)
{
  dpo_id_t                 via_dpo = DPO_INVALID;
  fib_forward_chain_type_t fwd_chain_type;
  u32                      fwabf_node_index;

  if (link->dpo_proto == DPO_PROTO_IP4)
    {
      fwabf_node_index = fwabf_ip4_node.index;
      fwd_chain_type   = FIB_FORW_CHAIN_TYPE_UNICAST_IP4;
    }
  else
    {
      fwabf_node_index = fwabf_ip6_node.index;
      fwd_chain_type   = FIB_FORW_CHAIN_TYPE_UNICAST_IP6;
    }

  /*
   * Befor refreshing DPO remove the current value from a adj_indexes_to_labels map.
   */
  if (PREDICT_TRUE(dpo_id_is_valid(&link->dpo)))
    {
      adj_indexes_to_labels[link->dpo.dpoi_index] = FWABF_INVALID_LABEL;
    }

  /*
   * Now refresh the DPO.
   */
  fib_path_list_contribute_forwarding (
      link->pathlist_index, fwd_chain_type, FIB_PATH_LIST_FWD_FLAG_COLLAPSE, &via_dpo);
  dpo_stack_from_node (fwabf_node_index, &link->dpo, &via_dpo);
  dpo_reset (&via_dpo);

  /*
   * Update adj_indexes_to_labels map with refreshed DPO.
   * Note we add only active DPO-s to the map, so ensure that DPO state
   * is DPO_ADJACENCY and not DPO_ADJACENCY_INCOMPLETE.
   * The last is set, if the adjacency is not arp-resolved, which means
   * the tunnel / WAN nexthop is down.
   */
  if (PREDICT_TRUE(link->dpo.dpoi_type == DPO_ADJACENCY))
    {
      ASSERT(link->dpo.dpoi_index < FWABF_MAX_ADJ_INDEX);
      adj_indexes_to_labels[link->dpo.dpoi_index] = link->fwlabel;
    }
}


/**
 * This function is a part of FIB graph logic.
 * See virtual function table fwabf_sw_interface_vft below.
 * It is used when FIB framework back walks on graph to inform nodes of
 * forwarding information update.
 * It gets the FWABF Link (fwabf_sw_interface_t object) out of embedded into it
 * fib_node_t object.
 */
static
fwabf_sw_interface_t * fwabf_sw_interface_get_from_node (fib_node_t * node)
{
  return ((fwabf_sw_interface_t *)
    (((char *) node) - STRUCT_OFFSET_OF (fwabf_sw_interface_t, fnode)));
}

/**
 * This function is a part of FIB graph logic.
 * See virtual function table fwabf_sw_interface_vft below.
 * It is used when FIB framework back walks on graph to inform nodes of
 * forwarding information update.
 * It returns the fib_node_t object that is embedded into the FWABF Link
 * (fwabf_sw_interface_t object) by index of link in pool of links.
 */
static
fib_node_t * fwabf_sw_interface_fnv_get_node (fib_node_index_t index)
{
  fwabf_sw_interface_t* link;
  ASSERT((FWABF_SW_INTERFACE_IS_VALID(index)));
  link = &fwabf_links[index];
  return (&(link->fnode));
}

/**
 * This function is a part of FIB graph logic.
 * See virtual function table fwabf_sw_interface_vft below.
 * FIB framework invokes it when the node (FWABF Link) has no more children,
 * so it can be safely destructed.
 * The children mechanism is used to propagate forwarding informantion updates.
 */
static
void fwabf_sw_interface_fnv_last_lock_gone (fib_node_t * node)
{
  /*not in use, as no one is attached to fwabf_sw_inteface object in FIB graph*/
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
  fwabf_sw_interface_t *link = fwabf_sw_interface_get_from_node(node);

  /*
   * Update DPO with the new current forwarding info.
   */
  fwabf_link_refresh_dpo(link);

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
  /*
   * Register fwabf_sw_interface with FIB graph, so it can be inserted into
   * the graph in order to get forwarding updates.
   */
  fwabf_link_fib_node_type = fib_node_register_new_type (&fwabf_sw_interface_vft);

  /*
   * Initialize array of labels, elements of which are lists of interfaces
   * marked with label. We preallocate it as label range is know in advance
   * and is pretty small: [0-254].
   */
  vec_validate(fwabf_labels, FWABF_MAX_LABEL);
  for (u32 i = 0; i < vec_len(fwabf_labels); i++)
  {
    memset(&fwabf_labels[i], 0, sizeof(fwabf_labels[i]));
    fwabf_labels[i].interfaces = vec_new(u32, 0);
  }

  /*
   * Initialize array of adjacencies, elements of which are labels.
   * We preallocate it as number of adjacencies is limited by 0xFFFF.
   */
  vec_validate(adj_indexes_to_labels, FWABF_MAX_ADJ_INDEX);
  vec_set(adj_indexes_to_labels, FWABF_INVALID_LABEL);

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
