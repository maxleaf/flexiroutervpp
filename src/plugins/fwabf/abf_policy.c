/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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


// nnoww - DOCUMENT

#include <plugins/fwabf/abf_policy.h>

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/drop_dpo.h>

// nnoww - TODO !!! - NOT DECIDED YET - Use label with mutlitple tunnels and choose by distance
//   +
// nnoww - fetch all possible routes from FIB and cross them with labels
//         Assumption: there is static default routes that turn ABR case into usual routing case,
//                     so destination IP will be matches in FIB and in labels always!


// nnoww - DONE - hash flow to make random selection for flow, and not for packet
// nnoww - TODO !!! - Solution:  idx = flow_hash & 0xFF;
//                               if (idx >= ap->action.n_link_groups)
//                                  idx = idx & (ap->action.n_link_groups-1);

// nnoww - CANCELLED - NOT NEEDED - check if policy -> labels <-> interface showed be optimized (add policy to fib???)

// nnoww - DONE - enable "all traffic" class (by Denys :))

// nnoww - TODO - move format functions to separate file

// nnoww - POSTPONED - take care of IPv6

// nnoww - DONE - fallback of drop

// nnoww - POSTPONED - add counters to labels and show them by CLI (see vlib_node_increment_counter() in abf_itf_attach.c)

// nnoww - TODO - clean all nnoww-s :)

// nnoww - TODO - add validation on delete policy that no attachment objects exist!

// nnoww - POSTPONED - check trace of FWABF node and add missing info if needed

// nnoww - CANCELLED - ASK Nir - should we separate IPv4 and IPv6 links, so IPv4 packet is not forwarded into IPv6 labels!


// nnoww - POSTPONED - check if quad and dual loops & prefetch (see ip4_lookup_inline) should be addded in nodes! (once we can measure benchmarking with the new feature)
// nnoww - POSTPONED - check if separation of ip4 and ip6 nodes should be done! (once we can measure benchmarking with the new feature)


// nnoww - TEST - test POLICY CLI thoroughly

// nnoww - TODO !!! - Multiple interfaces per label !!!

// nnoww - LIMITATION - OK - for now (March 2020) we don't enable labels with mixed IPv4/6 tunnels and WAN-s - see fwabf_sw_interface_t::dpo_proto field.
// nnoww - LIMITATION - OK - no ABF on WAN-to-LAN packets, as it does not work with NAT today! (see Denys fixes in NAT branch)

// nnoww - ASK Nir - DO SAME AS VPP - check VPP FIB for X.255 entries - if should support LAN Broadcast addresses - 192.168.1.255 - that requires refcounter (the 255.255.255.255 I already added)?

// nnoww - TODO - ensure that endianity of IP6 address stored in fwabf_locals matches that of packet in vlib_buffer

// nnoww - TEST - ???? - NAT & ABF coexistence:
//                  1. Modified by NAT packets go through FWABF
//                  2. NOT Modified by NAT packets go through FWABF
//                  3. Reassembled packets go through FWABF
//                  4. ICMP packet go FWABF ???
//

// nnoww - TEST - DONE - remove policy restore original flow / add again recreates new flow!
// nnoww - TEST - DONE - remove tunnel restore original flow / add again (and new fwabf link) - recreates new flow!
// nnoww - TEST - DONE - stop VPP-3 restore original flow / start again recreates new flow!


// nnoww - TEST - ???? - Incoming DHCP Server packets should be not shadled by policy!

// nnoww - moved to fwabf_sw_interface_t
/**
 * FIB node type the attachment is registered
 */
//fib_node_type_t abf_policy_fib_node_type;

/**
 * Pool of ABF objects
 */
static abf_policy_t *abf_policy_pool;

/**
  * DB of ABF policy objects
  *  - policy ID to index conversion.
  */
static abf_policy_t *abf_policy_db;


abf_policy_t *
fwabf_policy_get (u32 index)
{
  return (pool_elt_at_index (abf_policy_pool, index));
}

// static u32
// fwabf_policy_get_index (const abf_policy_t * abf)
// {
//   return (abf - abf_policy_pool);
// }

static abf_policy_t *
fwabf_policy_find_i (u32 policy_id)
{
  u32 api;

  api = fwabf_policy_find (policy_id);

  if (INDEX_INVALID != api)
    return (fwabf_policy_get (api));

  return (NULL);
}

u32
fwabf_policy_find (u32 policy_id)
{
  uword *p;

  p = hash_get (abf_policy_db, policy_id);

  if (NULL != p)
    return (p[0]);

  return (INDEX_INVALID);
}


u32
abf_policy_add (u32 policy_id, u32 acl_index, fwabf_policy_action_t * action)
{
  abf_policy_t*              ap;
  fwabf_policy_link_group_t* group;
  u32 api;

  api = fwabf_policy_find (policy_id);
  if (api != INDEX_INVALID)
  {
    clib_warning ("fawbf: abf_policy_add: policy-id %d exists (index %d)", policy_id, api);
    return VNET_API_ERROR_VALUE_EXIST;
  }

  pool_get (abf_policy_pool, ap);
  api = ap - abf_policy_pool;

  ap->ap_acl = acl_index;
  ap->ap_id  = policy_id;
  ap->action = *action;

  ap->action.n_link_groups_minus_1 = vec_len(action->link_groups) - 1;
  vec_foreach (group, ap->action.link_groups)
    group->n_links_minus_1 = vec_len(group->links) - 1;

  /*
    * add this new policy to the DB
    */
  hash_set (abf_policy_db, policy_id, api);
  return 0;
}

int
abf_policy_delete (u32 policy_id)
{
  fwabf_policy_link_group_t* group;
  abf_policy_t *ap;
  u32 api;

  api = fwabf_policy_find (policy_id);
  if (INDEX_INVALID == api)
    return VNET_API_ERROR_INVALID_VALUE;

  ap = fwabf_policy_get (api);

  vec_foreach (group, ap->action.link_groups)
    vec_free (group->links);
  vec_free (ap->action.link_groups);

  hash_unset (abf_policy_db, policy_id);
  pool_put (abf_policy_pool, ap);
  return (0);
}

/**
 * Get DPO to use for packet forwarding according to policy
 *
 * @param index     index of abf_policy_t in pool
 * @param ip4       the IPv4 header to be used for flow hash calculation
 * @return VPP's object index
 */
inline dpo_id_t fwabf_policy_get_dpo_ip4 (index_t index, ip4_header_t* ip4)
{
  abf_policy_t*              ap = fwabf_policy_get (index);
  dpo_id_t                   dpo;
  dpo_id_t                   dpo_invalid = DPO_INVALID;
  fwabf_policy_link_group_t* group;
  fwabf_label_t*             fwlabel;
  fwabf_label_t              label;
  u32                        flow_hash;

  // nnoww - Ask Nir - CANCELLED - (DANGEROUS)do you want me to store flow hash result in metadata and implement it reuse in ip4_forward/op4_lookup etc?

  // nnoww - CANCELLED - fix logic: today if we choose random group/link and it has no suitable DPO we fallback into ordered search!
  //                What should be done is choose out of other group/links!
  //                This will be not needed if we implement optimization: keep subset of valid DPO-s only !

  /*
   * Take a care of random selection of link group.
   * If the selection algorithm is not random, just iterate over list of groups
   * and use the first one with valid DPO.
   */
  if (ap->action.alg == FWABF_SELECTION_RANDOM  &&  vec_len(ap->action.link_groups) > 1)
    {
      flow_hash = ip4_compute_flow_hash (ip4, IP_FLOW_HASH_DEFAULT);
      group = &ap->action.link_groups[flow_hash & ap->action.n_link_groups_minus_1];

      /*
       * Take a care of random selection of link within selected group.
       * If randomly selected label has no suitable DPO, fallback into ordered
       * search over list of labels.
       */
      if (group->alg == FWABF_SELECTION_RANDOM  &&  vec_len(group->links) > 1)
        {
          label = group->links[flow_hash & group->n_links_minus_1];
          dpo = fwabf_links_get_dpo (label, DPO_PROTO_IP4);
          if (dpo.dpoi_type != DPO_DROP)
            return dpo;
        }

      /*
       * No random selection - just iterate over list of labels and use the first
       * one with valid DPO. If no valid label was found, fallback into ordered
       * search over list of link groups and their labels.
       */
      vec_foreach (fwlabel, group->links)
        {
          dpo = fwabf_links_get_dpo (*fwlabel, DPO_PROTO_IP4);
          if (dpo.dpoi_type != DPO_DROP)
            return dpo;
        }
    } /*if (ap->action.alg == FWABF_SELECTION_RANDOM  &&  vec_len(ap->action.link_groups) > 1)*/

  /*
   * No random selection - just iterate over list of groups and use the first
   * one with valid DPO.
   */
  vec_foreach (group, ap->action.link_groups)
    {
      /*
       * Take a care of random selection of link within selected group.
       * If randomly selected label has no suitable DPO, fallback into ordered
       * search over list of labels.
       */
      if (group->alg == FWABF_SELECTION_RANDOM  &&  vec_len(group->links) > 1)
        {
          label = group->links[flow_hash & group->n_links_minus_1];
          dpo = fwabf_links_get_dpo (label, DPO_PROTO_IP4);
          if (dpo.dpoi_type != DPO_DROP)
            return dpo;
        }

      vec_foreach (fwlabel, group->links)
        {
          dpo = fwabf_links_get_dpo (*fwlabel, DPO_PROTO_IP4);
          if (dpo.dpoi_type != DPO_DROP)
            return dpo;
        }
    }

  /*
   * At this point no active DPO was found.
   * If fallback is default route, indicate that to caller by DPO_INVALID.
   * If fallback is to drop packets, use the last found DPO, which should be DPO_DROP.
   */
  if (PREDICT_TRUE(ap->action.fallback==FWABF_FALLBACK_DEFAULT_ROUTE))
    return dpo_invalid;

  /*
   * If no DPO was found due to absence of interfaces with policy labels,
   * simulate the dropping DPO.
   */
  if (PREDICT_FALSE(!dpo_id_is_valid(&dpo)))
    {
    	dpo_copy(&dpo, drop_dpo_get(DPO_PROTO_IP4));
    }
  return dpo;
}

/**
 * Get DPO to use for packet forwarding according to policy
 *
 * @param index     index of abf_policy_t in pool
 * @param ip6       the IPv6 header to be used for flow hash calculation
 * @return VPP's object index
 */
inline dpo_id_t fwabf_policy_get_dpo_ip6 (index_t index, ip6_header_t* ip6)
{
  abf_policy_t*              ap = fwabf_policy_get (index);
  dpo_id_t                   dpo;
  dpo_id_t                   dpo_invalid = DPO_INVALID;
  fwabf_policy_link_group_t* group;
  fwabf_label_t*             fwlabel;
  fwabf_label_t              label;
  u32                        flow_hash;

  /*
   * Take a care of random selection of link group.
   * If the selection algorithm is not random, just iterate over list of groups
   * and use the first one with valid DPO.
   */
  if (ap->action.alg == FWABF_SELECTION_RANDOM  &&  vec_len(ap->action.link_groups) > 1)
    {
      flow_hash = ip6_compute_flow_hash (ip6, IP_FLOW_HASH_DEFAULT);
      group = &ap->action.link_groups[flow_hash & ap->action.n_link_groups_minus_1];

      /*
       * Take a care of random selection of link within selected group.
       * If randomly selected label has no suitable DPO, fallback into ordered
       * search over list of labels.
       */
      if (group->alg == FWABF_SELECTION_RANDOM  &&  vec_len(group->links) > 1)
        {
          label = group->links[flow_hash & group->n_links_minus_1];
          dpo = fwabf_links_get_dpo (label, DPO_PROTO_IP6);
          if (dpo.dpoi_type != DPO_DROP)
            return dpo;
        }

      /*
       * No random selection - just iterate over list of labels and use the first
       * one with valid DPO. If no valid label was found, fallback into ordered
       * search over list of link groups and their labels.
       */
      vec_foreach (fwlabel, group->links)
        {
          dpo = fwabf_links_get_dpo (*fwlabel, DPO_PROTO_IP6);
          if (dpo.dpoi_type != DPO_DROP)
            return dpo;
        }
    } /*if (ap->action.alg == FWABF_SELECTION_RANDOM  &&  vec_len(ap->action.link_groups) > 1)*/

  /*
   * No random selection - just iterate over list of groups and use the first
   * one with valid DPO.
   */
  vec_foreach (group, ap->action.link_groups)
    {
      /*
       * Take a care of random selection of link within selected group.
       * If randomly selected label has no suitable DPO, fallback into ordered
       * search over list of labels.
       */
      if (group->alg == FWABF_SELECTION_RANDOM  &&  vec_len(group->links) > 1)
        {
          label = group->links[flow_hash & group->n_links_minus_1];
          dpo = fwabf_links_get_dpo (label, DPO_PROTO_IP6);
          if (dpo.dpoi_type != DPO_DROP)
            return dpo;
        }

      vec_foreach (fwlabel, group->links)
        {
          dpo = fwabf_links_get_dpo (*fwlabel, DPO_PROTO_IP6);
          if (dpo.dpoi_type != DPO_DROP)
            return dpo;
        }
    }

  /*
   * At this point no active DPO was found.
   * If fallback is default route, indicate that to caller by DPO_INVALID.
   * If fallback is to drop packets, use the last found DPO, which should be DPO_DROP.
   */
  if (PREDICT_TRUE(ap->action.fallback==FWABF_FALLBACK_DEFAULT_ROUTE))
    return dpo_invalid;

  /*
   * If no DPO was found due to absence of interfaces with policy labels,
   * simulate the dropping DPO.
   */
  if (PREDICT_FALSE(!dpo_id_is_valid(&dpo)))
    {
    	dpo_copy(&dpo, drop_dpo_get(DPO_PROTO_IP6));
    }
  return dpo;
}

uword
unformat_labels (unformat_input_t * input, va_list * args)
{
  vlib_main_t*    vm     = va_arg (*args, vlib_main_t *);;
  fwabf_label_t** labels = va_arg (*args, fwabf_label_t**);
  u32             label;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d,", &label))
        {
          if (label >= FWABF_INVALID_LABEL)
            {
              vlib_cli_output (vm, "illegal label %d, should be in range [0-254]", label);
              return 0;
            }
          vec_add1(*labels, (fwabf_label_t)label);
        }
      else if (unformat (input, "%d", &label))
        {
          if (label >= FWABF_INVALID_LABEL)
            {
              vlib_cli_output (vm, "illegal label %d, should be in range [0-254]", label);
              return 0;
            }
          vec_add1(*labels, (fwabf_label_t)label);
          return 1; /* finished to parse list of labels */
        }
      else
        return 0; /* failed to parse list of labels*/
    }
  return 0; /* failed to parse input line */
}

uword
unformat_link_group (unformat_input_t * input, va_list * args)
{
  vlib_main_t*               vm    = va_arg (*args, vlib_main_t *);;
  fwabf_policy_link_group_t* group = va_arg (*args, fwabf_policy_link_group_t*);

  group->alg   = FWABF_SELECTION_ORDERED;
  group->links = (NULL);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "random"))
        {
          group->alg = FWABF_SELECTION_RANDOM;
        }
      else if (unformat (input, "labels %U", unformat_labels, vm, &group->links))
        ;
      else
        return 0; /* failed to parse action*/
    }

  if (vec_len(group->links) == 0)
    return 0;

  return 1; /* parsed successfully */
}

uword
unformat_action (unformat_input_t * input, va_list * args)
{
  vlib_main_t*              vm     = va_arg (*args, vlib_main_t *);;
  fwabf_policy_action_t*    action = va_arg (*args, fwabf_policy_action_t *);
  fwabf_policy_link_group_t group;
  u32                       gid;

  action->fallback    = FWABF_FALLBACK_DEFAULT_ROUTE;
  action->alg         = FWABF_SELECTION_ORDERED;
  action->link_groups = (NULL);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "select_group random"))
        {
          action->alg = FWABF_SELECTION_RANDOM;
        }
      else if (unformat (input, "fallback drop"))
        {
          action->fallback = FWABF_FALLBACK_DROP;
        }
      /* Now parse groups of links.
         Firstly give a try to 1-group action - action without 'group' keyword */
      else if (unformat (input, "%U", unformat_link_group, vm, &group))
        {
          vec_add1(action->link_groups, group);
          return 1;   /* finished to parse list of groups*/
        }
      /* Now give a chance to list of groups */
      else if (unformat (input, "group %d %U,", &gid, unformat_link_group, vm, &group))
        {
          vec_add1(action->link_groups, group);
        }
      else if (unformat (input, "group %d %U", &gid, unformat_link_group, vm, &group))
        {
          vec_add1(action->link_groups, group);
          return 1;   /* finished to parse list of groups*/
        }
      else
        return 0; /* failed to parse action*/
    }
  return 0; /* groups were not found */
}

static clib_error_t *
abf_policy_cmd (vlib_main_t * vm,
		unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fwabf_policy_action_t policy_action;
  u32 acl_index, policy_id;
  u32 is_del;
  u32 ret;

  is_del = 0;
  acl_index = INDEX_INVALID;
  policy_id = INDEX_INVALID;

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "acl %d", &acl_index))
        ;
      else if (unformat (line_input, "id %d", &policy_id))
        ;
      else if (unformat (line_input, "del"))
        is_del = 1;
      else if (unformat (line_input, "add"))
        is_del = 0;
      else if (unformat (line_input, "action %U", unformat_action, vm, &policy_action))
        ;
      else
        return (clib_error_return (0, "unknown input '%U'",
                                   format_unformat_error, line_input));
    }

  if (INDEX_INVALID == policy_id)
    {
      vlib_cli_output (vm, "Specify a Policy ID");
      return 0;
    }

  if (!is_del)
    {
      ret = abf_policy_add (policy_id, acl_index, &policy_action);
    }
  else
    {
      ret = abf_policy_delete (policy_id);
    }
  if (ret != 0)
    return (clib_error_return (0, "abf_policy_%s failed(ret=%d)", (is_del?"delete":"add"), ret));

  unformat_free (line_input);
  return 0;
}

/* *INDENT-OFF* */
/**
 * Create an ABF policy.
 */
VLIB_CLI_COMMAND (abf_policy_cmd_node, static) = {
  .path = "fwabf policy",
  .function = abf_policy_cmd,
  .short_help = "fwabf policy [add|del] id <index> [acl <index>] action [select_group random] [fallback drop] [group <id>] [random] labels <label1,label2,...> [group <id> [random] labels <label1,label2,...>] ...",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static u8*
format_link_group (u8 * s, va_list * args)
{
  fwabf_policy_link_group_t* group   = va_arg (*args, fwabf_policy_link_group_t *);
  u32                        n_links = vec_len(group->links);
  char*                      s_alg;

  s_alg = group->alg==FWABF_SELECTION_RANDOM ? "random" : "priority";
  s = format (s, "order=%s labels=", s_alg);
  if (n_links > 1)
    {
      for (i32 i=0; i<n_links-1; i++)
        {
          s = format (s, "%d,", group->links[i]);
        }
    }
  s = format (s, "%d", group->links[n_links-1]);
  return s;
}

static u8*
format_action (u8 * s, va_list * args)
{
  fwabf_policy_action_t*     action   = va_arg (*args, fwabf_policy_action_t *);
  u32                        n_groups = vec_len(action->link_groups);
  char*                      s_alg;

  if (n_groups > 1)
    {
      s_alg = action->alg==FWABF_SELECTION_RANDOM ? "random" : "priority";
      s = format (s, " select_group: %s\n", s_alg);
    }
  for (u32 i=0; i<n_groups; i++)
    {
      s = format (s, " group %d: %U\n", i, format_link_group, &action->link_groups[i]);
    }
  return s;
}

static u8 *
format_abf (u8 * s, va_list * args)
{
  abf_policy_t *ap = va_arg (*args, abf_policy_t *);

  s = format (s, "abf:[%d]: policy:%d acl:%d\n%U",
	      ap - abf_policy_pool, ap->ap_id, ap->ap_acl, format_action, &ap->action);
  return s;
}

static clib_error_t *
abf_show_policy_cmd (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 policy_id;
  abf_policy_t *ap;

  policy_id = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &policy_id))
        ;
      else
	      break;
    }

  if (INDEX_INVALID == policy_id)
    {
      /* *INDENT-OFF* */
      pool_foreach(ap, abf_policy_pool,
      ({
        vlib_cli_output(vm, "%U", format_abf, ap);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      ap = fwabf_policy_find_i (policy_id);

      if (NULL != ap)
        vlib_cli_output (vm, "%U", format_abf, ap);
      else
        vlib_cli_output (vm, "Invalid policy ID:%d", policy_id);
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (abf_policy_show_policy_cmd_node, static) = {
  .path = "show fwabf policy",
  .function = abf_show_policy_cmd,
  .short_help = "show fwabf policy <value>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
abf_policy_init (vlib_main_t * vm)
{
  return (NULL);
}

VLIB_INIT_FUNCTION (abf_policy_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
