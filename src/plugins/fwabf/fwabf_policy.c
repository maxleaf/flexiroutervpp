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


// nnoww - document

#include <plugins/fwabf/fwabf_policy.h>

#include <vlib/vlib.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/plugin/plugin.h>


// nnoww - TODO - clean all nnoww-s :)

// nnoww - TODO - add validation on delete policy that no attachment objects exist!

// nnoww - TODO - check VPP FIB for X.255 entries - if should support LAN Broadcast addresses - 192.168.1.255 - that requires refcounter (the 255.255.255.255 I already added)?

// nnoww - TODO - ensure that endianity of IP6 address stored in fwabf_locals matches that of packet in vlib_buffer

// nnoww - TEST - ???? - NAT & ABF coexistence:
//                  1. Modified by NAT packets go through FWABF
//                  2. NOT Modified by NAT packets go through FWABF
//                  3. Reassembled packets go through FWABF
//                  4. ICMP packet go FWABF ???
//

// nnoww - TEST - ???? -  flowhash algorithm
//                        i = FWABF_GET_INDEX_BY_FLOWHASH(
//                              flow_hash, ap->action.n_link_groups_pow2_mask,
//                              ap->action.n_link_groups_minus_1, i);

// nnoww - TEST - ???? - Incoming DHCP Server packets should be not shadled by policy!

/**
 * Pool of ABF objects
 */
static fwabf_policy_t *abf_policy_pool;

/**
  * DB of ABF policy objects
  *  - policy ID to index conversion.
  */
static fwabf_policy_t *abf_policy_db;

#define FWABF_GET_INDEX_BY_FLOWHASH(_flowhash, _vec_len_pow2_mask, _vec_len_minus_1, _res) \
      (((_res = (_flowhash & _vec_len_pow2_mask)) <= _vec_len_minus_1) ? _res : (_res & _vec_len_minus_1))

fwabf_policy_t *
fwabf_policy_get (u32 index)
{
  return (pool_elt_at_index (abf_policy_pool, index));
}

static fwabf_policy_t *
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
fwabf_policy_add (u32 policy_id, u32 acl_index, fwabf_policy_action_t * action)
{
  fwabf_policy_t*              ap;
  fwabf_policy_link_group_t* group;
  u32 api;

  api = fwabf_policy_find (policy_id);
  if (api != INDEX_INVALID)
  {
    clib_warning ("fawbf: fwabf_policy_add: policy-id %d exists (index %d)", policy_id, api);
    return VNET_API_ERROR_VALUE_EXIST;
  }

  pool_get (abf_policy_pool, ap);
  api = ap - abf_policy_pool;

  ap->ap_acl = acl_index;
  ap->ap_id  = policy_id;
  ap->action = *action;

  ap->action.n_link_groups_minus_1   = vec_len(action->link_groups) - 1;
  ap->action.n_link_groups_pow2_mask = (vec_len(action->link_groups) <= 0xF) ? 0xF : 0xFF; /* More than 255 groups is impractical*/
  vec_foreach (group, ap->action.link_groups)
    {
      group->n_links_minus_1   = vec_len(group->links) - 1;
      group->n_links_pow2_mask = (vec_len(group->links) <= 0xF) ? 0xF : 0xFF; /* Maximum number of labels is 255 */
    }

  /*
    * add this new policy to the DB
    */
  hash_set (abf_policy_db, policy_id, api);
  return 0;
}

int
fwabf_policy_delete (u32 policy_id)
{
  fwabf_policy_link_group_t* group;
  fwabf_policy_t *ap;
  u32 api;

  api = fwabf_policy_find (policy_id);
  if (INDEX_INVALID == api)
    return VNET_API_ERROR_INVALID_VALUE;

  ap = fwabf_policy_get (api);

  vec_foreach (group, ap->action.link_groups)
    {
      vec_free (group->links);
    }
  vec_free (ap->action.link_groups);

  hash_unset (abf_policy_db, policy_id);
  pool_put (abf_policy_pool, ap);
  return (0);
}

/**
 * Get DPO to use for packet forwarding according to policy.
 * The algorithm is as follows:
 *  1. Lookup FIB for adjacencies to be used for forwarding.
 *     Note this is done in the caller function - fwabf_input_ip4().
 *  2. Intersect found adjacencies with adjacencies that belong
 *     to the interfaces labeled with policy labels.
 *     The labeled interfaces are fetched out of fwabf_link database by labels
 *     in order of policy's label list. If policy specifies random selection,
 *     the interfaces are fetched based on flow hash.
 *     Note the flow hash is calculated on packet with default flow hash
 *     configuration - IP_FLOW_HASH_DEFAULT. It takes in account ip-s, ports-s,
 *     protocols and reverse combination.
 *  3. If no labeled interfaces that match FIB lookup adjacencies was found,
 *     the policy is ignored, the FIB lookup adjacency will be used.
 *     In that way we ensure no packet drops by intermediate vpp-s on path to
 *     destination due to simplified implementation of multi-link feature.
 *
 * Notes regarding the algorithm:
 * ------------------------------
 *  o It prefers Distance over Policy: labels that match shortest path are choosen
 *
 *  o As FIB lookup brings only shortest paths, the policy labels that match
 *    longest paths has no effect: they are simply not counted!
 *    This is known limitation.
 *
 *  o Flow hash optimization is possible: if flow hash on packet was calculated
 *    it can be stored in the buffer metadata and can be reused later by other
 *    nodes. This is what ip4-lookup node does. We decided not to do that
 *    optimization, as flow hashing has configuration parameters (e.g. use ports
 *    or not, use src IP or not, etc) that might be different in our case.
 *    So this optimization is considered to be dangerous.
 *
 *
 * Notes regarding implementation:
 * -------------------------------
 *  o Policy might have multiple group of labeled interfaces to choose from.
 *    If group selection is random, we tries randomly selected group only once.
 *    If the randomly selected group has no match to FIB lookup results,
 *    we switch to non-random group selection: iterare over groups and use
 *    the first with match. Optimization is possible here - continue random
 *    selection of groups that were not checked yet. Since this optimization
 *    complicates code a lot, it was decided not to deal with it now.
 *    Same thing regarding random selection of interfaces inside selected group.
 *
 *  o The group of links includes all policy interfaces, including not active
 *    ones that can't be use for forwarding right now (e.g. due to temporary
 *    tunnel down). As a result, the random selection might fall on not active
 *    interface, causing mismatch, so search will be switched to priority order.
 *    See item above. The 'randomality' will be lost.
 *    To avoid that we might implement optimization: keep two sets of links -
 *    full set and active set. The active set should be updated every time when
 *    any link goes down/up.
 *    It was decided not to deal with this optimization, as randomality is not
 *    really random, but it uses flow hash to pick link. That means the 'bad'
 *    case just maps 'bad' flowhash into the first available link in group
 *    instead of the 'bad' link. That causes the first link to take over load of
 *    the failed links. The active links are still able to provide load balance.
 *    We are OK with that for now (April 2020).
 *
 * @param index     index of fwabf_policy_t in pool.
 * @param b         the vlib buffer to be forwarded.
 * @param lb        the DPO of Load Balance type retrieved by FIB lookup.
 * @param dpo       result of the function: the DPO to be used for forwarding.
 *                  If return value is not 0, this parameter has no effect.
 * @return 1 if the policy DPO provided within 'dpo' parameter should be used for forwarding,
 *         0 otherwise which effectively means the FIB lookup result DPO should be used.
 */
inline u32 fwabf_policy_get_dpo_ip4 (
                                index_t                 index,
                                vlib_buffer_t*          b,
                                const load_balance_t*   lb,
                                dpo_id_t*               dpo)
{
  fwabf_policy_t*            ap = fwabf_policy_get (index);
  fwabf_policy_link_group_t* group;
  fwabf_label_t*             pfwlabel;
  fwabf_label_t              fwlabel;
  u32                        i;
  u32                        flow_hash = 0;
  ip4_header_t*              ip = vlib_buffer_get_current (b);

  /*
   * lb - is DPO of Load Balance type. It doesn't point to adjacency directly.
   * Instead it might point to one kinda "final" DPO or to multiple "mapped"
   * DPO-s. It points to final DPO if there is only single path to destination.
   * IN this case no load balancing is possible.
   * It points to array of mapped DPO-s, if ECMP (Equal Cost MultiPath)
   * forwarding paths are available. Mapped DPO-s are linked to the final DPO-s
   * by the load_balance_get_fwd_bucket() function.
   */

  /*
   * Policy might have multiple group of links. Take a care of random
   * selection between groups. If selection is not random, just iterate
   * over list of groups and use the first one that matches FIB lookup results.
   * If randomly selected group has no match, go to iterations as well.
   * Optimization is possible here, but it complicates code a lot,
   * so we decided not to implement it for now (April 2020).
   */
  if (ap->action.alg == FWABF_SELECTION_RANDOM  &&  vec_len(ap->action.link_groups) > 1)
    {
      flow_hash = ip4_compute_flow_hash (ip, IP_FLOW_HASH_DEFAULT);
      i = FWABF_GET_INDEX_BY_FLOWHASH(
                        flow_hash, ap->action.n_link_groups_pow2_mask,
                        ap->action.n_link_groups_minus_1, i);
      group = &ap->action.link_groups[i];

      /*
       * The randomly selected group might have multiple links/labels/interfaces.
       * Take a care of random selection of link within group in the same manner
       * as random selection of group: try selection one time only, if that brings
       * no match, go to iterations over list of links.
       */
      if (group->alg == FWABF_SELECTION_RANDOM  &&  vec_len(group->links) > 1)
        {
          i = FWABF_GET_INDEX_BY_FLOWHASH(
                flow_hash, group->n_links_pow2_mask, group->n_links_minus_1, i);
          fwlabel = group->links[i];
          *dpo    = fwabf_links_get_dpo (fwlabel, DPO_PROTO_IP4, lb);
          if (dpo_id_is_valid (dpo))
            return 1;
        }

      /*
       * No random selection - just iterate over list of labels and use the first
       * one with valid DPO. If no valid label was found, fallback into ordered
       * search over list of link groups and their labels.
       */
      vec_foreach (pfwlabel, group->links)
        {
          *dpo = fwabf_links_get_dpo (*pfwlabel, DPO_PROTO_IP4, lb);
          if (dpo_id_is_valid (dpo))
            return 1;
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
          fwlabel = group->links[flow_hash & group->n_links_minus_1];
          *dpo = fwabf_links_get_dpo (fwlabel, DPO_PROTO_IP4, lb);
          if (dpo_id_is_valid (dpo))
            return 1;
        }
      vec_foreach (pfwlabel, group->links)
        {
          *dpo = fwabf_links_get_dpo (*pfwlabel, DPO_PROTO_IP4, lb);
          if (dpo_id_is_valid (dpo))
            return 1;
        }
    }

  /*
   * At this point no active DPO was found.
   * If fallback is default route, just go and indicate the caller function
   * to use DPO found by FIB lookup.
   * If fallback is to drop packets, return DPO_DROP.
   */
  if (PREDICT_TRUE(ap->action.fallback==FWABF_FALLBACK_DEFAULT_ROUTE))
    {
      return 0;
    }
  dpo_copy(dpo, drop_dpo_get(DPO_PROTO_IP4));
  return 1;
}

/**
 * Get DPO to be used for packet forwarding according to policy.
 *
 * @param index     index of fwabf_policy_t in pool
 * @param b         the buffer to be forwarded
 * @param lb        the DPO of Load Balancing type retrieved by FIB lookup.
 * @param dpo       result of the function: the DPO to be used for forwarding.
 *                  If return value is not 0, this parameter has no effect.
 * @return 1 if the policy DPO provided within 'dpo' parameter should be used for forwarding,
 *         0 otherwise which effectively means the FIB lookup result DPO should be used.
 */
inline u32 fwabf_policy_get_dpo_ip6 (
                                index_t                 index,
                                vlib_buffer_t*          b,
                                const load_balance_t*   lb,
                                dpo_id_t*               dpo)
{
  fwabf_policy_t*              ap = fwabf_policy_get (index);
  fwabf_policy_link_group_t* group;
  fwabf_label_t*             pfwlabel;
  fwabf_label_t              fwlabel;
  u32                        i;
  u32                        flow_hash = 0;
  ip6_header_t*              ip = vlib_buffer_get_current (b);

  /*
   * lb - is DPO of Load Balance type. It doesn't point to adjacency directly.
   * Instead it might point to one final DPO or to multiple mapped DPO-s.
   * It points to final DPO if there is single path only to destination,
   * hence no load balancing is possible.
   * It points to array of mapped DPO-s, if ECMP (Equal Cost MultiPath)
   * forwarding paths are available. Mapped DPO-s are linked to the final DPO-s
   * by the load_balance_get_fwd_bucket() function.
   */

  /*
   * Policy might have multiple group of links. Take a care of random
   * selection between groups. If selection is not random, just iterate
   * over list of groups and use the first one that matches FIB lookup results.
   * If randomly selected group has no match, go to iterations as well.
   * Optimization is possible here, but it complicates code a lot,
   * so we decided not to implement it for now (April 2020).
   */
  if (ap->action.alg == FWABF_SELECTION_RANDOM  &&  vec_len(ap->action.link_groups) > 1)
    {
      flow_hash = ip6_compute_flow_hash (ip, IP_FLOW_HASH_DEFAULT);
      i = FWABF_GET_INDEX_BY_FLOWHASH(
                        flow_hash, ap->action.n_link_groups_pow2_mask,
                        ap->action.n_link_groups_minus_1, i);
      group = &ap->action.link_groups[i];

      /*
       * The randomly selected group might have multiple links/labels/interfaces.
       * Take a care of random selection of link within group in the same manner
       * as random selection of group: try selection one time only, if that brings
       * no match, go to iterations over list of links.
       */
      if (group->alg == FWABF_SELECTION_RANDOM  &&  vec_len(group->links) > 1)
        {
          i = FWABF_GET_INDEX_BY_FLOWHASH(
                flow_hash, group->n_links_pow2_mask, group->n_links_minus_1, i);
          fwlabel = group->links[i];
          *dpo    = fwabf_links_get_dpo (fwlabel, DPO_PROTO_IP6, lb);
          if (dpo_id_is_valid (dpo))
            return 1;
        }

      /*
       * No random selection - just iterate over list of labels and use the first
       * one with valid DPO. If no valid label was found, fallback into ordered
       * search over list of link groups and their labels.
       */
      vec_foreach (pfwlabel, group->links)
        {
          *dpo = fwabf_links_get_dpo (*pfwlabel, DPO_PROTO_IP6, lb);
          if (dpo_id_is_valid (dpo))
            return 1;
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
          fwlabel = group->links[flow_hash & group->n_links_minus_1];
          *dpo = fwabf_links_get_dpo (fwlabel, DPO_PROTO_IP6, lb);
          if (dpo_id_is_valid (dpo))
            return 1;
        }
      vec_foreach (pfwlabel, group->links)
        {
          *dpo = fwabf_links_get_dpo (*pfwlabel, DPO_PROTO_IP6, lb);
          if (dpo_id_is_valid (dpo))
            return 1;
        }
    }

  /*
   * At this point no active DPO was found.
   * If fallback is default route, just go and indicate the caller function
   * to use DPO found by FIB lookup.
   * If fallback is to drop packets, return DPO_DROP.
   */
  if (PREDICT_TRUE(ap->action.fallback==FWABF_FALLBACK_DEFAULT_ROUTE))
    {
      return 0;
    }
  dpo_copy(dpo, drop_dpo_get(DPO_PROTO_IP6));
  return 1;
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
      ret = fwabf_policy_add (policy_id, acl_index, &policy_action);
    }
  else
    {
      ret = fwabf_policy_delete (policy_id);
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
  fwabf_policy_t *ap = va_arg (*args, fwabf_policy_t *);

  s = format (s, "abf:[%d]: policy:%d acl:%d\n%U",
	      ap - abf_policy_pool, ap->ap_id, ap->ap_acl, format_action, &ap->action);
  return s;
}

static clib_error_t *
abf_show_policy_cmd (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 policy_id;
  fwabf_policy_t *ap;

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
