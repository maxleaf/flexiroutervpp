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

#include <dpi/dpi.h>
#include <dpi/flowtable.h>
#include <dpi/flowtable_tcp.h>

#include <vppinfra/dlist.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vnet/ip/ip4_packet.h>

typedef enum {
  CLASSIFY_IN2OUT_NEXT_DROP,
  CLASSIFY_IN2OUT_NEXT_LOOKUP,
  CLASSIFY_IN2OUT_N_NEXT,
} CLASSIFY_in2out_next_t;

#if CLIB_DEBUG > 0
#define classify_debug clib_warning
#else
#define classify_debug(...) \
  do { } while (0)
#endif

#define foreach_classify_error \
 _(NONE, "no error") \
 _(PROTO_NOT_SUPPORTED, "protocol not supported")

typedef enum
{
#define _(sym,str) CLASSIFY_ERROR_##sym,
  foreach_classify_error
#undef _
  CLASSIFY_N_ERROR,
} classify_error_t;

typedef struct
{
  u32 next_index;
} classify_trace_t;

static uword
classify_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
             vlib_frame_t * frame, u8 is_ip4)
{
    u32 n_left_from, * from, next_index, * to_next, n_left_to_next;
    dpi_main_t *sm = &dpi_main;
    u8 is_ip60 = 0;

    from = vlib_frame_vector_args(frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    while (n_left_from > 0)
      {
        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        /* Dual loop */
        while (n_left_from >= 4 && n_left_to_next >= 2)
      {
        u32 bi0, bi1;
        vlib_buffer_t * b0, * b1;
        u32 next0 = CLASSIFY_IN2OUT_NEXT_LOOKUP;
        u32 next1 = CLASSIFY_IN2OUT_NEXT_LOOKUP;

        /* prefetch next iteration */
        {
          vlib_buffer_t * p2, * p3;

          p2 = vlib_get_buffer(vm, from[2]);
          p3 = vlib_get_buffer(vm, from[3]);

          vlib_prefetch_buffer_header(p2, LOAD);
          vlib_prefetch_buffer_header(p3, LOAD);
        }

        bi0 = to_next[0] = from[0];
        bi1 = to_next[1] = from[1];
        b0 = vlib_get_buffer(vm, bi0);
        b1 = vlib_get_buffer(vm, bi1);

        /* frame mgmt */
        from += 2;
        to_next += 2;
        n_left_from -= 2;
        n_left_to_next -= 2;

        if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
            classify_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
            t->next_index = next0;
          }
        if (b1->flags & VLIB_BUFFER_IS_TRACED)
          {
            classify_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
            t->next_index = next1;
          }

        vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                        n_left_to_next, bi0, bi1, next0, next1);
      }

      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
      {
        u32 bi0;
        u32 next0 = CLASSIFY_IN2OUT_NEXT_LOOKUP;
        vlib_buffer_t * b0;
        fa_5tuple_opaque_t pkt_5tuple0;
        u8 action0 = 0;
        u32 acl_pos_p0, acl_match_p0;
        u32 rule_match_p0, trace_bitmap0;
        int res = 0;

        bi0 = to_next[0] = from[0];
        b0 = vlib_get_buffer(vm, bi0);

        acl_plugin_fill_5tuple_inline (sm->acl_plugin.p_acl_main,
                                       sm->acl_lc_id, b0,
                                       is_ip60,
                                       /* is_input */ 0,
                                       /* is_l2_path */ 1,
                                       &pkt_5tuple0);

        res = acl_plugin_match_5tuple_inline (sm->acl_plugin.p_acl_main,
                                              sm->acl_lc_id,
                                              &pkt_5tuple0, is_ip60,
                                              &action0, &acl_pos_p0,
                                              &acl_match_p0,
                                              &rule_match_p0,
                                              &trace_bitmap0);
        if (res > 0)
          {
            printf ("Rule matched! \n");
          }

        /* frame mgmt */
        from++;
        to_next++;
        n_left_from--;
        n_left_to_next--;

        if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
            classify_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
            t->next_index = next0;
          }

        vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                        n_left_to_next, bi0, next0);
      }
        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
      }

    return frame->n_vectors;
}

static uword
classify_ip4_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
    return classify_node_fn(vm, node, from_frame, /* is_ip4 */ 1);
}

static char *classify_error_strings[] =
  {
#define _(sym,string) string,
      foreach_classify_error
#undef _
    };

u8 *
format_classify_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

    classify_trace_t *t = va_arg (*args, classify_trace_t *);

    s = format (s, "FLOW: next index %d\n", t->next_index);

    return s;
}

VNET_FEATURE_INIT (classify_ip4_in2out_node_fn, static) =
  {
    .arc_name = "ip4-unicast",
    .node_name = "classify_ip4_in2out",
    .runs_before =  VNET_FEATURES("ip4-lookup"),
  };

VLIB_REGISTER_NODE (classify_ip4_node) =
  {
    .function = classify_ip4_node_fn,
    .name = "classify_ip4_in2out",
    .vector_size = sizeof(u32),
    .format_trace = format_classify_trace,
    .n_errors = CLASSIFY_N_ERROR,
    .error_strings = classify_error_strings,
    .n_next_nodes = CLASSIFY_IN2OUT_N_NEXT,
    .next_nodes =
      {
          [CLASSIFY_IN2OUT_NEXT_DROP] = "error-drop",
          [CLASSIFY_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
      },
  };
