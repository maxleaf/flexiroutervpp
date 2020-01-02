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
  FLOW_IN2OUT_NEXT_DROP,
  FLOW_IN2OUT_NEXT_LOOKUP,
  FLOW_IN2OUT_N_NEXT,
} FLOW_in2out_next_t;

#if CLIB_DEBUG > 0
#define flow_debug clib_warning
#else
#define flow_debug(...) \
  do { } while (0)
#endif

#define foreach_flow_error \
 _(NONE, "no error") \
 _(PROTO_NOT_SUPPORTED, "protocol not supported")

typedef enum
{
#define _(sym,str) FLOW_ERROR_##sym,
  foreach_flow_error
#undef _
  FLOW_N_ERROR,
} flow_error_t;

typedef struct
{
  u32 next_index;
} flow_trace_t;

static uword
flow_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
             vlib_frame_t * frame, u8 is_ip4)
{
    u32 n_left_from, * from, next_index, * to_next, n_left_to_next;
    flowtable_main_t * fm = &flowtable_main;
    u32 cpu_index = os_get_thread_index();
    flowtable_main_per_cpu_t * fmt = &fm->per_cpu[cpu_index];

    from = vlib_frame_vector_args(frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    u32 current_time =
      (u32) ((u64) fm->vlib_main->cpu_time_last_node_dispatch /
             fm->vlib_main->clib_time.clocks_per_second);
    timer_wheel_index_update(fm, fmt, current_time);

    while (n_left_from > 0)
      {
        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        /* Dual loop */
        while (n_left_from >= 4 && n_left_to_next >= 2)
      {
        u32 bi0, bi1;
        vlib_buffer_t * b0, * b1;
        u32 next0 = FLOW_IN2OUT_NEXT_LOOKUP;
        u32 next1 = FLOW_IN2OUT_NEXT_LOOKUP;

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
            flow_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
            t->next_index = next0;
          }
        if (b1->flags & VLIB_BUFFER_IS_TRACED)
          {
            flow_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
            t->next_index = next1;
          }

        vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                        n_left_to_next, bi0, bi1, next0, next1);
      }

      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
      {
        u32 bi0;
        u32 next0 = FLOW_IN2OUT_NEXT_LOOKUP;
        vlib_buffer_t * b0;
        int created;
        uword is_reverse;
        flow_entry_t * flow;
        BVT(clib_bihash_kv) kv;

        bi0 = to_next[0] = from[0];
        b0 = vlib_get_buffer(vm, bi0);

        /* lookup/create flow */
        flow_mk_key(b0, is_ip4, &is_reverse, &kv);
        flow = flowtable_entry_lookup_create(fm, fmt, &kv, current_time, &created);
        if (PREDICT_FALSE(flow == NULL))
          {
            flow_debug("flow was not created/found\n");
          }

        /* timer management */
        if (flow_update_lifetime(flow, b0, is_ip4))
          {
            timer_wheel_resched_flow(fm, fmt, flow, current_time);
          }

        /* frame mgmt */
        from++;
        to_next++;
        n_left_from--;
        n_left_to_next--;

        if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
            flow_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
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
flow_ip4_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
    return flow_node_fn(vm, node, from_frame, /* is_ip4 */ 1);
}

static char *flow_error_strings[] =
  {
#define _(sym,string) string,
      foreach_flow_error
#undef _
    };

u8 *
format_flow_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

    flow_trace_t *t = va_arg (*args, flow_trace_t *);

    s = format (s, "FLOW: next index %d\n", t->next_index);

    return s;
}

VNET_FEATURE_INIT (flow_ip4_in2out_node_fn, static) =
  {
    .arc_name = "ip4-unicast",
    .node_name = "flow_ip4_in2out",
    .runs_before =  VNET_FEATURES("classify_ip4_in2out"),
  };

VLIB_REGISTER_NODE (flow_ip4_node) =
  {
    .function = flow_ip4_node_fn,
    .name = "flow_ip4_in2out",
    .vector_size = sizeof(u32),
    .format_trace = format_flow_trace,
    .n_errors = FLOW_N_ERROR,
    .error_strings = flow_error_strings,
    .n_next_nodes = FLOW_IN2OUT_N_NEXT,
    .next_nodes =
      {
          [FLOW_IN2OUT_NEXT_DROP] = "error-drop",
          [FLOW_IN2OUT_NEXT_LOOKUP] = "classify_ip4_in2out",
      },
  };
