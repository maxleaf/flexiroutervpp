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

#define DPDK_NB_RX_DESC_DEFAULT   1024
#define DPDK_NB_TX_DESC_DEFAULT   1024
#define DPDK_MAX_LRO_SIZE_DEFAULT 65536
#define DPDK_NB_RX_DESC_VIRTIO    256
#define DPDK_NB_TX_DESC_VIRTIO    256

#define I40E_DEV_ID_SFP_XL710           0x1572
#define I40E_DEV_ID_QSFP_A              0x1583
#define I40E_DEV_ID_QSFP_B              0x1584
#define I40E_DEV_ID_QSFP_C              0x1585
#define I40E_DEV_ID_10G_BASE_T          0x1586
#define I40E_DEV_ID_VF                  0x154C

/* These args appear by themselves */
#define foreach_eal_double_hyphen_predicate_arg \
_(no-shconf)                                    \
_(no-hpet)                                      \
_(no-huge)                                      \
_(vmware-tsc-map)

#define foreach_eal_single_hyphen_mandatory_arg \
_(coremask, c)                                  \
_(nchannels, n)                                 \

#define foreach_eal_single_hyphen_arg           \
_(mem-alloc-request, m)                         \
_(force-ranks, r)

/* clang-format off */
/* These args are preceded by "--" and followed by a single string */
#define foreach_eal_double_hyphen_arg           \
_(huge-dir)                                     \
_(proc-type)                                    \
_(file-prefix)                                  \
_(vdev)                                         \
_(log-level)                                    \
_(iova-mode)                                    \
_(base-virtaddr)
/* clang-format on */

static inline void
dpdk_get_xstats (dpdk_device_t * xd)
{
  int len, ret;

  if (!(xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP))
    return;

  len = rte_eth_xstats_get (xd->port_id, NULL, 0);
  if (len < 0)
    return;

  vec_validate (xd->xstats, len - 1);

  ret = rte_eth_xstats_get (xd->port_id, xd->xstats, len);
  if (ret < 0 || ret > len)
    {
      _vec_len (xd->xstats) = 0;
      return;
    }

  _vec_len (xd->xstats) = len;
}

#define DPDK_UPDATE_COUNTER(vnm, tidx, xd, stat, cnt)                         \
  do                                                                          \
    {                                                                         \
      u64 _v = (xd)->stats.stat;                                              \
      u64 _lv = (xd)->last_stats.stat;                                        \
      if (PREDICT_FALSE (_v != _lv))                                          \
        {                                                                     \
          if (PREDICT_FALSE (_v < _lv))                                       \
            dpdk_log_warn ("%v: %s counter decreased (before %lu after %lu)", \
                           xd->name, #stat, _lv, _v);                         \
          else                                                                \
            vlib_increment_simple_counter (                                   \
                vec_elt_at_index ((vnm)->interface_main.sw_if_counters, cnt), \
                (tidx), (xd)->sw_if_index, _v - _lv);                         \
        }                                                                     \
    }                                                                         \
  while (0)

static inline void
dpdk_update_counters (dpdk_device_t * xd, f64 now)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 thread_index = vlib_get_thread_index ();

  /* only update counters for PMD interfaces */
  if ((xd->flags & DPDK_DEVICE_FLAG_PMD) == 0)
    return;

  xd->time_last_stats_update = now ? now : xd->time_last_stats_update;
  clib_memcpy_fast (&xd->last_stats, &xd->stats, sizeof (xd->last_stats));
  rte_eth_stats_get (xd->port_id, &xd->stats);

  /* maybe bump interface rx no buffer counter */
  DPDK_UPDATE_COUNTER (vnm, thread_index, xd, rx_nombuf,
		       VNET_INTERFACE_COUNTER_RX_NO_BUF);
  DPDK_UPDATE_COUNTER (vnm, thread_index, xd, imissed,
		       VNET_INTERFACE_COUNTER_RX_MISS);
  DPDK_UPDATE_COUNTER (vnm, thread_index, xd, ierrors,
		       VNET_INTERFACE_COUNTER_RX_ERROR);

  dpdk_get_xstats (xd);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
