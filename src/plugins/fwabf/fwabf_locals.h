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

/*
 * This file implements storage of local addresses.
 * The addresses are needed to filter out locally designated traffic,
 * before the flexiwan multi-link policies might forward it to egress interfaces.
 */

#ifndef __FWABF_LOCALS_H__
#define __FWABF_LOCALS_H__

#include <vnet/ip/ip.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_16_8.h>


static clib_bihash_8_8_t  fwabf_locals_ip4;
static clib_bihash_16_8_t fwabf_locals_ip6;

static inline int fwabf_locals_ip4_exists (const ip4_address_t * ip4)
{
  clib_bihash_kv_8_8_t kv = { ip4->as_u32, 0 };
  return !(clib_bihash_search_8_8 (&fwabf_locals_ip4, &kv, &kv));
}

static inline int fwabf_locals_ip6_exists (const ip6_address_t * ip6)
{
  clib_bihash_kv_16_8_t kv;
  kv.key[0] = ip6->as_u64[0];
  kv.key[1] = ip6->as_u64[1];
  return !(clib_bihash_search_16_8 (&fwabf_locals_ip6, &kv, &kv));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /*__FWABF_LOCALS_H__*/
