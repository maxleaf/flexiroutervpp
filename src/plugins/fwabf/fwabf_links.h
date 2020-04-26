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

#ifndef __FWABF_LINKS_H__
#define __FWABF_LINKS_H__

#include <vnet/fib/fib_path_list.h>


typedef u8 fwabf_label_t;	/*flexiwan path label used by policy to choose link*/

#define FWABF_INVALID_LABEL 0xFF
#define FWABF_MAX_LABEL     0xFE

// nnoww - document - check C-file
extern u32 fwabf_links_add_interface (
                        const u32 sw_if_index,
                        const fwabf_label_t fwlabel,
                        const fib_route_path_t* rpath);

// nnoww - document - check C-file
extern u32 fwabf_links_del_interface (const u32 sw_if_index);

// nnoww - document - check C-file
extern dpo_id_t fwabf_links_get_dpo (
                        fwabf_label_t         fwlabel,
                        dpo_proto_t           dpo_proto,
                        const load_balance_t* lb);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /*__FWABF_LINKS_H__*/
