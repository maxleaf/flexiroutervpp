/*
 *------------------------------------------------------------------
 * vat_helper_macros.h - collect api client helper macros in one place
 *
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
 *------------------------------------------------------------------
 */
#ifndef __vat_helper_macros_h__
#define __vat_helper_macros_h__

/* M: construct, but don't yet send a message */
#define M(T, mp)                                                \
do {                                                            \
    socket_client_main_t *scm = vam->socket_client_main;	\
    vam->result_ready = 0;                                      \
    if (scm && scm->socket_enable)                              \
      mp = vl_socket_client_msg_alloc (sizeof(*mp));		\
    else                                                        \
      mp = vl_msg_api_alloc_as_if_client(sizeof(*mp));          \
    clib_memset (mp, 0, sizeof (*mp));                          \
    mp->_vl_msg_id = ntohs (VL_API_##T+__plugin_msg_base);      \
    mp->client_index = vam->my_client_index;			\
} while(0);

/* MPING: construct a control-ping message, don't send it yet */
#define MPING(T, mp)                                            \
do {                                                            \
    socket_client_main_t *scm = vam->socket_client_main;	\
    vam->result_ready = 0;                                      \
    if (scm && scm->socket_enable)                              \
      mp = vl_socket_client_msg_alloc (sizeof(*mp));		\
    else                                                        \
      mp = vl_msg_api_alloc_as_if_client(sizeof(*mp));          \
    clib_memset (mp, 0, sizeof (*mp));                          \
    mp->_vl_msg_id = ntohs (VL_API_##T+__plugin_msg_base);      \
    mp->client_index = vam->my_client_index;                    \
    if (scm)							\
      scm->control_pings_outstanding++;				\
} while(0);

#define M2(T, mp, n)                                            \
do {                                                            \
    socket_client_main_t *scm = vam->socket_client_main;	\
    vam->result_ready = 0;                                      \
    if (scm && scm->socket_enable)                              \
      mp = vl_socket_client_msg_alloc (sizeof(*mp) + n);        \
    else                                                        \
      mp = vl_msg_api_alloc_as_if_client(sizeof(*mp) + n);      \
    clib_memset (mp, 0, sizeof (*mp));                          \
    mp->_vl_msg_id = ntohs (VL_API_##T+__plugin_msg_base);      \
    mp->client_index = vam->my_client_index;			\
} while(0);

#define PING(_tm, mp_ping)                                                    \
  do                                                                          \
    {                                                                         \
      socket_client_main_t *scm = vam->socket_client_main;                    \
      if (scm && scm->socket_enable)                                          \
	mp_ping = vl_socket_client_msg_alloc (sizeof (*mp_ping));             \
      else                                                                    \
	mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));          \
      mp_ping->_vl_msg_id = htons (VL_API_CONTROL_PING + 1);                  \
      mp_ping->client_index = vam->my_client_index;                           \
      vam->result_ready = 0;                                                  \
      if (scm)                                                                \
	scm->control_pings_outstanding++;                                     \
    }                                                                         \
  while (0);

/* S: send a message */
#define S(mp)                                                   \
do {                                                            \
  socket_client_main_t *scm = vam->socket_client_main;         	\
  if (scm && scm->socket_enable)                                \
    vl_socket_client_write ();					\
  else                                                          \
    vl_msg_api_send_shmem (vam->vl_input_queue, (u8 *)&mp);     \
 } while (0);

/* W: wait for results, with timeout */
#define W(ret)                                                  \
do {                                                            \
    f64 timeout = vat_time_now (vam) + 1.0;                     \
    socket_client_main_t *scm = vam->socket_client_main;	\
    ret = -99;                                                  \
                                                                \
    if (scm && scm->socket_enable)                              \
      vl_socket_client_read (5);                       		\
    while (vat_time_now (vam) < timeout) {                      \
        if (vam->result_ready == 1) {                           \
            ret = vam->retval;                                  \
            break;                                              \
        }                                                       \
        vat_suspend (vam->vlib_main, 1e-5);                     \
    }								\
} while(0);

/* W2: wait for results, with timeout */                        \
#define W2(ret, body)                                           \
do {                                                            \
    f64 timeout = vat_time_now (vam) + 1.0;                     \
    socket_client_main_t *scm = vam->socket_client_main;	\
    ret = -99;                                                  \
                                                                \
    if (scm && scm->socket_enable)                              \
      vl_socket_client_read (5);                       		\
    while (vat_time_now (vam) < timeout) {                      \
        if (vam->result_ready == 1) {                           \
	  (body);                                               \
	  ret = vam->retval;                                    \
          break;                                                \
        }                                                       \
        vat_suspend (vam->vlib_main, 1e-5);                     \
    }								\
} while(0);

#define VAT_PLUGIN_REGISTER(plug)                               \
clib_error_t * vat_plugin_register (vat_main_t *vam)            \
{                                                               \
  plug##_test_main_t * mp = &plug##_test_main;                  \
  u8 * name;                                                    \
                                                                \
  mp->vat_main = vam;                                           \
                                                                \
  /* Ask the vpp engine for the first assigned message-id */    \
  name = format (0, #plug "_%08x%c", api_version, 0);           \
  mp->msg_id_base =                                             \
      vl_client_get_first_plugin_msg_id ((char *) name);        \
  vec_free(name);                                               \
                                                                \
  if (mp->msg_id_base != (u16) ~0)                              \
    plug##_api_hookup (vam);                                    \
  else                                                          \
    return clib_error_return (0, #plug " plugin not loaded...");\
  return 0;                                                     \
}


#endif /* __vat_helper_macros_h__ */
