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

#include <dpi/util.h>
#include <dpi/dpi.h>

int dpi_enable_disable (u32 sw_if_index, int enable_disable)
{
  dpi_main_t *sm = &dpi_main;
  vnet_sw_interface_t * sw = NULL;
  int rv = 0;
  vnet_main_t * vnm = vnet_get_main();

  /* Utterly wrong? */
  if (pool_is_free_index (vnm->interface_main.sw_interfaces,
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (vnm, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("ip4-unicast", "classify_ip4_in2out",
                               sw_if_index, enable_disable, 0, 0);

  vnet_feature_enable_disable ("ip4-unicast", "flow_ip4_in2out",
                               sw_if_index, enable_disable, 0, 0);

  sm->acl_user_id = sm->acl_plugin.register_user_module ("DPI", "label1", "label2");

  sm->acl_lc_id = sm->acl_plugin.get_lookup_context_index (sm->acl_user_id, 1, 2);
  if (sm->acl_lc_id < 0)
    return sm->acl_lc_id;

  return rv;
}

int
vnet_dpi_app_add_del(u8 * name, u8 add)
{
    dpi_main_t *sm = &dpi_main;
    dpi_app_t *app = NULL;
    uword *p = NULL;

    p = hash_get_mem (sm->dpi_app_by_name, name);

    if (add)
      {
        if (p)
      return VNET_API_ERROR_VALUE_EXIST;

        pool_get (sm->dpi_apps, app);
        memset(app, 0, sizeof(*app));

        app->name = vec_dup(name);
        app->acl_id = ~0;
        app->rules_by_id = hash_create_mem (0, sizeof (u32), sizeof (uword));

        hash_set_mem (sm->dpi_app_by_name, app->name, app - sm->dpi_apps);
      }
    else
      {
        if (!p)
      return VNET_API_ERROR_NO_SUCH_ENTRY;

        hash_unset_mem (sm->dpi_app_by_name, name);
        app = pool_elt_at_index (sm->dpi_apps, p[0]);

        vec_free (app->name);
        hash_free(app->rules_by_id);
        pool_free(app->rules);
        pool_put (sm->dpi_apps, app);
      }

    return 0;
}

int
vnet_dpi_rule_add_del(u8 * app_name, u32 rule_index, u8 add)
{
  dpi_main_t *sm = &dpi_main;
  uword *p = NULL;
  dpi_app_t *app = NULL;
  dpi_rule_t *rule = NULL;

  p = hash_get_mem (sm->dpi_app_by_name, app_name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  app = pool_elt_at_index (sm->dpi_apps, p[0]);
  p = hash_get_mem (app->rules_by_id, &rule_index);

  if (add)
    {
      if (p)
        return VNET_API_ERROR_VALUE_EXIST;

      pool_get (app->rules, rule);
      memset(rule, 0, sizeof(*rule));
      rule->id = rule_index;

      hash_set_mem (app->rules_by_id, &rule_index, rule - app->rules);
    }
  else
    {
      if (!p)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      rule = pool_elt_at_index (app->rules, p[0]);
      hash_unset_mem (app->rules_by_id, &rule_index);
      pool_put (app->rules, rule);
    }

  return 0;
}

int
vnet_dpi_acl_add_del(u8 * app_name, u32 acl_index, u8 add)
{
  dpi_main_t *sm = &dpi_main;
  uword *p = NULL;
  dpi_app_t *app = NULL;

  p = hash_get_mem (sm->dpi_app_by_name, app_name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  app = pool_elt_at_index (sm->dpi_apps, p[0]);

  if (add)
    {
      app->acl_id = acl_index;

      vec_add1 (sm->acl_vec, app->acl_id);
      sm->acl_plugin.set_acl_vec_for_context (sm->acl_lc_id, sm->acl_vec);
    }
  else
    {
      if (!p)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      app->acl_id = ~0;

      //TBD: Implement ACL id removal from ACL plugin context
    }

  return 0;
}
