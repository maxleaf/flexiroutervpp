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
#include <dpi/flowtable.h>
#include <dpi/flowtable_tcp.h>

static void
foreach_upf_flows (BVT (clib_bihash_kv) * kvp, void * arg)
{
  flow_entry_t *flow = NULL;
  flowtable_main_t * fm = &flowtable_main;
  u8 *app_name = NULL;
  vlib_main_t *vm = vlib_get_main ();
  dpi_main_t * sm = &dpi_main;

  flow = pool_elt_at_index(fm->flows, kvp->value);
  if (flow->application_id != ~0)
    {
      dpi_app_t *app = pool_elt_at_index (sm->dpi_apps, flow->application_id);
      app_name = format (0, "%v", app->name);
    }
  else
    app_name = format (0, "%s", "None");

  vlib_cli_output (vm, "%U, UL pkt %u, DL pkt %u, "
                       "Src Intf %u, "
                       "app %v, lifetime %u",
                   format_flow_key, &flow->key,
                   flow->stats[0].pkts,
      flow->stats[1].pkts,
      flow->src_intf,
      app_name,
      flow->lifetime);

  vec_free(app_name);
}

static clib_error_t *
dpi_show_flows_command_fn (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  flowtable_main_t * fm = &flowtable_main;
  flowtable_main_per_cpu_t * fmt = &fm->per_cpu[0];

  BV (clib_bihash_foreach_key_value_pair) (&fmt->flows_ht, foreach_upf_flows, vm);

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_flows_command, static) =
{
  .path = "show flows",
  .short_help = "show flows",
  .function = dpi_show_flows_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpi_enable_disable_command_fn (vlib_main_t * vm,
                               unformat_input_t * input,
                               vlib_cli_command_t * cmd)
{
  u32 sw_if_index = ~0;
  int enable_disable = 1;
  int rv = 0;
  vnet_main_t * vnm = vnet_get_main();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
        enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
                         vnm, &sw_if_index))
        ;
      else
        break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = dpi_enable_disable (sw_if_index, enable_disable);

  switch(rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
          (0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0, "Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "dpi_enable_disable returned %d",
                                rv);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_enable_disable_command, static) =
{
  .path = "apps enable-disable",
  .short_help =
  "apps enable-disable <interface-name> [disable]",
  .function = dpi_enable_disable_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpi_create_app_command_fn (vlib_main_t * vm,
               unformat_input_t * input,
               vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = NULL;
  clib_error_t *error = NULL;
  int rv = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%_%v%_", &name))
    break;
      else
    {
      error = unformat_parse_error (line_input);
      goto done;
    }
    }

  rv = vnet_dpi_app_add_del(name, 1);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "application already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application does not exist...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_create_app_command, static) =
{
  .path = "create application",
  .short_help = "create application <name>",
  .function = dpi_create_app_command_fn,
};
/* *INDENT-ON* */

static void
dpi_show_rules(vlib_main_t * vm, dpi_app_t * app)
{
  u32 index = 0;
  u32 rule_index = 0;
  dpi_rule_t *rule = NULL;

  /* *INDENT-OFF* */
  hash_foreach(rule_index, index, app->rules_by_id,
  ({
     rule = pool_elt_at_index(app->rules, index);
     if (rule->end_port)
     {
       vlib_cli_output (vm, "rule: %u, ip range: %U/%d, ports: %d to %d",
                        rule->id,
                        format_ip46_address, &rule->server_ip, IP46_TYPE_ANY,
                        rule->ip_prefix, rule->start_port, rule->end_port);
     }
     else
     {
       vlib_cli_output (vm, "rule: %u, ip range: %U/%d, port: %d",
                        rule->id,
                        format_ip46_address, &rule->server_ip, IP46_TYPE_ANY,
                        rule->ip_prefix, rule->start_port);
     }
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
dpi_show_apps_command_fn (vlib_main_t * vm,
              unformat_input_t * input,
              vlib_cli_command_t * cmd)
{
  dpi_main_t * sm = &dpi_main;
  u8 *name = NULL;
  u32 index = 0;
  int verbose = 0;
  clib_error_t *error = NULL;
  unformat_input_t _line_input, *line_input = &_line_input;

  /* Get a line of input. */
  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "verbose"))
            {
              verbose = 1;
              break;
            }
          else
            {
              error = clib_error_return (0, "unknown input `%U'",
                                         format_unformat_error, input);
              unformat_free (line_input);
              return error;
            }
        }

      unformat_free (line_input);
    }

  /* *INDENT-OFF* */
  hash_foreach(name, index, sm->dpi_app_by_name,
  ({
     dpi_app_t *app = NULL;
     app = pool_elt_at_index(sm->dpi_apps, index);
     vlib_cli_output (vm, "%v", app->name);
     vlib_cli_output (vm, "ACL %u", app->acl_id);

     if (verbose)
       {
         dpi_show_rules(vm, app);
       }
  }));
  /* *INDENT-ON* */

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpi_show_apps_command, static) =
{
  .path = "show applications",
  .short_help = "show applications [verbose]",
  .function = dpi_show_apps_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpi_application_acl_rule_add_del_command_fn (vlib_main_t * vm,
                                             unformat_input_t * input,
                                             vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *app_name = NULL;
  u32 rule_index = ~0;
  u32 acl_index = ~0;
  clib_error_t *error = NULL;
  int rv = 0;
  int add = 1;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      rv = unformat (line_input, "%_%v%_ rule %u", &app_name, &rule_index);
      if (!rv)
        rv = unformat (line_input, "%_%v%_ acl %u", &app_name, &acl_index);
      if (!rv)
        {
          error = clib_error_return (0, "unknown input `%U'",
                                     format_unformat_error, input);
          goto done;
        }

      if (unformat (line_input, "del"))
          add = 0;
      else if (unformat (line_input, "add"))
          add = 1;
      else
        {
          error = clib_error_return (0, "unknown input `%U'",
                                     format_unformat_error, input);
          goto done;
        }
    }

  if (rule_index != ~0)
    {
      rv = vnet_dpi_rule_add_del(app_name, rule_index, add);
    }
  else if (acl_index != ~0)
    {
      rv = vnet_dpi_acl_add_del(app_name, acl_index, add);
    }
  else
    {
      error = clib_error_return (0, "unknown input `%U'",
                                 format_unformat_error, input);
      goto done;
    }

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "rule already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "application or rule does not exist...");
      break;

    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "application is in use...");
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

done:
  vec_free (app_name);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_application_rule_add_del_command, static) =
{
  .path = "application",
  .short_help = "application <name> (acl|rule) <id> (add | del)",
  .function = dpi_application_acl_rule_add_del_command_fn,
};
/* *INDENT-ON* */
