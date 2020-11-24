// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2020 SCANOSS LTD
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * router.c
 * 
 * This file implements a simple routing framework for the API.
 * 
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#include "router.h"
/**
 *  Matcher types:
 *  They specify the type of algorithm followed by the route matcher.
 *  - constant match: Matchers a rute exactly.
 *  - Parametric matcher: Expects a parameter in the route. 
 */
#define MATCHER_TYPE_CONSTANT 1
#define MATCHER_TYPE_PARAM 2

/**
 * The router looks into the routing table.
 */
typedef struct routing_table_t
{
  int n_routes;
  request_handler handlers[MAX_ROUTES];
  request_filter filters[MAX_ROUTES];
  route_matcher *matchers[MAX_ROUTES];
} routing_table_t;

// The global routing table. This variable should stay private to the router and no other module should use it.
// Hence it doesn't appear in router.h.
routing_table_t routing_table;

void router_init()
{
  routing_table.n_routes = 0;
}

void router_resolve_route(const char *template, route_matcher *matcher)
{

  char *tmp = strdup(template);
  tmp[strlen(template) - 1] = 0;
  char *prefix = tmp;
  int index = 0;
  while (*tmp > 0 && *tmp != '{')
  {
    tmp++;
    index++;
  }

  strcpy(matcher->param, ++tmp);
  prefix[index++] = 0;
  strcpy(matcher->prefix, prefix);
  free(prefix);
}

char *router_extract_param(const char *path, route_matcher *matcher)
{
  log_debug("router_extract_param(path=%s,prefix=%s,param=%s)", path, matcher->prefix, matcher->param);
  char *tmp = strdup(path);
  int prefix_len = strlen(matcher->prefix);
  char *qs = calloc(1, strlen(tmp) + prefix_len + 10);
  sprintf(qs, "%s=%s", matcher->param, tmp + prefix_len);
  free(tmp);
  return qs;
}

void router_add_route(char *template, request_handler handler, request_filter filter)
{

  log_debug("ADD ROUTE - %s", template);
  route_matcher *matcher = calloc(1, sizeof(route_matcher));
  if (strchr(template, '{') != NULL)
  {
    matcher->type = MATCHER_TYPE_PARAM;
    router_resolve_route(template, matcher);
  }
  else
  {
    matcher->type = MATCHER_TYPE_CONSTANT;
    strcpy(matcher->prefix, template);
  }
  routing_table.handlers[routing_table.n_routes] = handler;
  routing_table.matchers[routing_table.n_routes] = matcher;
  routing_table.filters[routing_table.n_routes] = filter;
  routing_table.n_routes++;
}

void router_handle_request(api_request *request)
{
  log_debug("Router handle request %s:%s", request->method, request->path);

  request_handler handler = NULL;
  request_filter filter = NULL;

  char matcher[255];

  // Match method:path
  sprintf(matcher, "%s:%s", request->method, request->path);

  for (int i = 0; i < routing_table.n_routes; i++)
  {
    char *template = routing_table.matchers[i]->prefix;
    int type = routing_table.matchers[i]->type;
    if (type == MATCHER_TYPE_CONSTANT && strcmp(template, matcher) == 0)
    {
      handler = routing_table.handlers[i];
      filter = routing_table.filters[i];
      break;
    }
    else if (type == MATCHER_TYPE_PARAM && strstr(matcher, template) != NULL && strcmp(template, matcher) != 0)
    {
      char *qs = router_extract_param(matcher, routing_table.matchers[i]);
      if (strlen(request->form) == 0)
      {
        request->form = strdup(qs);
      }
      else
      {
        request->form += sprintf("&%s", qs);
      }
      free(qs);
      handler = routing_table.handlers[i];
      filter = routing_table.filters[i];
      break;
    }
  }
  if (handler == NULL)
  {
    // we did not find a handler for given request, return default response.

    log_debug("Unable to find matching route for method %s and path %s", request->method, request->path);

    reject_routing_request(request);
    return;
  }
  if (filter != NULL)
  {
    bool result = filter(request);
    if (!result)
    {
      return;
    }
  }
  handler(request);
}

void reject_routing_request(api_request *request)
{
  log_debug("IP:%s Ignored API URL: %s", request->IP, request->url);
  bad_request(request);
}

void free_routing_table()
{
  for (int i = 0; i < routing_table.n_routes; i++)
  {
    free(routing_table.matchers[i]);
  }
}
