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
 * The router looks into the routing table.
 */
typedef struct routing_table_t
{
  int n_routes;
  request_handler handlers[MAX_ROUTES];
  request_filter filters[MAX_ROUTES];
  char *matchers[MAX_ROUTES];
} routing_table_t;

// The global routing table. This variable should stay private to the router and no other module should use it.
// Hence it doesn't appear in router.h.
routing_table_t routing_table;

void router_init()
{
  routing_table.n_routes = 0;
}

void router_add_route(char *matcher, request_handler handler, request_filter filter)
{

  log_debug("ADD ROUTE - %s", matcher);

  routing_table.handlers[routing_table.n_routes] = handler;
  routing_table.matchers[routing_table.n_routes] = strdup(matcher);
  routing_table.filters[routing_table.n_routes] = filter;
  routing_table.n_routes++;
}

void router_handle_request(api_request *request)
{
  log_debug("Router handle request %s:%s", request->method, request->path);
  
  request_handler handler = NULL;
  request_filter filter = NULL;

  char route_matcher[255];

  // Match method:path
  sprintf(route_matcher, "%s:%s", request->method, request->path);

  for (int i = 0; i < routing_table.n_routes; i++)
  {

    if (strcmp(routing_table.matchers[i], route_matcher) == 0)
    {
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
