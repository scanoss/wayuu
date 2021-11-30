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
  * @file router.c
  * @date 11 Jan 2021
  * @brief Implements a simple routing framework for the API.
  */

#define _GNU_SOURCE
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
 * @brief The routing table.
 */
typedef struct routing_table_t
{
  int n_routes;
  request_handler handlers[MAX_ROUTES]; /**< The handlers for the routes. See README.md for more information */
  request_filter filters[MAX_ROUTES]; /**< The filters for the routes. See README.md for more information */
  route_matcher *matchers[MAX_ROUTES]; /**< The matcher METHOD:PATH for the router. See README.md for more information */
} routing_table_t;

/**
 * @brief  The global routing table. 
 * This variable should stay private to the router and no other module should use it.
 * Hence it doesn't appear in router.h.
 */
routing_table_t routing_table;

/**
 * @brief Initialize the router. (Only reset the routing table)
 * This method should be called once per instance.
 */
void router_init()
{
  routing_table.n_routes = 0;
}

/**
 * @brief Separates the API template parameter from the path and stores them in the matcher struct.
 * Example: [in]  template = "/users/{id}"
 *          
 *          [out] matcher->param = "id"
 *                matcher->prefix = "/users/"
 * 
 *          matcher->type = MATCHER_TYPE_PARAM (This should be set manually, this method does not set it)
 *
 * 
 * @param template Path with parameter
 * @param matcher Output parameter.
 */
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

/**
 * @brief Extracts the parameter specified in the matcher from the path and returns it as a query string.
 * Example: /users/123456 -> id=123456 with matcher->param = "id"
 * 
 * @param path Match method:path
 * @param matcher 
 * @return char* A query string with the parameter.
 */
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


/**
 * @brief Adds a route to the global routing table.
 * 
 * @param template Route matcher sintax: "method:path"
 *  - method: The HTTP Method, for now only GET, POST, DELETE are supported.
 *  - path: The HTTP Request path, relative to the API mount point (/api). Example: /user/list.
 *    Path parameters are supported, as well as query parameters.
 *    Example: "GET:/user/{username}" or "GET:/user"
 * 
 * @param handler function that handles the request
 * @param filter filter to apply to the request. It returns true if successful and false otherwise
 */
void router_add_route(char *template, request_handler handler, request_filter filter)
{

  log_debug("ADD ROUTE - %s", template);
  route_matcher *matcher = calloc(1, sizeof(route_matcher));
  if (strchr(template, '{') != NULL)  // Automatically set the matcher type
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

/**
 * @brief Main routing method, searches for request handler in routing table and if found
 * delegates request to it, otherwise it returns a default response. 
 * 
 * @param request 
 */
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
        char *param;
        asprintf(&param, "&%s", qs);
        strcat(request->form, param);
        free(param);
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

/**
 * @brief Rejects the request with a 400 error response.
 * 
 * @param request Structure containing the client request.
 */
void reject_routing_request(api_request *request)
{
  log_debug("IP:%s Ignored API URL: %s", request->IP, request->url);
  bad_request(request);
}

/**
 * @brief Free the routing table.
 */
void free_routing_table()
{
  for (int i = 0; i < routing_table.n_routes; i++)
  {
    free(routing_table.matchers[i]);
  }
}
