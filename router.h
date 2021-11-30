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
 * router.h
 * 
 * Public structures, constants and declarations for WAYUU Router.
 */
#include <openssl/ssl.h>
#include <stdbool.h>
#ifndef __WAYUU_ROUTER_H
#define __WAYUU_ROUTER_H

#include "http_utils.h"

/**
 * MAX_ROUTES: The maximum amount of route definitions in the routing table. 
 */
#define MAX_ROUTES 128

#define MAX_ROUTE_PATH 256
#define MAX_PARAM_LENGTH 64

typedef struct route_matcher {
  int type; /**< Whether or not expects a parameter in the route. MATCHER_TYPE_CONSTANT or MATCHER_TYPE_PARAM (see file router.c) */
  char prefix[MAX_ROUTE_PATH]; /**< Complete path of the route. If the route has a parameter it is included*/
  char param[MAX_PARAM_LENGTH]; /**< The parameter name if the route is a parameter. */
} route_matcher;

/**
 * @brief: function that handles the request.
 * 
 * For more information see README.md
 */
typedef void (*request_handler)(api_request *req);

/**
 * @brief: filter to apply to the request. It returns true if successful and false otherwise. 
 * When filter returns false the router will assume that the request has completed and will not invoke handler. 
 * The filter must handle error responses. 
 * 
 * An optional mechanism that can be used to implement features such as enpoint authentication, 
 * security and logging functionality.
 * 
 * For more information see README.md
 */
typedef bool (*request_filter)(api_request *req);

/**
 * router_init: Initialises routing table. This method should be called once per instance.
 */
void router_init();

/**
 * router_handle_request: Main routing method, searches for request handler in routing table and if found
 * delegates request to it, otherwise it returns a default response. 
 * 
 */
void router_handle_request(api_request *request);

void router_add_route(char *matcher, request_handler handler, request_filter filter);

void reject_routing_request(api_request *req);

void free_routing_table();

void router_resolve_route(const char *template, route_matcher *matcher);

char *router_extract_param(const char *path, route_matcher *matcher);

#endif
