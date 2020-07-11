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
#define MAX_ROUTES 50

/**
 * request_handler: function that handles the request.
 */
typedef void (*request_handler)(api_request *req);

/**
 * request_filter: filter to apply to the request. It returns true if successful and false otherwise. 
 * When filter returns false the router will assume that the request has completed and will not invoke handler. 
 * The filter must handle error responses. 
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

/**
 * router_add_route: Adds a route to the global routing table.
 * 
 * - Matcher syntax: METHOD:PATH 
 * - METHOD: The HTTP Method, for now only GET, POST, DELETE are supported
 * - PATH: The HTTP Request path, relative to the API mount point (/api). Example: /user/list
 * - Path parameters are not supported, only query parameters. 
 */
void router_add_route(char *matcher, request_handler handler, request_filter filter);

void reject_routing_request(api_request *req);

void free_routing_table();

#endif
