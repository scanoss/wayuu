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
#include <arpa/inet.h>
#include <stdio.h>
#include "snow.h"

#include "../http_utils.h"
#include "../router.h"
#include "test_mocks.h"

void mock_request_handler(api_request *req)
{
  char *buf = calloc(1024, sizeof(char));
  sprintf(buf, "REQUEST USER: %s", req->username);
  send(0, buf, 0, 0);
  free(buf);
}

bool true_filter(api_request *req)
{
  return true;
}

bool false_filter(api_request *req)
{
  bad_request(req);
  return false;
}

describe(router)
{
  subdesc(router_handle_request)
  {

    it("should handle API URIs")
    {
      init_mock_socket_buffer();
      router_init();
      router_add_route("GET:/user", mock_request_handler, NULL);
      api_request *req = malloc(sizeof(api_request));
      req->username = "test-user-154";
      req->IP = "127.0.0.1";
      req->method = "GET";
      req->path = "/user";
      req->n_headers = 0;
      router_handle_request(req);
      char *data_sent = get_sent_data();
      asserteq("REQUEST USER: test-user-154", data_sent);
      free_routing_table();
      free(data_sent);
      free(req);
    }

    it("should handle API URIs with filter")
    {
      init_mock_socket_buffer();
      router_init();
      router_add_route("GET:/user", mock_request_handler, true_filter);
      api_request *req = malloc(sizeof(api_request));
      req->username = "test-user-154";
      req->IP = "127.0.0.1";
      req->method = "GET";
      req->path = "/user";
      req->n_headers = 0;
      router_handle_request(req);
      char *data_sent = get_sent_data();
      asserteq("REQUEST USER: test-user-154", data_sent);
      free_routing_table();
      free(data_sent);
      free(req);
    }

    it("should handle API URIs with false filter")
    {
      init_mock_socket_buffer();
      router_init();
      router_add_route("GET:/user", mock_request_handler, false_filter);
      api_request *req = malloc(sizeof(api_request));
      req->username = "test-user-154";
      req->IP = "127.0.0.1";
      req->method = "GET";
      req->path = "/user";
      req->n_headers = 0;
      router_handle_request(req);
      char *data_sent = get_sent_data();
      char expected[1024];
      sprintf(expected, "%s%s%s%s", HTTP_BAD_REQUEST_START, WAYUU_HTTP_SERVER_STRING, HTTP_CONTENT_LENGTH_ZERO, CRLF);
      asserteq(data_sent, expected);
      free_routing_table();
      free(data_sent);
      free(req);
    }
  }
}