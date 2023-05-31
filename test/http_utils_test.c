// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2023 SCANOSS LTD
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
#include <stdio.h>
#include <stdlib.h>
#include "snow.h"
#include "../ws.h"
#include "../http_utils.h"
#include "test_mocks.h"
#include "log.h"

api_request *new_test_api_request(int socket, char *IP, char *url)
{
  api_request *req = malloc(sizeof(api_request));
  req->IP = IP;
  req->socket = socket;
  req->url = url;
  req->n_headers = 0;
  return req;
}

describe(http_utils)
{
  subdesc(send_http_status)
  {
    it("should send 404")
    {
      init_mock_socket_buffer();
      api_request *req = new_test_api_request(0, "0.0.0.0", "");
      send_http_status(req, 404, "Error message");
      char *data_sent = get_sent_data();
      char *expected_str = malloc(256);
      sprintf(expected_str, "%s%sContent-Length: 15\r\n\r\nError message\r\n", HTTP_NOT_FOUND_START, WAYUU_HTTP_SERVER_STRING);
      asserteq(data_sent, expected_str);
      free(expected_str);
      free(data_sent);
      free(req);
    }

    it("should ignore non status")
    {
      init_mock_socket_buffer();
      api_request *req = new_test_api_request(0, "0.0.0.0", "");
      send_http_status(req, 888, "Error message");
      char *data_sent = get_sent_data();
      asserteq(data_sent, "");
      free(data_sent);
      free(req);
    }
  }

  subdesc(not_authenticated)
  {
    it("should return HTTP 401")
    {
      init_mock_socket_buffer();
      api_request *req = new_test_api_request(0, "0.0.0.0", "");
      not_authenticated(req);
      char *data_sent = get_sent_data();
      char *expected_str = malloc(256);
      sprintf(expected_str, "%s%s%s\r\n", HTTP_UNAUTHORIZED_START, WAYUU_HTTP_SERVER_STRING, HTTP_CONTENT_LENGTH_ZERO);
      asserteq(data_sent, expected_str);
      free(expected_str);
      free(data_sent);
      free(req);
    }
  }

  subdesc(not_found)
  {
    it("should return HTTP 404")
    {
      init_mock_socket_buffer();
      api_request *req = new_test_api_request(0, "0.0.0.0", "");
      not_found(req);
      free(req);
      char *data_sent = get_sent_data();
      char *expected_str = malloc(256);
      sprintf(expected_str, "%s%s%s\r\n", HTTP_NOT_FOUND_START, WAYUU_HTTP_SERVER_STRING, HTTP_CONTENT_LENGTH_ZERO);
      asserteq(data_sent, expected_str);
      free(data_sent);
      free(expected_str);
    }
  }

  subdesc(get_path_and_query_string)
  {
    it("should return query string for GET request")
    {
      char *url = "/user/list?filter=john&sort=desc";
      path_and_query_t *result = get_path_and_query_string(url);
      asserteq(result->path, "/user/list");
      asserteq(result->query, "filter=john&sort=desc");
      free_path_and_query_t(result);
    }

    it("should return query string for GET request 2")
    {
      char *url = "/api/scan/file?code=sunzip_test_2&project_id=1111111&path=sunzip.c";
      path_and_query_t *result = get_path_and_query_string(url);
      asserteq(result->path, "/api/scan/file");
      asserteq(result->query, "code=sunzip_test_2&project_id=1111111&path=sunzip.c");
      free_path_and_query_t(result);
    }

    it("should return query string for GET request 3")
    {
      char *url = "/api/scan/file?code=snow_2.3.1&project_id=3285416309&path=snow-2.3.1/README.md";
      path_and_query_t *result = get_path_and_query_string(url);
      asserteq(result->path, "/api/scan/file");
      asserteq(result->query, "code=snow_2.3.1&project_id=3285416309&path=snow-2.3.1/README.md");
      free_path_and_query_t(result);
    }

    it("should return empty string if there is no query string")
    {
      char *url = "/user/list";
      path_and_query_t *result = get_path_and_query_string(url);
      asserteq(result->path, "/user/list");
      asserteq(result->query, "");
      free_path_and_query_t(result);
    }

    it("should remove /api prefix")
    {
      char *url = "/api/user/list";
      path_and_query_t *result = get_path_and_query_string(url);
      asserteq(result->path + strlen(API_MOUNT), "/user/list");
      free_path_and_query_t(result);

      char *url2 = "/api";
      path_and_query_t *result2 = get_path_and_query_string(url2);
      asserteq(result2->path + strlen(API_MOUNT), "");
      free_path_and_query_t(result2);
    }
  }

  subdesc(return_json)
  {
    it("should return a well formed response")
    {
      init_mock_socket_buffer();
      char *body = "{\"session\":\"1234\"}";
      api_request *req = new_test_api_request(0, "0.0.0.0", "");
      return_json(req, body);
      char *data_sent = get_sent_data();
      char *expected_str = malloc(2048);
      sprintf(expected_str, "%s%s%s%s%s\r\n%s\r\n", HTTP_OK_START, WAYUU_HTTP_SERVER_STRING, HTTP_ACCESS_CONTROL,CONTENT_TYPE_JSON, "Content-Length: 20\r\n", body);
      asserteq(data_sent, expected_str);
      free(expected_str);
      free(data_sent);
      free(req);
    }
  }

  subdesc(bad_request_with_error)
  {
    it("should return a bad request with error")
    {
      init_mock_socket_buffer();
      wayuu_error_t *error = calloc(1, sizeof(wayuu_error_t));
      strcpy(error->code, "TEST_CODE");
      strcpy(error->message, "This is a test message");
      api_request *req = new_test_api_request(0, "0.0.0.0", "");
      bad_request_with_error(req, error);
      char *data_sent = get_sent_data();
      char *expected_str = malloc(1024);
      char *error_json = "{\"code\":\"TEST_CODE\",\"message\":\"This is a test message\"}";
      char content_length[128];
      sprintf(content_length, "Content-Length: %lu\r\n", strlen(error_json) + 2);
      sprintf(expected_str, "%s%s%s%s%s\r\n%s\r\n", HTTP_BAD_REQUEST_START, WAYUU_HTTP_SERVER_STRING, HTTP_ACCESS_CONTROL,CONTENT_TYPE_JSON, content_length, error_json);
      asserteq(data_sent, expected_str);
      free(error);
      free(data_sent);
      free(expected_str);
      free(req);
    }
  }
}
