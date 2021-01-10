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
 * http_util.h
 * 
 * Public structures, constants and declarations for HTTP utilities.  
 */

#ifndef __WAYUU_HTTP_UTIL_H
#define __WAYUU_HTTP_UTIL_H

#include <openssl/ssl.h>
#include <stdbool.h>
#include "json_utils.h"

// HTTP protocol start strings

#define CRLF "\r\n"
#define HTTP_VERSION "HTTP/1.1"
#define WAYUU_WS_VERSION "1.4"
#define WAYUU_HTTP_SERVER_STRING "Server: WAYUU/" WAYUU_WS_VERSION CRLF
// HTTP STATUS STRINGS. 
#define HTTP_OK_START HTTP_VERSION " 200 OK\r\n"
#define HTTP_CREATED_START HTTP_VERSION " 201 CREATED\r\n"
#define HTTP_BAD_REQUEST_START HTTP_VERSION " 400 Bad Request\r\n"
#define HTTP_FORBIDDEN_START HTTP_VERSION " 403 Forbidden\r\n"
#define HTTP_UNAUTHORIZED_START HTTP_VERSION " 401 UNAUTHORIZED\r\n"
#define HTTP_NOT_FOUND_START HTTP_VERSION " 404 NOT FOUND\r\n"
#define HTTP_TOO_MANY_CONNECTIONS HTTP_VERSION " 429 Too many connections\r\n"
#define HTTP_CONTENT_LENGTH_ZERO "Content-Length: 0\r\n"

#define HTTP_INTERNAL_ERROR_START HTTP_VERSION " 500 Internal Server Error\r\n"

#define CONTENT_TYPE_JSON "Content-Type: application/json\r\n"
#define CONTENT_TYPE_TEXT_HTML "Content-Type: text/html\r\n"
#define CONTENT_TYPE_IMAGE_PNG "Content-Type: image/png\r\n"
#define CONTENT_TYPE_IMAGE_JPEG "Content-Type: image/jpeg\r\n"
#define CONTENT_TYPE_ZIP "Content-Type: application/zip\r\n"
#define CONTENT_TYPE_CSS "Content-Type: text/css\r\n"
#define CONTENT_TYPE_SVG "Content-Type: image/svg+xml\r\n"
#define CONTENT_TYPE_ICON "Content-Type: image/vnd.microsoft.icon\r\n"
#define CONTENT_TYPE_TEXT_PLAIN "Content-Type: text/plain\r\n"
#define CONTENT_TYPE_TEXT_CSV "Content-Type: text/csv\r\n"
#define CONTENT_TYPE_YAML "Content-Type: text/yaml\r\n"
#define CONTENT_TYPE_OCTET_STREAM "Content-Type: application/octet-stream\r\n"

#define HTTP_MAX_ERROR_CODE_LEN 64
#define HTTP_MAX_ERROR_MSG_LEN 1024

#define HTTP_MAX_HEADER_NAME 64
#define HTTP_MAX_HEADER_VALUE 256
#define HTTP_MAX_HEADERS 20 // Maximum number of HTTP Headers handled by WAYUU

#define HTTP_MAX_PATH 512 // Max path length in URI
#define HTTP_MAX_IP 16 // Max length of an IP address

/**
 * WAYUU_SSL_ON is a global that defines whether WAYUU is in SSL mode (HTTPS) or plain HTTP.
 * By default SSL mode is enabled
 */
extern bool WAYUU_SSL_ON;

/**
 * @openapi-schema 
 * name: Error
 * properties:
 *   code: string
 *   message: string
 */
typedef struct error_t
{
  char code[HTTP_MAX_ERROR_CODE_LEN];
  char message[HTTP_MAX_ERROR_MSG_LEN];
} error_t;

typedef struct
{
  char name[HTTP_MAX_HEADER_NAME];
  char value[HTTP_MAX_HEADER_VALUE];
} header_t;

/**
 *  api_request: encapsulates all that's needed to handle a particular request
 */
typedef struct api_request
{
  SSL *ssl;
  int socket;
  int n_headers;                      // Number of HTTP Headers
  header_t headers[HTTP_MAX_HEADERS]; // The HTTP Headers
  char *content_type;                 // The HTTP Content-Type
  char *form;                         // Contains the request body in the case of a POST request, or the form contents.
  char *method;                       // The HTTP Method
  char *url;                          // The Request URL (e.g. /user/list?filter=john&sort=desc&...)
  char *path;                         // The Request Path (e.g. /user/list)
  char *query_string;
  char *IP;
  char *username;
  char *session;
  char *request_line;       // The full request line (e.g. GET /index.html HTTP/1.1)
  uint64_t request_start;   // Start time in epoch milliseconds
  uint32_t response_length; // Length in bytes of the response
} api_request;


/* Stores data on ongoing activity */
typedef struct connections
{
    int socket;
    long unix_time;
    char path[HTTP_MAX_PATH];
    char IP[HTTP_MAX_IP];
} connections;


/* Stores API limits by path */
typedef struct path_limits
{
    char path[HTTP_MAX_PATH];
	char max_connections;
	char max_connections_per_ip;
	char max_seconds;
} path_limits;

/**
 * http_read_char: Reads a char from the socket, supports SSL mode and plain HTTP.
 */
int http_read_char(api_request *req, char *c);

// ERROR Handling
char *error_t_json_serializer(error_t *error);

int return_headers(api_request *req, char *filename);
int return_headers_with_mime(api_request *req, int status, char *mime_type);
/**
 * return_json_headers: Returns the HTTP headers for a JSON response
 */
int return_json_headers(api_request *req, int status);
void return_json(api_request *req, char *data);
/**
 * return_json_list: Returns JSON content from the given JSON list. It also frees the list. 
 */
void return_json_list(api_request *req, json_list_t list);
void return_json_with_status(api_request *req, int status, char *data);
void return_json_stream(api_request *req, int status, FILE *fp);
void http_print(api_request *req, void *data, int length);
void http_print_str(api_request *req, char *data);
int direct_file(api_request *req, char *filename);
int send_stream(api_request *req, FILE *fp);
void send_empty_line(api_request *req);

// Helper methods for returning HTTP Status
void not_found(api_request *req);
void not_authenticated(api_request *req);
void bad_request(api_request *req);
void too_many_connections(api_request *req);
void bad_request_with_error(api_request *req, error_t *error);
void forbidden(api_request *req);
void forbidden_with_error(api_request *req, error_t *error);
void ok(api_request *req);
void created(api_request *req);
void created_with_json(api_request *req, char *data);
void internal_server_error(api_request *req);
void internal_server_error_with_error(api_request *req, error_t *error);

void send_http_status(api_request *req, int status, char *message);

// URL Parsing helpers
typedef struct path_and_query_t
{
  char *path;
  char *query;
} path_and_query_t;

path_and_query_t *get_path_and_query_string(char *url);
void free_path_and_query_t(path_and_query_t *p);

error_t *new_error_with_values(char *code, char *message);

// HTTP HEADER UTILS

/**
 * http_log_headers: Logs all the http headers found in the HTTP REQUEST. 
 * Make sure that LOG_DEBUG is enabled. 
 */
void http_log_headers(api_request *req);

/**
 * http_get_header: Returns the value of the header with given name. Or NULL if the header is not found in the request.
 */
char *http_get_header(api_request *req, char *name);


char *get_content_type(char *filename);

#endif
