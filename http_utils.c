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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>

#include "log.h"
#include "wayuu_log.h"
#include "string_utils.h"
#include "file_utils.h"
#include "json_utils.h"
#include "http_utils.h"

/**
 * WAYUU_SSL_ON is a global that defines whether WAYUU is in SSL mode (HTTPS) or plain HTTP.
 * By default SSL mode is enabled
 */
bool WAYUU_SSL_ON = true;

/**
 * http_read_char: Reads a char from the socket, supports SSL mode and plain HTTP.
 */
int http_read_char(api_request *req, char *c)
{
	int n;
	if (WAYUU_SSL_ON)
	{
		n = SSL_read(req->ssl, c, 1);
	}
	else
	{
		n = recv(req->socket, c, 1, 0);
	}
	return n;
}

const char *HTTP_ERROR_STARTS[] = {
		HTTP_OK_START,
		HTTP_CREATED_START,
		HTTP_BAD_REQUEST_START,
		HTTP_UNAUTHORIZED_START,
		HTTP_FORBIDDEN_START,
		HTTP_NOT_FOUND_START,
		HTTP_TOO_MANY_CONNECTIONS,
		HTTP_INTERNAL_ERROR_START};

const int HTTP_ERROR_STATUS[] = {200, 201, 400, 401, 403, 404, 429, 500};

int HTTP_ERROR_N = sizeof(HTTP_ERROR_STATUS)/sizeof(HTTP_ERROR_STATUS[0]);

int _find_http_status_index(int status)
{
	int error_index = -1;
	for (int i = 0; i < HTTP_ERROR_N; i++)
	{
		if (status == HTTP_ERROR_STATUS[i])
		{
			error_index = i;
			break;
		}
	}
	return error_index;
}

int return_headers(api_request *req, char *filename)
{
	int len = 0;
	char buf[1024];
	sprintf(buf, "%s%s", HTTP_OK_START, WAYUU_HTTP_SERVER_STRING);
	len += strlen(buf);
	http_print(req, buf, len);
	char *content_type = get_content_type(filename);
	strcat(buf, content_type);
	free(content_type);
	len += strlen(buf);
	http_print(req, buf, strlen(buf));

	if (strlen(req->session) > 0)
	{
		sprintf(buf, "X-Session: %s\r\nSet-Cookie:WSSESSION=%s\r\n", req->session, req->session);
		len += strlen(buf);
		http_print(req, buf, strlen(buf));
	}
	strcpy(buf, "\r\n");
	http_print(req, buf, strlen(buf));
	len += strlen(buf);
	return len;
}

char *get_content_type(char *filename)
{
	char *buf = malloc(1024);
	char *ext = strrchr(filename, '.');
	if (!ext || ext == filename)
		sprintf(buf, CONTENT_TYPE_TEXT_HTML);
	else if (strcmp(ext, ".html") == 0 || strcmp(ext, ".js") == 0)
		sprintf(buf, CONTENT_TYPE_TEXT_HTML);
	else if (strcmp(ext, ".png") == 0)
		sprintf(buf, CONTENT_TYPE_IMAGE_PNG);
	else if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0)
		sprintf(buf, CONTENT_TYPE_IMAGE_JPEG);
	else if (strcmp(ext, ".zip") == 0)
		sprintf(buf, CONTENT_TYPE_ZIP);
	else if (strcmp(ext, ".css") == 0)
		sprintf(buf, CONTENT_TYPE_CSS);
	else if (strcmp(ext, ".svg") == 0)
		sprintf(buf, CONTENT_TYPE_SVG);
	else if (strcmp(ext, ".ico") == 0)
		sprintf(buf, CONTENT_TYPE_ICON);
	else if (strcmp(ext, ".txt") == 0)
		sprintf(buf, CONTENT_TYPE_TEXT_PLAIN);
	else if (strcmp(ext, ".csv"))
		sprintf(buf, CONTENT_TYPE_TEXT_CSV);
	else if (strcmp(ext, ".yaml") == 0)
	{
		sprintf(buf, CONTENT_TYPE_YAML);
	}
	else
		sprintf(buf, CONTENT_TYPE_OCTET_STREAM);

	return buf;
}

char *get_content_type_for_mime(char *mime)
{
	char *buf = malloc(1024);
	
	if (strcmp(mime, "text/html") == 0)
		sprintf(buf, CONTENT_TYPE_TEXT_HTML);
	else if (strcmp(mime, "image/png") == 0)
		sprintf(buf, CONTENT_TYPE_IMAGE_PNG);
	else if (strcmp(mime, "image/jpeg") == 0)
		sprintf(buf, CONTENT_TYPE_IMAGE_JPEG);
	else if (strcmp(mime, "application/zip") == 0)
		sprintf(buf, CONTENT_TYPE_ZIP);
	else if (strcmp(mime, "text/css") == 0)
		sprintf(buf, CONTENT_TYPE_CSS);
	else if (strcmp(mime, "text/plain") == 0)
		sprintf(buf, CONTENT_TYPE_TEXT_PLAIN);
	else if (strcmp(mime, "text/csv"))
		sprintf(buf, CONTENT_TYPE_TEXT_CSV);
	else if (strcmp(mime, "text/yaml") == 0)
	{
		sprintf(buf, CONTENT_TYPE_YAML);
	}
	else
		sprintf(buf, CONTENT_TYPE_OCTET_STREAM);

	return buf;
}

int return_file(api_request *req, char *path)
{

	char *src;
	long length = 0;

	FILE *file = fopen(path, "rb");
	if (file)
	{

		fseek(file, 0, SEEK_END);
		length = ftell(file);
		fseek(file, 0, SEEK_SET);
		src = calloc(length + 5, 1);

		if (src)
		{
			fread(src, 1, length, file);
		}

		fclose(file);
		http_print(req, src, length);
		free(src);
	}
	return length;
}



int direct_file(api_request *req, char *filename)
{
	if (!is_file(filename))
	{
		log_warn("File not found: %s", filename);
		return -1;
	}
	int length = return_headers(req, filename);
	length += return_file(req, filename);
	req->response_length = length;
	log_access(req, 200);
	return 0;
}

/**
 * send_stream: Read from file until end and streams response until end. It doesn't send any HTTP headers.
 */
int send_stream(api_request *req, FILE *fp)
{
	char buf[1024];
	int len = 0;
	while (fgets(buf, sizeof(buf) - 1, fp) != NULL)
	{
		int s = strlen(buf);
		len += s;
		http_print(req, buf,s);
	}
	sprintf(buf, "\r\n");
	http_print(req, buf, strlen(buf));
	len += strlen(buf);
	return len;
}

void send_empty_line(api_request *req)
{
	char buf[1024];
	sprintf(buf, "\r\n");
	http_print(req, buf, strlen(buf));
}

/**
 * http_print: Writes data to the socket, it supports SSL or plain HTTP
 * 
 * Parameters:
 * - req: api_request object
 * - data: void buffer, not necesarily char pointer
 * - length: length of the data sent. Required because this function should work with binary data as well as strings.
 */
void http_print(api_request *req, void *data, int length)
{
	if (WAYUU_SSL_ON)
	{
		SSL_write(req->ssl, data, length);
	}
	else
	{
		send(req->socket, data, length, 0);
	}
}

/**
 * http_print_str: Convenience function to print a char array over HTTP.
 */
void http_print_str(api_request *req, char *data)
{
	http_print(req, data, strlen(data));
}

void return_json(api_request *req, char *data)
{
	return_json_with_status(req, 200, data);
}

void return_json_list(api_request *req, json_list_t list)
{
	log_debug("Returning list with elements: %d", list.size);
	char *json = json_array_of_entities(list);
	return_json(req, json);
	for (int i = 0; i < list.size; i++)
	{
		free(list.elements[i]);
	}
	free(list.elements);
	free(json);
}

/**
 * return_json_headers: Returns the HTTP headers for a JSON response
 */
int return_json_headers(api_request *req, int status)
{
	// Find status in statuses
	int error_index = _find_http_status_index(status);
	if (error_index == -1)
	{
		return 0;
	}
	char buf[1024];

	sprintf(buf, "%s%s%s%s", HTTP_ERROR_STARTS[error_index], WAYUU_HTTP_SERVER_STRING, HTTP_ACCESS_CONTROL, CONTENT_TYPE_JSON);
	http_print(req, buf, strlen(buf));
	return strlen(buf);
}

int return_headers_with_mime(api_request *req, int status, char *mime)
{
	int error_index = _find_http_status_index(status);
	if (error_index == -1)
	{
		return 0;
	}
	char buf[1024];

	sprintf(buf, "%s%s%s%s", HTTP_ERROR_STARTS[error_index], WAYUU_HTTP_SERVER_STRING, HTTP_ACCESS_CONTROL, get_content_type_for_mime(mime));
	http_print(req, buf, strlen(buf));
	return strlen(buf);
}

void return_json_stream(api_request *req, int status, FILE *fp)
{
	int len = return_json_headers(req, status);
	char buf[1024];
	strcpy(buf, "\r\n");
	http_print(req, buf, strlen(buf));
	len += send_stream(req, fp);
	req->response_length = len + 2;
	log_access(req, status);
}

void return_json_with_status(api_request *req, int status, char *data)
{
	int len = return_json_headers(req, status);

	char buf[1024];
	sprintf(buf, "Content-Length: %zu\r\n\r\n", strlen(data) + 2);
	http_print_str(req, buf);

	http_print_str(req, data);
	len += strlen(buf) + strlen(data) + 2;
	// Empty line
	strcpy(buf, "\r\n");
	http_print_str(req, buf);
	req->response_length = len;
	log_access(req, status);
}

void not_found(api_request *req)
{
	send_http_status(req, 404, "");
}

void too_many_connections(api_request *req)
{
	send_http_status(req, 429, "");
}

void not_authenticated(api_request *req)
{
	send_http_status(req, 401, "");
}

void bad_request(api_request *req)
{
	send_http_status(req, 400, "");
}

void bad_request_with_error(api_request *req, wayuu_error_t *error)
{
	char *error_json = wayuu_error_t_json_serializer(error);
	return_json_with_status(req, 400, error_json);
	free(error_json);
}

void forbidden(api_request *req)
{
	send_http_status(req, 403, "");
}

void forbidden_with_error(api_request *req, wayuu_error_t *error)
{
	char *error_json = wayuu_error_t_json_serializer(error);
	return_json_with_status(req, 403, error_json);
	free(error_json);
}

void ok(api_request *req)
{
	send_http_status(req, 200, "");
}

void created(api_request *req)
{
	send_http_status(req, 201, "");
}

void created_with_json(api_request *req, char *data)
{
	return_json_with_status(req, 201, data);
}

void internal_server_error(api_request *req)
{
	send_http_status(req, 500, "");
}

void internal_server_error_with_error(api_request *req, wayuu_error_t *error) {
	char *error_json = wayuu_error_t_json_serializer(error);
	return_json_with_status(req, 500, error_json);
	free(error_json);
}

void send_http_status(api_request *req, int status, char *message)
{
	// Find status in statuses
	int error_index = _find_http_status_index(status);
	if (error_index == -1)
	{
		return;
	}

	char buf[1024];

	strcpy(buf, HTTP_ERROR_STARTS[error_index]);
	strcat(buf, WAYUU_HTTP_SERVER_STRING);
	if (strcmp("", message))
	{
		char contentLength[100];
		sprintf(contentLength, "Content-Length: %zu%s%s", strlen(message) + 2, CRLF, CRLF);
		strcat(buf, contentLength);
		strcat(buf, message);
	}
	else
	{
		strcat(buf, HTTP_CONTENT_LENGTH_ZERO);
	}
	http_print_str(req, buf);
	req->response_length += strlen(buf);
	strcpy(buf, "\r\n");
	http_print_str(req, buf);
	req->response_length += strlen(buf);
	log_access(req, status);
}

/**
 * get_path_and_query_string: Returns the path and query string part of an URL. It will only work on GET
 * requests by definition.
 */
path_and_query_t *get_path_and_query_string(char *url)
{

	path_and_query_t *result = malloc(sizeof(path_and_query_t));

	str_list_t *list = split(url, "?");

	result->path = strdup(list->strings[0]);

	if (list->n_str > 1)
	{
		result->query = strdup(list->strings[1]);
	}
	else
	{
		result->query = "";
	}

	free_str_list_t(list);
	return result;
}

void free_path_and_query_t(path_and_query_t *p)
{
	free(p->path);
	if (strcmp(p->query, ""))
	{
		free(p->query);
	}
	free(p);
}

char *wayuu_error_t_json_serializer(wayuu_error_t *error)
{
	if (error->code == NULL || strlen(error->code) == 0)
	{
		strcpy(error->code, "UNKNOWN");
	}

	char *code_json = json_key_value("code", error->code);
	char *message_json = json_key_value("message", error->message);

	int json_len = strlen(code_json) + strlen(message_json) + 25;
	char *json = malloc(json_len);
	sprintf(json, "{%s,%s}", code_json, message_json);
	free(code_json);
	free(message_json);
	return json;
}

wayuu_error_t *new_error_with_values(char *code, char *message)
{
	wayuu_error_t *error = malloc(sizeof(wayuu_error_t));
	strcpy(error->code, code);
	strcpy(error->message, message);
	return error;
}

void http_log_headers(api_request *req)
{
	if (log_level_is_enabled(LOG_DEBUG))
	{
		log_debug("Found %d headers", req->n_headers);
		for (int i = 0; i < req->n_headers; i++)
		{
			log_debug("HEADER: %s, VALUE: %s", req->headers[i].name, req->headers[i].value);
		}
	}
}

char *http_get_header(api_request *req, char *name)
{
	for (int i = 0; i < req->n_headers; i++)
	{
		if (!strcmp(req->headers[i].name, name))
		{
			return strdup(req->headers[i].value);
		}
	}
	return "";
}

char *return_response(call_response_t rsp)
{
	char *aux;
	char *aux_err;
	char *aux_txt;
	char *aux_additional_info;
	char *aux_description;

	if (rsp.status == -1)
		asprintf(&aux_err, "\"RSP\":\"FAIL\"");
	if (rsp.status == 0)
		asprintf(&aux_err, "\"RSP\":\"OK\"");
	if (rsp.status == 1)
		asprintf(&aux_err, "\"RSP\":\"ERROR\"");
	if (rsp.status == 2)
		asprintf(&aux_err, "\"RSP\":\"WARNING\"");
	if (rsp.text)
		asprintf(&aux_txt, ", \"info\":\"%s\"", rsp.text);
	if (rsp.description)
		asprintf(&aux_description, ", \"description\":\"%s\"", rsp.description);

	if (rsp.additional_info != NULL)
		asprintf(&aux_additional_info, ",\"data\":%s", rsp.additional_info);
	else
		asprintf(&aux_additional_info, ",\"data\":%s", "\"\"");

	asprintf(&aux, "{%s%s%s%s}", aux_err, (aux_txt ? aux_txt : ""), (aux_description ? aux_description : ""), (aux_additional_info ? aux_additional_info : ""));

	if (aux_err)
		free(aux_err);

	if (aux_additional_info)
		free(aux_additional_info);

	if (aux_description)
		free(aux_description);

	if (aux_txt)
		free(aux_txt);

	return aux;
}

