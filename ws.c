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
#include "ws.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "file_utils.h"
#include "http_utils.h"
#include "string_utils.h"
#include "log.h"
#include "wayuu_log.h"
#include "router.h"
#include <openssl/ssl.h>
#include <netinet/in.h>

/* Globals */
pthread_mutex_t ws_mutex;
pthread_cond_t ws_cond;
ws_queue *ws_threads_queue;
SSL_CTX *ctx;

char WAYUU_WS_ROOT[ROOT_PATH_MAX];
char FAVICON_URL[ROOT_PATH_MAX];
char WWW_INDEX[ROOT_PATH_MAX];

char WAYUU_STATIC_ROOT[2 * ROOT_PATH_MAX];

char WAYUU_WS_ALLOW[ROOT_PATH_MAX + 32];
char WAYUU_WS_DENY[ROOT_PATH_MAX + 32];
char WAYUU_WS_LIMITS[ROOT_PATH_MAX + 32];

const char *COOKIE_HEADERS[] = {"X-Session:", "Authorization:", ""};

// LIST OF ALLOWED HTTP METHODS. Last element must be NULL so that startswithany can work.
const char *ALLOWED_HTTP_METHODS[] = {"GET", "POST", "PUT", "DELETE", NULL};

void wayuu_failed()
{
	printf("Service failed. Please check %s for details\n", WAYUU_LOGFILE);
	exit(EXIT_FAILURE);
}

bool allowed_address(char *ip)
{
	if (strlen(WAYUU_WS_ALLOW) == 0)
	{
		sprintf(WAYUU_WS_ALLOW, "%s/etc/allow", WAYUU_WS_ROOT);
		sprintf(WAYUU_WS_DENY, "%s/etc/deny", WAYUU_WS_ROOT);
	}

	if (find_in_file(WAYUU_WS_DENY, ip))
	{
		return false;
	}

	if (!is_file(WAYUU_WS_ALLOW))
	{
		return true;
	}
	return find_in_file(WAYUU_WS_ALLOW, ip);
}

int get_line(api_request *req, char *buf, int size)
{

	int i = 0;
	char c = '\0';
	int n;

	while ((i < size - 1) && (c != '\n'))
	{

		n = http_read_char(req, &c);
		if (n > 0)
		{
			buf[i] = c;
			i++;
		}
		else
		{
			c = '\n';
		}
	}

	buf[i] = '\0';
	return (i);
}

void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		log_error("Unable to create SSL context");
		wayuu_failed();
	}

	return ctx;
}

void configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);
	char cert_loc[ROOT_PATH_MAX + 32];
	char key_loc[ROOT_PATH_MAX + 32];
	sprintf(cert_loc, "%s/ssl/cert.pem", WAYUU_WS_ROOT);
	sprintf(key_loc, "%s/ssl/key.pem", WAYUU_WS_ROOT);
	/* Set the key and cert */
	if (SSL_CTX_use_certificate_chain_file(ctx, cert_loc) <= 0)
	{
		log_error("Failed to use certificate in %s", cert_loc);
		wayuu_failed();
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, key_loc, SSL_FILETYPE_PEM) <= 0)
	{
		log_error("Failed to open private_key in %s", key_loc);
		wayuu_failed();
	}
}

void part_parse(char *IP, char *tmpfields, char *tmpdata, long length)
{

	long actuallength = length;
	long start = text_find_after(tmpdata, "form-data; name=\"", 0, strlen(tmpdata));
	if (start < 1)
	{
		log_warn("IP:%s Multipart error: Form-data not found ", IP);
		return;
	}

	if (strlen(tmpdata + start) > 0)
	{
		char *field = calloc(actuallength + 1, 1);
		long bytes = actuallength - start;

		memcpy(field, tmpdata + start, bytes);
		field[bytes] = 0;
		chop_string(field);
		long data_start = text_find_after(tmpdata, "\r\n\r\n", 0, actuallength);
		/* If there is already data in tmpfields, start with & */
		if (strlen(tmpfields) > 0)
			sprintf(tmpfields + strlen(tmpfields), "&");

		long start_file = text_find_after(tmpdata, "; filename=\"", 0, strlen(tmpdata));
		if (data_start > 0)
		{
			/* Save filename */
			if (start_file > 0)
			{
				save_tmp_file(tmpfields, field, start_file, tmpdata, data_start, actuallength);
			}

			/* It is a form field: Save field value */
			else
			{
				char *value = calloc(actuallength + 1, 1);
				memcpy(value, tmpdata + data_start, actuallength - data_start - 2);
				sprintf(tmpfields + strlen(tmpfields), "%s=%s", field, value);
				free(value);
			}
		}

		free(field);
	}
}

// TODO: Make this work for multiple file downloads
/**
 * save_tmp_file: Saves a file into FILE_DOWNLOAD_TMP_DIR, and stores the file name in tmpfields as well as the original filename
 */
void save_tmp_file(char *tmpfields, char *field, long start_file, char *tmpdata, long data_start, long actuallength)
{
	log_debug("save_tmp_file, start_file: %d, data_start: %d, actuallength: %d", start_file, data_start, actuallength);
	char orig_filename[MAX_ORIG_FILENAME];
	strncpy(orig_filename, tmpdata + start_file, MAX_ORIG_FILENAME);
	// Add string termination to last character to prevent strlen errors.
	orig_filename[MAX_ORIG_FILENAME - 1] = 0;
	chop_string(orig_filename);
	log_debug("Original filename %s\n", orig_filename);

	char md5[36];
	char tmpfile[256];
	// Make sure FILE_DOWNLOAD_TMP_DIR exists
	if (!is_dir(FILE_DOWNLOAD_TMP_DIR))
	{
		log_debug("Creating FILE_DOWNLOAD_TMP_DIR: %s", FILE_DOWNLOAD_TMP_DIR);
		check_createdir(FILE_DOWNLOAD_TMP_DIR);
	}
	char tmpfilepath[strlen(FILE_DOWNLOAD_TMP_DIR) + 264];
	md5sum(md5, tmpdata + data_start, actuallength - data_start - 2);
	sprintf(tmpfile, "%lu-%s", pthread_self(), md5);
	sprintf(tmpfilepath, "%s/%s", FILE_DOWNLOAD_TMP_DIR, tmpfile);

	write_file(tmpfilepath, tmpdata + data_start, actuallength - data_start - 2);
	sprintf(tmpfields + strlen(tmpfields), "%s=%s&tmpfile=%s", field, orig_filename, tmpfile);
}

void multipart_parse(char *form, char *IP, char *multipart_boundary, long content_length)
{

	char *tmppart = calloc(content_length + 1, 1);
	char *tmpfields = calloc(content_length + 1, 1);

	long ptr = 0;
	long part_start;
	long part_end;

	while (ptr < content_length)
	{

		part_start = text_find_after(form, multipart_boundary, ptr, content_length);
		if (part_start < 0)
			break;
		part_end = text_find_after(form, multipart_boundary, part_start, content_length);
		if (part_end < 0)
			break;

		int tmppart_len = part_end - part_start - strlen(multipart_boundary);
		memcpy(tmppart, form + part_start, tmppart_len);

		part_parse(IP, tmpfields, tmppart, tmppart_len);

		trim(tmppart);
		ptr = part_start + 1;
	}

	strcpy(form, tmpfields);

	free(tmpfields);
	free(tmppart);
}

void handle_api_request(api_request *req, long content_length, char *multipart_boundary)
{

	// Trace API request.
	if (log_level_is_enabled(LOG_DEBUG))
	{
		log_debug("IP:%s, URL:%s, METHOD:%s, PATH:%s, SESSION:%s ", req->IP, req->url, req->method, req->path, req->session);
		if (req->query_string[0] != 0)
			log_debug("IP: %s PARAMETERS: %s", req->IP, req->query_string);
	}

	/* Retrieve form data */

	if (content_length > 0)
	{
		char c = '\0';
		req->form = malloc(content_length + 1);
		long formptr = 0;
		for (int i = 0; i < content_length; i++)
		{
			http_read_char(req, &c);
			req->form[formptr++] = c;
			req->form[formptr] = 0;
		}

		/* If multipart boundary is at least = "--", then parse multipart */
		if (strlen(multipart_boundary) >= 2)
			multipart_parse(req->form, req->IP, multipart_boundary, content_length);
	}
	// Delegate request to router
	router_handle_request(req);
}

void handle_static_routes(api_request *req)
{
	log_debug("Handle static route: %s", req->path);
	char path[1024];
	/**
	 *  Handle default routes. URL Rewritting.
	 */
	if (strcmp(req->path, "/") == 0 || strcmp(req->path, "/index.html") == 0)
	{
		free(req->path);
		req->path = strdup(WWW_INDEX);
	}

	if (strcmp(req->path, "/favicon.ico") == 0)
	{
		free(req->path);
		req->path = strdup(FAVICON_URL);
	}

	sprintf(path, "%s/%s", WAYUU_STATIC_ROOT, req->path);
	log_debug("IP:%s GET: %s, PATH: %s", req->IP, req->path, path);
	// If the file is not found return /index.html
	if (direct_file(req, path) < 0)
	{
		sprintf(path, "%s/%s", WAYUU_STATIC_ROOT, WWW_INDEX);
		direct_file(req, path);
	}
}

api_request *api_request_new(int socket)
{
	api_request *req = calloc(1, sizeof(api_request));
	req->request_start = epoch_millis();
	req->response_length = 0;
	req->query_string = "";
	req->form = "";
	req->session = "";
	req->path = "";
	req->username = "";
	req->url = "";
	req->socket = socket;
	return req;
}

/* Return "total" / "by_ip" ongoing connections "path" and "IP" */
void get_live_stats(char *path, char *IP, int *total, int *by_ip)
{
	for (int i = 0; i < WS_MAX_CONNECTIONS; i++)
	{
		if (live_connections[i].socket)
		{
			if (startswith(live_connections[i].path, path))
			{
				(*total)++;
				if (!strcmp(IP, live_connections[i].IP))
					(*by_ip)++;
			}
		}
	}
}

/* Validates if socket/IP/path is to be allowed */
bool connection_validate(char *IP, char *path)
{
	for (int i = 0; i < MAX_LIMIT_RULES; i++)
	{
		if (!*limits[i].path)
			break;
		if (startswith(path, limits[i].path))
		{
			int total = 0;
			int by_ip = 0;
			get_live_stats(limits[i].path, IP, &total, &by_ip);
			if (total > limits[i].max_connections)
			{
				log_debug("IP:%s denied, max_connections exceeded for %s", IP, limits[i].path);
				return false;
			}
			if (by_ip > limits[i].max_connections_per_ip)
			{
				log_debug("IP:%s denied, max_connections_per_ip exceeded for %s", IP, limits[i].path);
				return false;
			}
		}
	}
	return true;
}

void connection_close(api_request *req)
{
	if (WAYUU_SSL_ON)
	{
		SSL_shutdown(req->ssl);
		SSL_free(req->ssl);
	}
	close(req->socket);
	connection_del(req->socket);
}

/* Removes socket from live_connections */
void connection_del(int socket)
{
	for (int i = 0; i < WS_MAX_CONNECTIONS; i++)
	{
		if (live_connections[i].socket == socket)
		{
			live_connections[i].socket = 0;
			*live_connections[i].path = 0;
			*live_connections[i].IP = 0;
			break;
		}
	}
}

/* Adds socket to live_connections (if allowed) */
bool connection_add(int socket, char *IP, char *path)
{
	if (!connection_validate(IP, path))
		return false;

	for (int i = 0; i < WS_MAX_CONNECTIONS; i++)
	{
		if (!live_connections[i].socket)
		{
			live_connections[i].socket = socket;
			strcpy(live_connections[i].path, path);
			strcpy(live_connections[i].IP, IP);
			return true;
		}
	}

	log_debug("WS_MAX_CONNECTIONS reached");
	return false;
}

/**
 * accept_request: Main request handling routine. It performs initial parsing of structures,
 * generates api_request structure
 * and delegates request to static handler or api handler depending on mount points. 
 */
void accept_request(int socket)
{

	char buf[1024] = "\0";
	int numchars;
	char method[255];
	char url[255];
	size_t i, j;
	api_request *req = api_request_new(socket);

	// IP
	req->IP = calloc(24, 1);
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	getpeername(socket, (struct sockaddr *)&addr, &addr_len);
	strcpy(req->IP, inet_ntoa(addr.sin_addr));
	SSL *ssl;
	// SSL
	if (WAYUU_SSL_ON)
	{

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, socket);

		if (SSL_accept(ssl) <= 0)
		{
			log_warn("SSL connection failed from IP: %s\n", req->IP);
		}
		req->ssl = ssl;
	}

	/* Read header start */
	numchars = get_line(req, buf, sizeof(buf));
	log_trace("IP: %s, Request: %s", req->IP, buf);

	req->request_line = strdup(buf);
	// The request line ends in the two characters \r\n
	req->request_line[strlen(req->request_line) - 2] = 0;

	// HTTP METHOD
	i = 0;
	j = 0;
	while (!isspace((int)(buf[j])) && (i < sizeof(method) - 1))
	{
		method[i] = buf[j];
		i++;
		j++;
	}
	method[i] = '\0';

	req->method = method;

	// If the request is not from any of the supported HTTP methods, reject the request.
	if (!startswithany(method, ALLOWED_HTTP_METHODS))
	{
		bad_request(req);
		connection_close(req);
		free(req);
		return;
	}

// Parse URL
	i = 0;
	while (isspace((int)(buf[j])) && (j < sizeof(buf)))
	{
		j++;
	}
	// URL
	while (!isspace((int)(buf[j])) && (i < sizeof(url) - 1) && (j < sizeof(buf)))
	{
		url[i] = buf[j];
		i++;
		j++;
	}

	url[i] = '\0';

	req->url = strdup(url);

	/* Validate and add connection to live_connections */
	if (!connection_add(req->socket, req->IP, req->url))
	{
		too_many_connections(req);
		connection_close(req);
		free(req);
		return;
	}

	/* Parse remaining part of the HTTP header section */
	long content_length = -1;
	char multipart_boundary[100] = "\0";
	numchars = 1;
	buf[0] = 'A';
	buf[1] = '\0';
	numchars = get_line(req, buf, sizeof(buf));
	req->session = calloc(MAX_SESSION, 1);
	int headers_idx = 0;
	while ((numchars > 0) && strcmp("\n", buf) && strcmp("\r\n", buf))
	{

		if (headers_idx < HTTP_MAX_HEADERS)
		{
			str_list_t *nameval = split_once(buf, ":");
			if (nameval->n_str > 1)
			{
				log_trace("Found header: %s, %s", nameval->strings[0], nameval->strings[1]);
				strncpy(req->headers[headers_idx].name, nameval->strings[0], HTTP_MAX_HEADER_NAME);
				trim(nameval->strings[1]);
				strncpy(req->headers[headers_idx].value, nameval->strings[1], HTTP_MAX_HEADER_VALUE);
				headers_idx++;
			}
			free_str_list_t(nameval);
		}
		if (startswith(buf, "Content-Type:"))
		{
			req->content_type = rtrim(&(buf[14]), ';');
		}
		/* Get multipart boundary */
		if (startswith(buf, "Content-Type: multipart/form-data"))
		{
			char *boundary = strcasestr(buf, "boundary=");
			if (boundary)
			{
				sprintf(multipart_boundary, "--%s", boundary + strlen("boundary=")); // TODO: Validate size
				trim(multipart_boundary);
			}
		}

		/* Get content length */
		if (startswith(buf, "Content-Length:"))
		{
			content_length = atoi(&(buf[16]));
		}

		// Get original IP if behind proxy
		if (startswith(buf, "X-Real-IP:"))
		{
			free(req->IP);
			req->IP = calloc(26, 1);
			trim(buf);
			strncpy(req->IP, buf + 11, 24);
		}

		/* Get Session */
		if (startswithany(buf, COOKIE_HEADERS))
		{
			strncpy(req->session, buf + 10, MAX_SESSION);
			trim(req->session);
		}

		if (startswith(buf, "Cookie:") && req->session[0] == 0)
		{
			if (strlen(buf + 18) < MAX_SESSION)
				strcpy(req->session, buf + 18);
		}

		numchars = get_line(req, buf, sizeof(buf));
	}

	req->n_headers = headers_idx;

	// ROUTE HANDLING LOGIC
	// query string and path
	path_and_query_t *pq = get_path_and_query_string(url);
	// Remove /api from PATH

	req->query_string = strdup(pq->query);

	/* I. Handle Static Routes */
	if (!startswith(url, API_MOUNT))
	{
		req->path = strdup(pq->path);
		// Only handle GET request to static routes
		if (strcasecmp(method, "GET") == 0)
		{
			handle_static_routes(req);
		}
		else
		{
			bad_request(req);
		}
	}

	/* II. HANDLE API REQUEST */
	else
	{
		req->path = strdup(pq->path) + strlen(API_MOUNT);
		// Create an api request object.
		handle_api_request(req, content_length, multipart_boundary);
	}
	free_path_and_query_t(pq);
	connection_close(req);
	free(req);
}

ws_queue *ws_create_queue(int maxElements)
{

	ws_queue *queue;
	queue = (ws_queue *)malloc(sizeof(ws_queue));
	queue->elements = (int *)malloc(sizeof(int) * maxElements);
	queue->size = 0;
	queue->capacity = maxElements;
	queue->front = 0;
	queue->rear = -1;
	return queue;
}

int ws_queue_get()
{

	pthread_mutex_lock(&ws_mutex);

	while (ws_threads_queue->size == 0)
	{
		if (pthread_cond_wait(&ws_cond, &ws_mutex) != 0)
			perror("cond_wait failed");
	}

	int val = ws_threads_queue->elements[ws_threads_queue->front];
	if (ws_threads_queue->size != 0)
	{
		ws_threads_queue->size--;
		ws_threads_queue->front++;
		if (ws_threads_queue->front == ws_threads_queue->capacity)
			ws_threads_queue->front = 0;
	}

	pthread_mutex_unlock(&ws_mutex);
	return val;
}

static void *ws_connection_handler()
{
	int socket = 0;
	while (1)
	{
		socket = ws_queue_get();
		accept_request(socket);
	}
	return NULL;
}

void ws_launch(int port, char *bind_addr)
{

	int server_sock = -1;
	int client_sock = -1;
	struct sockaddr_in client_name;
	uint32_t client_name_len = sizeof(client_name);

	// Create TMP dir
	if (!check_createdir(FILE_DOWNLOAD_TMP_DIR))
	{
		log_fatal("Cannot create path %s", FILE_DOWNLOAD_TMP_DIR);
	}
	if (WAYUU_SSL_ON)
	{
		init_openssl();
		ctx = create_context();
		configure_context(ctx);
	}
	/* Load path limits */
	live_connections = calloc(sizeof(connections), WS_MAX_CONNECTIONS);
	limits = load_limits();
	/* Start service */
	ws_threads_queue = ws_create_queue(WS_MAX_CONNECTIONS);
	pthread_mutex_init(&ws_mutex, NULL);
	pthread_t threadPool[WS_THREAD_POOL_SIZE];

	int httpd = 0;
	struct sockaddr_in name;

	httpd = socket(PF_INET, SOCK_STREAM, 0);
	if (httpd == -1)
	{
		log_fatal("Unable to obtain socket handle");
	}

	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_port = htons(port);
	name.sin_addr.s_addr = inet_addr(bind_addr);
	log_info("WAYUU binding to address: %s", bind_addr);
	log_info("WAYUU starting on port %d", port);
	// Set SO_REUSEADDR to prevent no bind on TIME_WAIT. See for instance
	// https://serverfault.com/questions/329845/how-to-forcibly-close-a-socket-in-time-wait
	// http://www.unixguide.net/network/socketfaq/4.5.shtml
	if (setsockopt(httpd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
		log_error("setsockopt(SO_REUSEADDR) failed");
	if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
	{
		log_fatal("Unable to bind to port %d", port);
	}

	for (int i = 0; i < WS_THREAD_POOL_SIZE; i++)
		pthread_create(&threadPool[i], NULL, ws_connection_handler, (void *)NULL);

	if (listen(httpd, 5) < 0)
		log_fatal("Error while listening to socket");

	server_sock = httpd;

	log_info("WAYUU WS %s running on port %d", WAYUU_WS_VERSION, port);

	while (true)
	{

		client_sock = accept(httpd, (struct sockaddr *)&client_name, &client_name_len);
		if (client_sock == -1)
			log_fatal("Error while creating client socket");

		char *IP = malloc(16);
		strcpy(IP, inet_ntoa(client_name.sin_addr));

		if (!allowed_address(IP))
		{
			log_debug("IP:%s Access denied", IP);
			close(client_sock);
		}
		else
		{

			// Add to queue
			pthread_mutex_lock(&ws_mutex);
			if (ws_threads_queue->size != ws_threads_queue->capacity)
			{
				ws_threads_queue->size++;
				ws_threads_queue->rear = ws_threads_queue->rear + 1;
				if (ws_threads_queue->rear == ws_threads_queue->capacity)
					ws_threads_queue->rear = 0;
				ws_threads_queue->elements[ws_threads_queue->rear] = client_sock;
			}
			else
			{
				log_warn("IP:%s Connection dropped. No threads available", IP);
			}
			pthread_mutex_unlock(&ws_mutex);
			pthread_cond_signal(&ws_cond);
		}
	}

	log_info("WAYUU WS shutting down");
	close(server_sock);
	if (WAYUU_SSL_ON)
	{
		SSL_CTX_free(ctx);
	}
	cleanup_openssl();
}

/* 

	load_limits: Loads the limits configuration file.
  
	The limits configuration file contains a list of comma delimited limits with:
	path, max connections, max connections per IP, max execution seconds

  Example:
  /api, 20, 2, 10

  Access to /api will be limited to a maximum of 20 simultaneous connections
  and no more than 2 from the same IP. Connections will be dropped if alive
  for more than 10 seconds
*/
path_limits *load_limits()
{
	sprintf(WAYUU_WS_LIMITS, "%s/etc/limits", WAYUU_WS_ROOT);
	path_limits *out = calloc(sizeof(path_limits), MAX_LIMIT_RULES);

	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	int path_rules = 0;

	/* Open etc/limits file */
	fp = fopen(WAYUU_WS_LIMITS, "r");
	if (fp != NULL)
	{
		/* Read file line by line */
		while ((read = getline(&line, &len, fp)) != -1)
		{
			/* Only lines starting with / are considered */
			if (*line == '/')
			{
				/* Tokenize line, comma delimited */
				char *token;
				token = strtok(line, ",");
				strcpy(out[path_rules].path, token);
				int i = 1;
				while (token != NULL)
				{
					token = strtok(NULL, ",");
					if (!token)
						break;
					if (i == 1)
						out[path_rules].max_connections = atoi(token);
					if (i == 2)
						out[path_rules].max_connections_per_ip = atoi(token);
					if (i == 3)
						out[path_rules].max_seconds = atoi(token);
					if (++i >= 4)
						break;
				}

				/* If all fields are present, increment path_rules, otherwise clean record */
				if (i >= 3) {
					log_debug("Read limits configuration: (path: %s, max_connections: %d, max_connections_per_ip: %d, max_seconds: %d)", out[path_rules].path, out[path_rules].max_connections, out[path_rules].max_connections_per_ip, out[path_rules].max_seconds);
					path_rules++;
				}
				else
					*out[path_rules].path = 0;

				/* Stop here if MAX_LIMIT_RULES is reached */
				if (path_rules >= MAX_LIMIT_RULES)
					break;
			}
		}
		fclose(fp);
	}

	if (line)
		free(line);
	return out;
}
