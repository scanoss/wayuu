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
#ifndef __WAYUU_WS_H
#define __WAYUU_WS_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/ssl.h>
#include <stdbool.h>
#include "http_utils.h"

// DEFINITIONS
// This is the maximum size for the original name of the downloaded file
#define MAX_ORIG_FILENAME 256
// Folder where files are downloaded.
#define FILE_DOWNLOAD_TMP_DIR "/tmp/wayuu"

// WS Worker Thread pool size
#define WS_THREAD_POOL_SIZE 20
// Maximum amount of connections held in the WS queue
#define WS_MAX_CONNECTIONS 1024

#define DEFAULT_PORT 4443
// This is the default folder for configuration.
#define DEFAULT_ROOT "/etc/wayuu"

#define DEFAULT_STATIC_ROOT "www"
// By default Wayuu will bind to 127.0.0.1.
#define DEFAULT_BIND_ADDRESS "127.0.0.1"
#define ROOT_PATH_MAX 256
#define MAX_LIMIT_RULES 64

extern char WAYUU_WS_ROOT[ROOT_PATH_MAX];
extern char WAYUU_STATIC_ROOT[2 * ROOT_PATH_MAX];
extern char FAVICON_URL[ROOT_PATH_MAX];
extern char WWW_INDEX[ROOT_PATH_MAX];
// These are alternative paths that will be tried for static assets.
extern char *REDIR_PATHS[];

extern const char *ALLOWED_HTTP_METHODS[];

// WEB SERVICE Constants
/**
 * API_MOUNT: Mount point of the API. All requests beginning with API_MOUNT will be routed to the API router.
 */
#define API_MOUNT "/api"
#define DEFAULT_WWW_INDEX "/index.html"
#define DEFAULT_FAVICON_URL "/favicon.ico"

#define WAYUU_LOGFILE "/var/log/wayuu.log"

#define MAX_SESSION 64

typedef struct ws_queue
{
  int capacity;
  int size;
  int front;
  int rear;
  int *elements;
} ws_queue;
  
connections *live_connections;
path_limits *limits;

// WS HOOKS

/**
 * ws_url_rewrite: Function that rewrites URL based on conditions.
 */
typedef void (*ws_url_rewrite)(char *url);

/**
 * ws_launch: Launches Wayuu in the port and IP given. 
 */
void ws_launch(int port, char *bind_addr);

void handle_static_routes(api_request *req);

/**
 * part_parse: Handles parsing each of the parts of a multipart POST
 */
void part_parse(char *IP, char *tmpfields, char *tmpdata, long length);

/**
 * save_tmp_file: Saves a file into SCAN_TMP_DIR, and stores the file name in tmpfields as well as the original filename
 */
void save_tmp_file(char *tmpfields, char *field, long start_file, char *tmpdata, long data_start, long actuallength);

/**
 * wayuu_failed: Exits with EXIT_FAILURE and warns via STDOUT showing log location
 */
void wayuu_failed();

bool allowed_address(char *ip);
path_limits *load_limits();

void connection_del(int socket);
void connection_close(api_request *req);
#endif
