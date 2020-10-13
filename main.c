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

#ifdef WAYUU_DIST
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "router.h"
#include "http_utils.h"
#include "ws.h"
#include "file_utils.h"
#include "log.h"

char *REDIR_PATHS[] = {""};

void print_usage()
{
  printf("USAGE: wayuu [-d] [-b ip_addr] [-p port] [-r root] [-f]\n");
  printf("Options:\n");
  printf("-d         : Enabled DEBUG mode\n");
  printf("-b ip_addr : Bind to IP address. Default: \"0.0.0.0\"\n");
  printf("-p port    : Bind to TCP port. Default: 4443\n");
  printf("-r root    : Use root as the root folder for WAYUU. Default: /etc/wayuu\n");
  printf("-f         : HTTP mode\n");
}

int main(int argc, char *argv[])
{

  int ws_port = DEFAULT_PORT;
  strcpy(WAYUU_WS_ROOT, DEFAULT_ROOT);
  sprintf(WAYUU_STATIC_ROOT, "%s/%s", DEFAULT_ROOT, DEFAULT_STATIC_ROOT);
  strcpy(WWW_INDEX, DEFAULT_WWW_INDEX);
  strcpy(FAVICON_URL, DEFAULT_FAVICON_URL);
  char bind_addr[24];
  strcpy(bind_addr, DEFAULT_BIND_ADDRESS);

  /* Load path limits */
  live_connections = calloc(sizeof(connections), WS_MAX_CONNECTIONS);
  limits = load_limits();

  signal(SIGPIPE, SIG_IGN);
  // Parse CLI Arguments using getopt

  int opt;
  
  while ((opt = getopt(argc, argv, ":b:p:r:hdf")) != -1)
  {
    switch (opt)
    {

    case 'd':
      log_set_level(LOG_DEBUG);
      break;
    case 'f':
      WAYUU_SSL_ON = false;
      break;
    case 'h':
      print_usage();
      exit(EXIT_SUCCESS);
      break;
    case 'b':
      strcpy(bind_addr, optarg);
      break;
    case 'p':
      ws_port = atoi(optarg);
      break;
    case 'r':
      strcpy(WAYUU_WS_ROOT, optarg);
      log_info("WAYUU ROOT now: %s", WAYUU_WS_ROOT);
      if (!is_dir(WAYUU_WS_ROOT))
      {
        log_fatal("Unable to start, root directory doesn't exist: %s", WAYUU_WS_ROOT);
      }
      break;
    case ':':
      printf("option needs a value\n");
      break;
    case '?':
      printf("unknown option: %c\n", optopt);
      exit(EXIT_FAILURE);
      break;
    default:
      print_usage();
      exit(1);
    }
  }

  /* Launch webservice */
  log_set_file(WAYUU_LOGFILE);
  ws_launch(ws_port, bind_addr);
  log_close_file();
  free(live_connections);
  exit(EXIT_SUCCESS);
}

#endif
