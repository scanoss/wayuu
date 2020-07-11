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

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>

#include "router.h"

#include "log.h"
#include "wayuu_log.h"


/**
 * Logs access in NGINX Combined log format.
 */
void log_access(api_request *req, int status)
{

  char *ts = format_ts_common_log();

  char *referer = http_get_header(req, "Referer");
  char *ua = http_get_header(req, "User-Agent");
  // FORMAT: REMOTE_IP [TIMESTAMP] "HTTP REQUEST" "REFERRER" "USER AGENT"
  FILE *fp = fopen(WAYUU_ANALYTICS_LOG, "a");
  if (fp != NULL)
  {
    fprintf(fp, "%s - - [%s] \"%s\" %d %u \"%s\" \"%s\" %.3f\n", req->IP, ts, req->request_line, status, req->response_length, referer, ua, response_time(req));
    fclose(fp);
  }
  free(ts);
  if (strlen(referer) > 0)
    free(referer);
  if (strlen(ua) > 0)
    free(ua);
}

uint64_t epoch_millis()
{
  struct timeval tv;

  gettimeofday(&tv, NULL);

  return (uint64_t)(tv.tv_sec) * 1000 +
         (uint64_t)(tv.tv_usec) / 1000;
}

double response_time(api_request *req)
{
  return (double)(epoch_millis() - req->request_start) / 1000;
}
