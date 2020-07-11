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
 * wayuu_log.h
 * 
 * Wayuu specific logging utilities. Uses logging from base.
 */
#ifndef __WAYUU_LOG_H
#define __WAYUU_LOG_H

#include <stdbool.h>
#include "http_utils.h"
#include "log.h"

// Log file for analytics
#define WAYUU_ANALYTICS_LOG "/var/log/wayuu-access.log"


void wayuu_failed();

void log_access(api_request *req, int status);

double response_time(api_request *req);

uint64_t epoch_millis();

#endif
