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
#ifndef __WAYUU_FILE_UTILS_H
#define __WAYUU_FILE_UTILS_H

#include <stdbool.h>
#include <stdint.h>

bool check_createdir(char *path);
bool find_in_file(char *path, char *needle);
bool is_dir(char *path);
bool is_file(char *path);
void read_file(char *out, char *path, uint64_t maxlen);
void write_file(char *filename, char *ptr, int size);
#endif