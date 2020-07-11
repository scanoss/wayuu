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
#ifndef __WAYUU_STRING_UTILS_H
#define __WAYUU_STRING_UTILS_H

#include <stdbool.h>

/**
 * MAX_INT_STR: Defines the maximum length of a string representation of an integer.
 */
#define MAX_INT_STR 32
/**
 * MAX_SPLIT_STR: Maximum number of strings that can be handled by split method.
 */
#define MAX_SPLIT_STR 50
#define MAX_SPLIT_STR_LEN 1024

typedef struct str_list_t
{
  int n_str;
  char *strings[MAX_SPLIT_STR];
} str_list_t;
/**
 * md5sum: Returns a hex representation of the MD5 of the input 'data' string.
 */
void md5sum(char *out, char *data, int len);
void trim(char *str);
/**
 * rtrim: Returns a subtring of the original string until the first occurrence of the character 'sep'.
 */
char *rtrim(const char *str, char sep);

str_list_t *split(char *str, char *delim);
void free_str_list_t(str_list_t *list);

/**
 * split_once: Variant of split, only splits at most once the string by the separator.
 */
str_list_t *split_once(char *str, char *delim);
/*
 * join: returns a dynamically allocated string with all the elements separated by the delimiter specified.
 */
char *join(char **array, int size, char *delim);

/**
 * startswithany: Checks if any of the strings in the list is contained in the string and returns true
 * otherwise it returns false.
 *
 * IMPORTANT: list has to be an array of strings with the last element an empty string, "". This saves having to add
 * an extra argument with the size of the array.
 */
bool startswithany(char *str, const char *list[]);

/**
 * startswith: Returns true if str starts with prefix.
 */
bool startswith(char *str, const char *prefix);

/**
 * chop_string: Chops string at the next character less than 34 ASCII ('"')
 */
void chop_string(char *input);

/**
 * text_find_after: Returns position in haystack right after end of needle, or -1 if not found 
 */
long text_find_after(char *haystack, char *needle, long start, long bytes);
#endif
