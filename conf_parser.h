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
#ifndef __WAYUU_CONF_PARSER_H
#define __WAYUU_CONF_PARSER_H

#include <stdbool.h>
#define _CONF_MAX_MULTI_ELEMENTS 20
#define CONF_ITEM_SIZE sizeof(conf_item) + _CONF_MAX_MULTI_ELEMENTS
#define _CONF_MAX_ITEMS 20


/**
 * @brief Maximum amount of multi valued values.
 */
#define MAX_MULTIVAL_LEN 50

/**
 * @brief Maximum length of a single line in a config file.
 */
#define MAX_LINE_LEN 512

/**
 * @brief Represents a line in a CONF file. 
 */
typedef struct conf_item
{
  char *key;
  char *value;
  char *multivalue[_CONF_MAX_MULTI_ELEMENTS];
  int n_multivalues;
} conf_item;

/**
 * @brief Contains an array of conf_items and a location. Designed to simplify serialisation.
 */
typedef struct serializable
{
  char *path;
  conf_item *items[_CONF_MAX_ITEMS];
  int n_items;
} serializable;

typedef struct key_flag
{
  char *key;
  bool is_multi;
} key_flag;

typedef struct key_flags
{
  key_flag flags[10];
  int size;
} key_flags;

// PARSING and READING function definitions
typedef int (*conf_handler)(void *output, conf_item *item);
typedef serializable *(*conf_serializer)(void *input);

conf_item *conf_parse_line(char *line, bool is_multi);
key_flag get_key_flag(char *key, key_flags keys);

// Constructors and destructors
conf_item *new_conf_item();
conf_item *new_conf_item_with_values(char *key, char *value, char *multivalue[], int n_multivalues);
serializable *new_serializable(char *path, conf_item *items[], int n_items);
void free_conf_item(conf_item *item);
void free_serializable(serializable *items);

int parse(char *path, conf_handler handler, void *output, key_flags flags);
int write_conf(void *input, conf_serializer serializer);

// UTILS
char *conf_item_to_string(conf_item *item);
char *serializable_to_string(serializable *s);

#endif