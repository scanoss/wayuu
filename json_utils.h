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
 * json_utils.h 
 * 
 * Collection of simple utilities for serializing JSON.
 * 
 */
#ifndef __WAYUU_JSON_UTILS_H
#define __WAYUU_JSON_UTILS_H

#include <stdint.h>

/**
 * json_type_serializer: Function that knows how to serialize a particular entity. Must be implemented by all the
 * entities.
 */
typedef char *(*json_type_serializer)(void *object);

typedef struct json_list_t
{
  int size;
  json_type_serializer serializer;
  void **elements;
} json_list_t;

/**
 * json_array_of_strings: Returns a dynamically allocated string containing the JSON representation of an array of strings.
 */
char *json_array_of_strings(char **array, int size);

/**
 * json_array_of_ints: Returns a dynamically allocated string containing the JSON representation for an array of integers.
 */
char *json_array_of_ints(int array[], int size);

/**
 * json_array_of_entities: Returns a dynamically allocated string containing the JSON representation of an array of entities.
 */
char *json_array_of_entities(json_list_t list);

/**
 * json_key_value: Returns a json fragment for a key value, e.g.: "key":"value"
 */
char *json_key_value(char *key, char *value);

/**
 * json_key_value: Returns a json fragment for a key value for an int, e.g.: "key":value
 */
char *json_key_value_int(char *key, int value);

char *json_key_value_bool(char *key, bool value);

/**
 * json_key_value: Returns a json fragment for a key value for an uint32_t, e.g.: "key":value
 */
char *json_key_value_uint32_t(char *key, uint32_t value);

#endif
