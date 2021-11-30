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
  * @file json_utils.c
  * @date 16 March 2021 
  * @brief Contains helper functions for JSON parsing
  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "string_utils.h"
#include "log.h"
#include "json_utils.h"

#define JSON_ARRAY_BEGIN "["
#define JSON_ARRAY_STR_BEGIN "[\""
#define JSON_ARRAY_END "]"
#define JSON_ARRAY_STR_END "\"]"
#define JSON_ARRAY_STR_SEP "\",\""
#define MAX_SINGLE_JSON_ENTITY_STR_LEN 512
#define MAX_INT_STRING_LEN 32

/**
 * @brief Returns a dynamically allocated string containing the JSON representation of an array of strings.
 * Example: **array = {"uno", "dos", "tres"}** will return **"[\"uno\",\"dos\",\"tres\"]"**
 * 
 * @param array Pointer to the array of strings. Each string must be NULL terminated.
 * @param size Size of the array.
 * @return char* Pointer to the dynamically allocated string. 
 */
char *json_array_of_strings(char **array, int size)
{
  if (array == NULL || size < 1)
  {
    return strdup("[]");
  }
  // calculate size of string
  int string_size = strlen(JSON_ARRAY_STR_BEGIN) + strlen(JSON_ARRAY_STR_END) + size * strlen(JSON_ARRAY_STR_SEP) + 2;
  for (int i = 0; i < size; i++)
  {
    if (array[i] != NULL)
      string_size += strlen(array[i]);
  }

  char *json = calloc(string_size, sizeof(char));
  strcpy(json, JSON_ARRAY_STR_BEGIN);
  char *joined_str = join(array, size, JSON_ARRAY_STR_SEP);
  strcat(json, joined_str);
  strcat(json, JSON_ARRAY_STR_END);
  free(joined_str);
  return json;
}

/**
 * @brief Returns a dynamically allocated string containing the JSON representation of 
 * an array of entities.
 * 
 * @param list A list of entities. The list must provide a function to convert the entity to a string. 
 * @return char* JSON representation of the array of entities. 
 */
char *json_array_of_entities(json_list_t list)
{
  if (list.size == 0)
  {
    char *json = malloc(strlen(JSON_ARRAY_BEGIN) + strlen(JSON_ARRAY_END) + 2);
    sprintf(json, "%s%s", JSON_ARRAY_BEGIN, JSON_ARRAY_END);
    return json;
  }
  char **json_entities = calloc(list.size, MAX_SINGLE_JSON_ENTITY_STR_LEN);
  for (int i = 0; i < list.size; i++)
  {
    json_entities[i] = list.serializer(list.elements[i]);
    // TODO reallocate memory if json_one exceeds length of max single json entity string.
  }

  char *joined_str = join(json_entities, list.size, ",");
  char *json = malloc(strlen(joined_str) + list.size + strlen(JSON_ARRAY_BEGIN) + strlen(JSON_ARRAY_END) + 2);
  strcpy(json, JSON_ARRAY_BEGIN);
  strcat(json, joined_str);
  strcat(json, JSON_ARRAY_END);
  
  if (joined_str && *joined_str!='\0')
    free(joined_str);
 
  for (int i = 0; i < list.size; i++)
  {
    free(json_entities[i]);
  }
  free(json_entities);
  return json;
}

/**
 * @brief Returns a json fragment for a key value, e.g.: "key":"value"
 * Example json_key_value("key", "value") will return a string "key":"value"
 * 
 * @param key Key of the json fragment.
 * @param value Value of the json fragment. 
 * @return char* The json fragment.
 */
char *json_key_value(char *key, char *value)
{
  char *json = calloc(1, strlen(key) + strlen(value) + 15);
  sprintf(json, "\"%s\":\"%s\"", key, value? value : "");
  return json;
}

/**
 * @brief Returns a json fragment for a key value for an int, e.g.: "key":value
 * Example json_key_value_int("key", 1) will return a string "key":1
 * 
 * @param key Key of the json fragment.
 * @param value Value of the json fragment. 
 * @return char* The json fragment.
 */
char *json_key_value_int(char *key, int value)
{
  char *json = calloc(1, strlen(key) + MAX_INT_STR + 15);
  sprintf(json, "\"%s\":%d", key, value);
  return json;
}

/**
 * @brief Returns a json fragment for a key value for an boolean, e.g.: "key":boolean
 * Example json_key_value_bool("key", true) will return a string "key":true
 * 
 * @param key Key of the json fragment.
 * @param value Value of the json fragment. 
 * @return char* The json fragment.
 */
char *json_key_value_bool(char *key, bool value)
{
  char *json = calloc(1, strlen(key) + MAX_INT_STR + 15);
  sprintf(json, "\"%s\":%s", key, value ? "true": "false");
  return json;
}

/**
 * @brief Returns a json fragment for a key value for an uint32_t, e.g.: "key":value
 * Example json_key_value_uint32("key", 1) will return a string "key":1
 * 
 * @param key Key of the json fragment.
 * @param value Value of the json fragment.
 * @return char*  The json fragment.
 */
char *json_key_value_uint32_t(char *key, uint32_t value)
{
  char *json = calloc(1, strlen(key) + MAX_INT_STR + 15);
  sprintf(json, "\"%s\":%u", key, value);
  return json;
}

/**
 * @brief Returns a dynamically allocated string containing the JSON representation for an array of integers.
 * Example json_array_of_ints({1,2,3}, 3) will return "[1,2,3]"
 * 
 * @param array 
 * @param size 
 * @return char* 
 */
char *json_array_of_ints(int array[], int size)
{
  log_debug("Printing an array of ints with size: %d", size);
  if (array == NULL || size < 1)
  {
    return strdup("[]");
  }
  char *json = calloc(size, (MAX_INT_STRING_LEN + 2));
  strcat(json, JSON_ARRAY_BEGIN);
  for (int i = 0; i < size; i++)
  {
    log_debug("array[%d]: %d", i, array[i]);
    char *int_str = malloc(MAX_INT_STRING_LEN + 1);
    sprintf(int_str, "%d", array[i]);
    strcat(json, int_str);
    free(int_str);
    if (i < (size - 1))
    {
      strcat(json, ",");
    }
  }

  strcat(json, JSON_ARRAY_END);
  return json;
}
