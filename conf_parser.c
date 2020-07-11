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
 *  conf_parser.c - functions to parse and write CONF files
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "string_utils.h"
#include "conf_parser.h"

/*
 * DELIM is the delimiter that separates keys and values in a conf file. 
 */
const char DELIM[] = "=";
const char MULTI_DELIM[] = ",";

/*
 * conf_parse_multi: Parses comma separated strings into array of values.
 */
void conf_parse_multi(conf_item *item)
{
  int i = 0;
  // We store value string in a separate string because strtok modifies it.
  char *value = strdup(item->value);
  // tmp_value is a register that stores the current value obtained from the tokenizer.
  char *tmp_value = strtok(value, MULTI_DELIM);
  if (tmp_value && strcmp("", tmp_value))
  {
    item->multivalue[0] = strdup(tmp_value);
    trim(item->multivalue[0]);
    while (tmp_value != NULL && i < _CONF_MAX_MULTI_ELEMENTS)
    {
      i++;
      tmp_value = strtok(NULL, MULTI_DELIM);
      if (tmp_value != NULL)
      {
        item->multivalue[i] = strdup(tmp_value);
        trim(item->multivalue[i]);
      }
    }
  }
  item->n_multivalues = i;
  free(tmp_value);
  free(value);
}

/*
 * conf_parse_first_pass - parses a line and returns a conf_item. 
 * It doesn't handle multivalues.
 * 
 */

conf_item *conf_parse_first_pass(char *line)
{
  if (!strstr(line, "="))
  {
    return NULL;
  }

  conf_item *result = new_conf_item();
  // make copy of line to prevent affecting the original line.
  char *line_copy = strdup(line);
  trim(line_copy);
  // Get the key
  char *key = strtok(line_copy, DELIM);
  result->key = strdup(key);
  trim(result->key);
  // store the value
  char *value = strtok(NULL, DELIM);
  if (value == NULL)
  {
    value = "";
  }

  if (strcmp(value, ""))
  {
    trim(value);
    result->value = strdup(value);
    trim(result->value);
  }
  else
  {
    result->value = "";
  }

  // initialise n_multivalues
  result->n_multivalues = 0;
  free(line_copy);

  return result;
}

conf_item *conf_parse_line(char *line, bool is_multi)
{
  conf_item *result = conf_parse_first_pass(line);
  if (is_multi)
  {
    conf_parse_multi(result);
  }
  return result;
}

int parse(char *path, conf_handler handler, void *output, key_flags flags)
{
  FILE *file = fopen(path, "r");
  if (file == NULL)
  {
    char errorString[120];
    sprintf(errorString, "Unable to open path: %s", path);
    perror(errorString);
    return -1;
  }
  char line[MAX_LINE_LEN];
  while (fgets(line, sizeof line, file) != NULL)
  {
    conf_item *item = conf_parse_first_pass(line);
    if (item == NULL)
    {
      char errorString[120];
      sprintf(errorString, "Entity in invalid format, path: %s\n", path);
      perror(errorString);
      fclose(file);
      return -1;
    }
    key_flag flag = get_key_flag(item->key, flags);

    if (flag.key != NULL)
    {
      if (flag.is_multi == true)
      {
        conf_parse_multi(item);
      }
      handler(output, item);
    }
    free_conf_item(item);
  }
  fclose(file);
  return 0;
}

key_flag get_key_flag(char *key, key_flags flags)
{
  key_flag result = {NULL, false};
  for (int i = 0; i < flags.size; i++)
  {
    if (strcmp(flags.flags[i].key, key) == 0)
    {
      result = flags.flags[i];
      break;
    }
  }
  return result;
}

conf_item *new_conf_item()
{
  conf_item *result = (conf_item *)malloc(CONF_ITEM_SIZE);
  result->key = "";
  result->value = "";
  result->n_multivalues = 0;
  return result;
}

conf_item *new_conf_item_with_values(char *key, char *value, char *multivalue[], int n_multivalues)
{
  conf_item *item = new_conf_item();
  item->key = strdup(key);
  if (strcmp("", value))
    item->value = strdup(value);
  item->n_multivalues = 0;
  if (n_multivalues > 0)
  {
    item->n_multivalues = n_multivalues;
    for (int i = 0; i < n_multivalues; i++)
    {
      item->multivalue[i] = strdup(multivalue[i]);
    }
  }
  return item;
}

/*
 * free_conf_item: frees memory allocated to a conf_item struct.
 */
void free_conf_item(conf_item *item)
{
  if (item->key && strcmp("", item->key))
    free(item->key);
  if (item->value && strcmp("", item->value))
    free(item->value);
  // free multivalues if it has.
  if (item->n_multivalues > 0)
  {
    for (int i = 0; i < item->n_multivalues; i++)
    {
      free(item->multivalue[i]);
    }
  }
  free(item);
}

char *conf_item_to_string(conf_item *item)
{
  if (item->n_multivalues == 0)
  {
    // single value case
    char *result = (char *)malloc(strlen(item->key) + strlen(item->value) + 2);
    sprintf(result, "%s=%s", item->key, item->value);
    return result;
  }
  else
  {
    // multivalue case.
    char *multivalues_str = join(item->multivalue, item->n_multivalues, ",");
    char *result = (char *)malloc(strlen(multivalues_str) + strlen(item->key) + 20);
    sprintf(result, "%s=%s", item->key, multivalues_str);
    free(multivalues_str);
    return result;
  }
}

void copy_conf_item(conf_item *dest, conf_item *src)
{
  dest->key = strdup(src->key);
  if (strcmp("", src->value))
    dest->value = strdup(src->value);
  dest->n_multivalues = src->n_multivalues;
  for (int i = 0; i < src->n_multivalues; i++)
  {
    dest->multivalue[i] = strdup(src->multivalue[i]);
  }
}

int write_conf(void *input, conf_serializer serializer)
{
  serializable *s = serializer(input);
  FILE *file = fopen(s->path, "w");
  if (file == NULL)
  {
    char errorString[120];
    sprintf(errorString, "Unable to open file %s for writing", s->path);
    perror(errorString);
    return -1;
  }
  for (int i = 0; i < s->n_items; i++)
  {
    char *itemString = conf_item_to_string(s->items[i]);
    fprintf(file, "%s\n", itemString);
    free(itemString);
  }
  free_serializable(s);
  fclose(file);
  return 0;
}

serializable *new_serializable(char *path, conf_item *items[], int n_items)
{
  serializable *s = (serializable *)malloc(sizeof(serializable) + strlen(path) + n_items * CONF_ITEM_SIZE);
  s->path = path;
  s->n_items = n_items;
  for (int i = 0; i < n_items; i++)
  {
    s->items[i] = new_conf_item();
    copy_conf_item(s->items[i], items[i]);
    free_conf_item(items[i]);
  }
  return s;
}

char *serializable_to_string(serializable *s)
{
  char *result = malloc(1024 * sizeof(char));
  sprintf(result, "[path=%s,n_items=%d", s->path, s->n_items);
  for (int i = 0; i < s->n_items; i++)
  {
    strcat(result, ",");
    strcat(result, conf_item_to_string(s->items[i]));
  }
  strcat(result, "]");
  return result;
}

void free_serializable(serializable *s)
{
  free(s->path);
  for (int i = 0; i < s->n_items; i++)
  {
    free_conf_item(s->items[i]);
  }
  free(s);
}
