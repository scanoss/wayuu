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

#include <stdint.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "log.h"
#include "string_utils.h"

void chop_string(char *data)
{
  int len = strlen(data);
  for (int i = 0; i < len; i++)
  {
    if (data[i] <= 34)
    {
      data[i] = 0;
      break;
    }
  }
}

void trim(char *str)
{
  int i = 0;

  /* Left trim */
  int len = strlen(str);
  for (i = 0; i < len; i++)
    if (!isspace(str[i]))
      break;
  if (i) {
    memmove(str, str + i, strlen(str + i));
    str[strlen(str + i)] = 0;
  }
  /* Right trim */
  len = strlen(str);
  for (i = len - 1; i >= 0; i--)
    if (!isspace(str[i]))
      break;
  str[i + 1] = 0;
}

/**
 * rtrim: Returns a subtring of the original string until the first occurrence of the character 'sep'.
 */
char *rtrim(const char *str, char sep)
{
  char *str2 = strdup(str);
  for (int i = 0; i < strlen(str2); i++)
  {
    if (str2[i] == sep)
    {
      str2[i] = 0;
    }
  }
  return str2;
}

/**
 * ltrim: Returns a substring of the original string from the first occurrence of character 'sep'
 */
char *ltrim(const char *str, char sep)
{

  for (int i = 0; i < strlen(str); i++)
  {
    if (str[i] == sep)
    {
      return strdup(str + i + 1);
    }
  }
  return strdup(str);
}

void md5sum(char *out, char *data, int len)
{

  int i;
  MD5_CTX c;
  unsigned char digest[16];
  char *md5;
  md5 = malloc(33);
  md5[0] = 0;
  MD5_Init(&c);
  while (len > 0)
  {
    if (len > 512)
    {
      MD5_Update(&c, data, 512);
    }
    else
    {
      MD5_Update(&c, data, len);
    }
    data += 512;
    len -= 512;
  }
  MD5_Final(digest, &c);
  for (i = 0; i < 16; ++i)
    snprintf(&(md5[i * 2]), 32, "%02x", (unsigned int)digest[i]);
  memcpy(out, md5, 32);
  out[32] = 0;
  free(md5);
}

/*
 * join: returns a dynamically allocated string with all the elements separated by the delimiter specified.
 */
char *join(char **array, int size, char *delim)
{
  if (array == NULL || size <= 0 || array[0] == NULL)
  {
    return "";
  }
  if (size == 1)
  {
    return strdup(array[0]);
  }
  int str_len = 0;
  for (int i = 0; i < size; i++)
  {
    if (array[i] != NULL)
      str_len += strlen(array[i]);
  }
  str_len += size * strlen(delim) + 1;
  char *joined_str = calloc(str_len, sizeof(char));
  char *tmp;
  for (int i = 0; i < size - 1; i++)
  {
    if (array[i] != NULL)
    {
      tmp = strdup(array[i]);
      strcat(joined_str, tmp);
      free(tmp);
      strcat(joined_str, delim);
    }
  }
  tmp = strdup(array[size - 1]);
  strcat(joined_str, tmp);
  free(tmp);
  return joined_str;
}

str_list_t *split(char *str, char *delim)
{
  char *str_copy = strdup(str);
  int n_tokens = 0;
  str_list_t *result = malloc(sizeof(result) + (MAX_SPLIT_STR + 1) * MAX_SPLIT_STR_LEN);
  char *token = strtok(str_copy, delim);

  while (token != NULL)
  {
    result->strings[n_tokens] = malloc(MAX_SPLIT_STR_LEN);
    strncpy(result->strings[n_tokens], token, MAX_SPLIT_STR_LEN - 1);

    token = strtok(NULL, delim);
    n_tokens++;
  }

  result->n_str = n_tokens;
  free(token);
  free(str_copy);
  return result;
}

str_list_t *split_once(char *str, char *delim)
{

  str_list_t *result = malloc(sizeof(result) + (2 + 1) * MAX_SPLIT_STR_LEN);
  result->strings[0] = malloc(MAX_SPLIT_STR_LEN);
  char *first = rtrim(str, ':');
  trim(first);
  strncpy(result->strings[0], first, MAX_SPLIT_STR_LEN - 1);
  char *second = ltrim(str, ':');
  if (strlen(second) < strlen(str))
  {
    trim(second);
    result->strings[1] = malloc(MAX_SPLIT_STR_LEN);
    strncpy(result->strings[1], second, MAX_SPLIT_STR_LEN - 1);
    result->n_str = 2;
  }
  else
  {
    result->n_str = 1;
  }

  free(first);
  free(second);
  return result;
}

void free_str_list_t(str_list_t *list)
{
  for (int i = 0; i < list->n_str; i++)
  {
    free(list->strings[i]);
  }
  free(list);
}

/**
 * startswith: Returns true if str starts with prefix.
 */
bool startswith(char *str, const char *prefix)
{
  return strncasecmp(str, prefix, strlen(prefix)) == 0;
}

/**
 * startswithany: Checks if any of the strings in the list is contained in the string and returns true
 * otherwise it returns false.
 *
 * IMPORTANT: list has to be an array of strings with the last element an empty string, "". This saves having to add
 * an extra argument with the size of the array.
 */
bool startswithany(char *str, const char *list[])
{
  int i = 0;
  const char *prefix = list[0];
  while (prefix != NULL && strcmp(prefix, ""))
  {
    if (startswith(str, prefix))
    {
      return true;
    }
    i++;
    prefix = list[i];
  }
  return false;
}

/**
 * text_find_after: Returns position in haystack right after end of needle, or -1 if not found 
 */
long text_find_after(char *haystack, char *needle, long start, long bytes)
{

  int l = strlen(needle);
  for (long i = start; i < bytes; i++)
  {
    bool found = true;
    for (int b = 0; b < l; b++)
    {
      if (haystack[i + b] != needle[b])
      {
        found = false;
        break;
      }
    }
    if (found)
      return (i + strlen(needle));
  }

  return -1;
}

bool string_isalnum(char *data)
{

  if (data[0] == 0)
    return false;

  for (int i = 0; i < strlen(data); i++)
    if (!isalnum(data[i]))
      return false;

  return true;
}
