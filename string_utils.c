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
  * @file string_utils.c
  * @date 24 Nov 2021
  * @brief Implements a simple routing framework for the API.
  */

#include <stdint.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "log.h"
#include "string_utils.h"

/**
 * @brief Chops string at the next character less than 34 ASCII ('"')
 * 
 * @param data Pointer to the string. Must be NULL terminated
 */
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

/**
 * @brief Eliminates leading and trailing spaces
 * 
 * @param str String ending with null character
 */
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
 * @brief Returns a substring of the original string until the first occurrence of the character 'sep'
 * 
 * @param str String ending with null character
 * @param sep Character to search for
 * @return char* Pointer to the substring
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
 * @brief Returns a substring of the original string from the first occurrence of character 'sep'
 * 
 * @param str String ending with null character
 * @param sep Character to search for
 * @return char* Pointer to the substring
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

/**
 * @brief Returns a hex representation of the MD5 of the input 'data' string.
 * 
 * @param out pointer to the output buffer
 * @param data data to hash
 * @param len length of data
 */
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

/**
 * @brief  Returns a dynamically allocated string with all the elements 
 * separated by the delimiter specified.
 * 
 * Ex: { "test1" , "test2" , "test3" } -> "test1,test2,test3"
 * 
 * @IMPORTANT: The returned string must be freed by the caller
 * 
 * @param array array of strings 
 * @param size number of elements in the array 
 * @param delim delimiter to use 
 * @return char* 
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

/**
 * @brief Divides a string into a list of substrings, 
 * puts these substrings into an array, and returns the array
 * 
 * Ex: "test1,test2,test3" -> { "test1" , "test2" , "test3" } (str_list_t)
 * 
 * @param str String to split
 * @param delim Delimiter to use
 * @return str_list_t* Struct with all the values separated by the delimiter
 */
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

/**
 * @brief Variant of split, only splits at most once the string by the separator.
 * 
 * @param str  
 * @param delim  
 * @return str_list_t* 
 */

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

/**
 * @brief Free the memory allocated by split
 * 
 * @param list Points to the struct returned by split
 */
void free_str_list_t(str_list_t *list)
{
  for (int i = 0; i < list->n_str; i++)
  {
    free(list->strings[i]);
  }
  free(list);
}

/**
 * @brief Verify if a string starts with a prefix. 
 * 
 * @param str String to check.
 * @param prefix Prefix to check.
 * 
 * @return true if str starts with prefix. False otherwise.
 */
bool startswith(char *str, const char *prefix)
{
  return strncasecmp(str, prefix, strlen(prefix)) == 0;
}

/**
 * @brief Checks if any of the strings in the list is contained in the string.
 * 
 * @returns true if there is a match, false otherwise.
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
 * @brief Returns position in haystack right after end of needle, or -1 if not found
 * 
 * @param haystack Main text 
 * @param needle Substring to search for.
 * @param start Position to start searching the needle in the haystack. 0 to search from the beginning.
 * @param bytes Length of the haystack.
 * @return long Returns position in haystack right after end of needle, or -1 if not found 
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

/**
 * @brief Checks whether the argument passed has only an alphanumeric character or not.
 * 
 * @param data Data to check
 * @return true if the data has only alphanumeric characters. False otherwise.
 */
bool string_isalnum(char *data)
{

  if (data[0] == 0)
    return false;

  for (int i = 0; i < strlen(data); i++)
    if (!isalnum(data[i]))
      return false;

  return true;
}
