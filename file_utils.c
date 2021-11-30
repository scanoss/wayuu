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
  * @file file_utils.c
  * @date 11 Jul 2020 
  * @brief Contains helper functions for file operations.
  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "log.h"
#include "file_utils.h"

/**
 * @brief Opens a file and search for a string.
 * 
 * 
 * @param path Path to the file.
 * @param needle String to search.
 * @return true String found, false String not found or path not found.
 */
bool find_in_file(char *path, char *needle)
{

  if (!is_file(path))
  {
    return false;
  }

  bool result = false;

  char *haystack = calloc(8192, 1);
  read_file(haystack, path, 0);

  if (strstr(haystack, needle))
    result = true;

  free(haystack);
  return result;
}

/**
 * @brief Check if a directory exists, if not create it.
 * @param path path to the directory.
 * @return true Directory created. False Directory not created.
 */
bool check_createdir(char *path)
{
  if (!is_dir(path) && mkdir(path, 0755))
  {
    return false;
  }
  return true;
}

/**
 * @brief Verify if the path exists and is a directory.
 * 
 * @param path Path to the directory.
 * @return true Path is a directory, false if Path is not a directory or does not exist.
 */

bool is_dir(char *path)
{

  struct stat pstat;
  if (!stat(path, &pstat))
    if (S_ISDIR(pstat.st_mode))
      return true;
  return false;
}

/**
 * @brief Verify if the path exists and is a file.
 * 
 * @param path Path to the file.
 * @return true Path is a file, false if Path is not a file or does not exist.
 */
bool is_file(char *path)
{
  struct stat pstat;
  if (!stat(path, &pstat))
    if (S_ISREG(pstat.st_mode))
      return true;
  return false;
}
/**
 * @brief Reads a file into a buffer.
 * 
 * @param out Buffer to store the content of the file.
 * @param path Path to the file.
 * @param maxlen Max length of the buffer.
 */
void read_file(char *out, char *path, uint64_t maxlen)
{

  char *src;
  uint64_t length = 0;
  out[0] = 0;

  if (!is_file(path))
  {
    log_error("File not found: %s", path);
    return;
  }

  FILE *file = fopen(path, "rb");
  if (file)
  {
    fseek(file, 0, SEEK_END);
    length = ftell(file);
    fseek(file, 0, SEEK_SET);
    src = calloc(length, 1);
    if (src)
    {
      fread(src, 1, length, file);
    }
    fclose(file);
    if (maxlen > 0)
      if (length > maxlen - 1)
        length = maxlen - 1;
    memcpy(out, src, length);
    out[length] = 0;
    free(src);
  }
}

/**
 * @brief Write a buffer to a file.
 * 
 * @param path Path to the file. If the file exists it will be overwritten.
 * @param buffer Buffer to write.
 * @param length Length of the buffer.
 */
void write_file(char *filename, char *ptr, int size)
{
  log_debug("write_file(filename=%s, strlen(ptr)=%d, size=%d)", filename, strlen(ptr), size);
  if (is_file(filename))
  {
    remove(filename);
  }
  FILE *f = fopen(filename, "wb+");
  if (f == NULL)
  {
    log_error("There was an error opening file: %s", filename);
    return;
  }
  size_t written = fwrite(ptr, 1, size, f);
  if (written < 1)
  {
    log_error("There was an error writing file: %s", filename);
  }
  fclose(f);
}
