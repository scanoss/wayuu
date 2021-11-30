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
  * @file log.c
  * @date 11 Jul 2020 
  * @brief Contains helper functions for logging
  */

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "log.h"

static const char *level_names[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"};

/**
 * @brief Default log level is INFO
 */
static int LEVEL = LOG_INFO;

/**
 * @brief Default log file is STDERR
 */
static FILE *LOG_FILE = NULL;

/**
 * @brief Gets the current UTC time
 * Example: 30-11-21 00:08:36
 * 
 * @return char* A string with the current UTC time
 */
char *format_timestamp()
{
  // I. Format timestamp
  // Always use UTC time
  char *out = malloc(64);
  time_t t = time(NULL);
  struct tm *utc = gmtime(&t);
  strftime(out, 64, "%d-%m-%y %H:%M:%S", utc);
  return out;
}

/**
 * @brief Formats UTC timestamp in common log format.
 * Example: 30/Nov/2021:00:10:02 +0000
 * @return char* A string with the UTC timestamp in common log format
 */
char *format_ts_common_log()
{
  //%d/%b/%Y:%H:%M:%S %z
  char *out = malloc(64);
  time_t t = time(NULL);
  struct tm *utc = gmtime(&t);
  strftime(out, 64, "%d/%b/%Y:%H:%M:%S %z", utc);
  return out;
}
/**
 * @brief Writes a log message to the log file.
 * 
 * @param level Log level
 * @param file  
 * @param line 
 * @param func 
 * @param format 
 * @param ... 
 */
void __logger(int level, const char *file, int line, const char *func, const char *format, ...)
{
  if (level < LEVEL)
  {
    return;
  }

  if (LOG_FILE == NULL)
  {
    LOG_FILE = stderr;
  }

  char *buf = format_timestamp();
  va_list args;

  // II. Format log
  fprintf(LOG_FILE, "%s %lu %-5s %s:%s:%d: ", buf, pthread_self(), level_names[level], file, func, line);
  va_start(args, format);
  vfprintf(LOG_FILE, format, args);
  va_end(args);
  fprintf(LOG_FILE, "\n");
  fflush(LOG_FILE);
  free(buf);

  // Exit with error if log level is FATAL
  if (level == LOG_FATAL)
  {
    exit(EXIT_FAILURE);
  }
}

/**
 * @brief Verify the actual log level
 * 
 * @param level See enum log_level in log.c
 * @return true if the level passed as parameter is equal or greater than the actual log level
 */
bool log_level_is_enabled(int level)
{
  return level >= LEVEL;
}

/**
 * @brief Sets the log level
 * 
 * @param level See enum log_level in log.c
 */
void log_set_level(int level)
{
  LEVEL = level;
}

/**
 * @brief Opens the log file
 * 
 * @param filename Path to the filename
 */
void log_set_file(char *filename)
{
  LOG_FILE = fopen(filename, "a+");
  if (LOG_FILE == NULL)
  {
    fprintf(stderr, "ERROR SETTING LOG FILE: %s\n", filename);
    exit(EXIT_FAILURE);
  }
}

/**
 * @brief Closes the log file
 * 
 */
void log_close_file()
{
  fclose(LOG_FILE);
}
