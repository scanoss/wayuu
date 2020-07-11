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
#include <string.h>
#include "snow.h"

#include "../log.h"
#include "../ws.h"
#include "../http_utils.h"
#include "../string_utils.h"
#include "../file_utils.h"
#include "test_mocks.h"

void url_decode(char *dest, const char *src)
{

  const char *p = src;
  char code[3] = "\0";
  unsigned long ascii = 0;
  char *end = NULL;

  while (*p)
    if (*p == '%')
    {
      memcpy(code, ++p, 2);
      ascii = strtoul(code, &end, 16);
      *dest++ = (char)ascii;
      p += 2;
    }
    else
      *dest++ = *p++;

  dest[0] = 0;
}

void extract_tag(char *out, char *tag, char *in, long max_len)
{
  out[0] = 0;

  if (!in || in[0] == 0)
  {
    // Uninitialized string
    return;
  }

  /* Exit in case data exceeds limit */
  if (strlen(in) > max_len)
  {
    return;
  }

  char *ptr = strdup(in);

  char *tg = calloc(strlen(tag) + 2, 1);
  char *tmpout = malloc(max_len);
  sprintf(tg, "%s=", tag);
  bool done = false;

  int moves = 0;
  while (strlen(ptr) > 0 && !done)
  {

    /* Found the tag */
    if (strncmp(tg, ptr, strlen(tg)) == 0)
    {
      strcpy(out, ptr + strlen(tg));
      /* Trim remaining parameters */
      for (int i = 0; i <= strlen(out); i++)
      {
        if (out[i] == '&' || out[i] == '\0')
        {
          out[i] = '\0';
          break;
        }
      }
      done = true;
    }

    /* Move to after next & or to \0 */
    else
    {

      for (int i = 0; i <= strlen(ptr); i++)
      {
        if (ptr[i] == '&')
        {
          ptr += i + 1;
          moves += i + 1;
          break;
        }
        if (ptr[i] == '\0')
        {
          done = true;
          break;
        }
      }
    }
  }
  // Reset pointer to initial position before freeing it.
  ptr -= moves;
  free(ptr);
  trim(out);
  strcpy(tmpout, out);
  url_decode(out, tmpout);
  free(tmpout);
  free(tg);
}

describe(ws)
{

  subdesc(part_parse)
  {
    it("parse part and save tmp file")
    {
      check_createdir(FILE_DOWNLOAD_TMP_DIR);
      char *test_part = "Content-Disposition: form-data; name=\"uploadedfile\"; filename=\"hello.txt\"\r\nContent-Type: text/plain\r\n\r\nThis is an example\r\n";

      char *tmpfields = calloc(strlen(test_part) + 1, 1);
      part_parse("0.0.0.0", tmpfields, test_part, strlen(test_part));
      log_info("tmpfields: %s", tmpfields);
      char *uploadedfile = calloc(1024, 1);
      char *tmpfile = calloc(1024, 1);

      extract_tag(uploadedfile, "uploadedfile", tmpfields, 1024);

      log_info("uploadedfile: %s", uploadedfile);
      extract_tag(tmpfile, "tmpfile", tmpfields, 1024);
      log_info("tmpfile: %s", tmpfile);

      asserteq(uploadedfile, "hello.txt");
      assert(strcmp(tmpfile, ""));
      free(tmpfile);
      free(uploadedfile);
      free(tmpfields);
    }
  }

  subdesc(allowed_address)
  {
    it("Returns false if address not in etc/allow")
    {
      strcpy(WAYUU_WS_ROOT, "/tmp");
      check_createdir("/tmp/etc");
      char *allowed = "127.0.0.1";
      write_file("/tmp/etc/allow", allowed, strlen(allowed));
      assert(allowed_address("127.0.0.1"));
      assert(!allowed_address("140.12.13.11"));
    }
  }
}