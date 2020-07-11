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

#include <stddef.h>
#include "snow.h"
#include "../string_utils.h"
#include "../ws.h"

describe(string_utils)
{
  subdesc(join)
  {
    it("joins an array comma-separated")
    {
      char *array[3] = {"test1", "test2", "test3"};
      char *actual_str = join(array, 3, ",");
      asserteq(actual_str, "test1,test2,test3");
      free(actual_str);
    }
    it("returns empty string for null array")
    {
      char *actual_str = join(NULL, 3, ",");
      asserteq(actual_str, "");
    }
    it("behaves well on nasty join")
    {
      char *array[1] = {NULL};
      char *actual_str = join(array, 3, ",");
      asserteq(actual_str, "");
    }
  }

  subdesc(split)
  {
    it("splits comma-separated string")
    {
      char *str = "one,two,three";
      str_list_t *splits = split(str, ",");
      asserteq(splits->n_str, 3);
      asserteq(splits->strings[0], "one");
      asserteq(splits->strings[1], "two");
      asserteq(splits->strings[2], "three");
      free_str_list_t(splits);
    }

    it("handles string without separator")
    {
      char *str = "one";
      str_list_t *splits = split(str, ",");
      asserteq(splits->n_str, 1);
      asserteq(splits->strings[0], "one");
      free_str_list_t(splits);
    }

    it("handles empty string")
    {
      str_list_t *splits = split("", ",");
      asserteq(splits->n_str, 0);
      free_str_list_t(splits);
    }

    it("handles a very long string")
    {
      str_list_t *splits = split("onetwothreefouraverylongstring really reallylong trueeeeeeeeeeeeeeeeeeeeeee,fffffffffffffffffffffffffffffffffffffff,adsfjdfjaldfjasljffasfdsafdafdfasfkadfasdfasfafafasfasfsafdasfdasfdfasfasfasfas", ",");
      asserteq(splits->n_str, 3);
      asserteq(splits->strings[0], "onetwothreefouraverylongstring really reallylong trueeeeeeeeeeeeeeeeeeeeeee");
      asserteq(splits->strings[1], "fffffffffffffffffffffffffffffffffffffff");
      asserteq(splits->strings[2], "adsfjdfjaldfjasljffasfdsafdafdfasfkadfasdfasfafafasfasfsafdasfdasfdfasfasfasfas");
      free_str_list_t(splits);
    }
  }

  subdesc(split_once)
  {
    it("splits only once")
    {
      str_list_t *splits = split_once("Referer :  http://www.example.com:4444/test", ":");
      asserteq(splits->n_str, 2);
      asserteq(splits->strings[0], "Referer");
      asserteq(splits->strings[1], "http://www.example.com:4444/test");
      free_str_list_t(splits);
    }
  }

  subdesc(startswith)
  {
    it("returns true if string starts with substring")
    {
      assert(startswith("one two three", "one"));
    }

    it("returns false if string does not start with substring")
    {
      asserteq(startswith("one two three", "four"), false);
    }
  }

  subdesc(startswithany)
  {
    const char *list[3] = {"three", "four", ""};
    it("returns true if string starts with substring")
    {
      assert(startswithany("four in a row", list));
    }

    it("returns false if string does not start with substring")
    {
      asserteq(startswithany("six this time", list), false);
    }

    it("Returns false for HEAD method")
    {
      asserteq(startswithany("HEAD", ALLOWED_HTTP_METHODS), false);
    }
  }

  subdesc(rtrim)
  {
    it("returns substring")
    {
      char *str = "One;Two";
      char *str2 = rtrim(str, ';');
      asserteq(str2, "One");
      free(str2);
    }

    it("returns same string if no sep found")
    {
      char *str = "One;Two";
      char *str2 = rtrim(str, '.');
      asserteq(str2, str);
      free(str2);
    }
  }

  subdesc(trim)
  {
    it("trims whitespaces left and right")
    {
      char *str = strdup(" A string  ");
      trim(str);
      asserteq(str, "A string");
      free(str);
    }
  }
}
