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

#include "snow.h"
#include "../conf_parser.h"

void NOP_READER(void *output, char *filename)
{
  printf("READ %s\n", filename);
}

describe(conf_parser)
{
  subdesc(conf_parse_line)
  {
    it("can parse a line with single value")
    {
      char test_line[] = "key1=the_value";
      conf_item *actual = conf_parse_line(test_line, false);
      asserteq("key1", actual->key);
      asserteq("the_value", actual->value);
      free_conf_item(actual);
    }

    it("can parse a line with multi values")
    {
      char test_line[] = "key1=value1,value2,value3";
      conf_item *actual = conf_parse_line(test_line, true);
      asserteq("key1", actual->key);
      asserteq("value1,value2,value3", actual->value);

      asserteq("value1", actual->multivalue[0]);
      asserteq("value2", actual->multivalue[1]);
      asserteq("value3", actual->multivalue[2]);
      asserteq(3, actual->n_multivalues);
      free_conf_item(actual);
    }

    it("can parse a line with empty value")
    {
      char test_line[] = "key1=";
      conf_item *actual = conf_parse_line(test_line, false);
      asserteq(actual->key, "key1");
      asserteq(actual->value, "");
      free_conf_item(actual);
    }
  }

  subdesc(get_key_flags)
  {
    key_flags flags = {
        {{"key_one", false}, {"key_two", true}},
        2};

    it("can find flag for given key")
    {
      key_flag flag_two = get_key_flag("key_two", flags);
      asserteq("key_two", flag_two.key);
      asserteq(flag_two.is_multi, true);
    }

    it("returns empty if it doesn't find key")
    {

      key_flag bad_flag = get_key_flag("key_inexistent", flags);
      asserteq(bad_flag.key, NULL);
    }
  }

  subdesc(conf_item_to_string)
  {
    it("should handle single value case")
    {
      char test_line[] = "key1=the_value";
      conf_item *item = conf_parse_line(test_line, false);
      char *actual_str = conf_item_to_string(item);
      asserteq(test_line, actual_str);
      free_conf_item(item);
      free(actual_str);
    }

    it("should handle multi value case")
    {
      char test_line[] = "key1=value1,value2,value3";
      conf_item *item = conf_parse_line(test_line, true);
      char *actual_str = conf_item_to_string(item);
      asserteq(test_line, actual_str);
      free_conf_item(item);
      free(actual_str);
    }
  }
}