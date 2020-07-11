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
#include "../json_utils.h"

describe(json_utils)
{
  subdesc(json_array_of_strings)
  {
    it("return a valid json array")
    {
      char *array[3] = {"uno", "dos", "tres"};
      char *json = json_array_of_strings(array, 3);
      asserteq(json, "[\"uno\",\"dos\",\"tres\"]");
      free(json);
    }

    it("returns empty array for empty array")
    {
      char *array[0];
      char *json = json_array_of_strings(array, 0);
      asserteq(json, "[]");
      free(json);
    }
  }

  subdesc(json_array_of_entities)
  {
    it("returns empty array if empty list")
    {
      json_list_t list;
      list.size = 0;
      char *json = json_array_of_entities(list);
      asserteq(json, "[]");
      free(json);
    }
  }

  subdesc(json_array_of_ints)
  {
    it("Returns an array of ints")
    {
      int array[] = {1, 2, 3};
      char *json = json_array_of_ints(array, 3);
      asserteq(json, "[1,2,3]");
      free(json);
    }
    it("works for array with single element")
    {
      int array[] = {1};
      char *json = json_array_of_ints(array, 1);
      asserteq(json, "[1]");
      free(json);
    }

    it("Returns correct array with sizes")

    {
      int array[] = {11, 22, 33, 44, 55, 444, 6666, 777};
      char *json = json_array_of_ints(array, 4);
      asserteq(json, "[11,22,33,44]");
      free(json);
    }
  }
}