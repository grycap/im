#! /usr/bin/env python
#
# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import unittest
import time

from IM.recipe import Recipe
from IM.config import Config
from mock import patch, MagicMock


class TestRecipe(unittest.TestCase):
    """
    Class to test the Recipe class
    """
    @patch("IM.recipe.DataBase")
    def test_recipe(self, DataBase):
        DataBase.db_available = True
        db = MagicMock()
        DataBase.return_value = db

        recipe = Recipe("app", "1.0", "mod", "rec", "desc", "req")
        db.execute.return_value = True
        res = recipe.insert()
        self.assertEqual(res, True)

        db.select.return_value = [("app", "1.0", "mod", "rec", 0, "gmod", "desc", "req")]
        res = Recipe.getRecipes()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].name, "app")
        self.assertEqual(res[0].version, "1.0")

        db.select.return_value = [("app", "1.0", "mod", "rec", 1, "gmod", "desc", "req")]
        res = Recipe.getInstallableApps()
        self.assertIn(str(res[0][0]), ["version = '1.0' and\nname = 'app'", "name = 'app' and\nversion = '1.0'"])
        self.assertEqual(res[0][1], "mod")
        self.assertEqual(res[0][2], "gmod")

if __name__ == '__main__':
    unittest.main()
