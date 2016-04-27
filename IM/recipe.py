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

from db import DataBase

from config import Config
from radl.radl import FeaturesApp


class Recipe:
    """ Class to access the recipes stored in the DB """

    def __init__(self, name, version, module, recipe, desc, requirements, galaxy_module=None, isapp=0):
        """ Recipe creator function """
        self.name = name
        self.version = version
        self.module = module
        self.recipe = recipe
        self.desc = desc
        self.requirements = requirements
        self.isapp = isapp
        self.galaxy_module = galaxy_module

    def insert(self):
        """ Recipe insert function """
        return Recipe.insertRecipe(self.name, self.version, self.module, self.recipe,
                                   self.isapp, self.galaxy_module, self.desc, self.requirements)

    @staticmethod
    def insertRecipe(name, version, module, recipe, desc, requirements, galaxy_module=None, isapp=0):
        """ Static method to insert a recipe in the DB """
        if not DataBase.db_available:
            return False
        else:
            try:
                db = DataBase(Config.RECIPES_DB_FILE)
                db.connect()

                res = db.execute('''insert into recipes values ("%s", "%s", "%s", "%s", %d, %d, "%s", "%s")''' % (
                    name, version, module, recipe, isapp, galaxy_module, desc, requirements))
                return res
            except Exception:
                return False

    @staticmethod
    def getRecipes():
        """ Static method to get the list of recipes """
        if not DataBase.db_available:
            return []
        else:
            try:
                db = DataBase(Config.RECIPES_DB_FILE)
                db.connect()

                res = []
                result = db.select('select * from recipes')
                for d in result:
                    name = d[0]
                    version = d[1]
                    modules = d[2].split(",")
                    recipe = d[3]
                    isapp = d[4]
                    galaxy_module = d[5]
                    desc = d[6]
                    requirements = d[7]
                    res.append(Recipe(name, version, modules, recipe,
                                      desc, requirements, galaxy_module, isapp))

                return res
            except Exception:
                return []

    @staticmethod
    def insertApp(name, version, module, recipe, galaxy_module=None, requirements=""):
        """ Static method to insert an app in the DB """
        return Recipe.insertRecipe(name, version, module, recipe, "Application " + name, requirements, galaxy_module, 1)

    @staticmethod
    def getInstallableApps():
        """ Static method to get the list of avalible apps """
        if not DataBase.db_available:
            return []
        else:
            try:
                db = DataBase(Config.RECIPES_DB_FILE)
                db.connect()

                res = []
                result = db.select('select * from recipes where isapp = 1')
                for d in result:
                    name = d[0]
                    version = d[1]
                    module = d[2]
                    recipe = d[3]
                    galaxy_module = d[5]
                    requirements = d[7]
                    res.append((FeaturesApp.from_str(name, version),
                                module, galaxy_module, recipe, requirements))

                return res
            except Exception:
                return []

    @staticmethod
    def getInfoApps(apps_to_install):
        modules = []
        recipes = []
        for app_to_install in apps_to_install:
            recipe_app = None
            for app_avail, _, galaxy_module, recipe, _ in Recipe.getInstallableApps():
                if app_avail.isNewerThan(app_to_install):
                    modules.append(galaxy_module)
                    recipe_app = recipe
                    break
            recipes.append((app_to_install.getValue("name"), recipe_app))
        return (modules, recipes)
