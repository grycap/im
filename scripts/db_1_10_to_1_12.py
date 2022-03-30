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

import sys
import time

sys.path.append("..")
sys.path.append(".")

from IM.db import DataBase


class DB110to112():

    @staticmethod
    def save_data(db_url, inf_list):
        """ Save Data to file """
        try:
            InfrastructureList.init_table(db_url)
            InfrastructureList._save_data_to_db(db_url, inf_list)
        except Exception as ex:
            sys.stderr.write("ERROR saving data: " + str(ex) + ".")
            sys.exit(-1)

    @staticmethod
    def load_data(db_url):
        """ Load Data from DB"""
        try:
            return InfrastructureList._get_data_from_db(db_url, all=True)
        except Exception as ex:
            sys.stderr.write("ERROR loading data: " + str(ex) + ".\nCorrect or delete it!! ")
            sys.exit(-1)

    @staticmethod
    def rename_old_data(db_url, now):
        db = DataBase(db_url)
        if db.connect():
            if db.table_exists("inf_list"):
                if db.db_type == DataBase.SQLITE:
                    db.execute('ALTER TABLE inf_list RENAME TO inf_list_%s;' % now)
                    db.close()
                elif db.db_type == DataBase.MYSQL:
                    db.execute('RENAME TABLE inf_list TO inf_list_%s;' % now)
                    db.close()
                else:
                    db.close()
                    sys.stderr.write("ERROR connecting with the database!.")
                    sys.exit(-1)
            else:
                db.close()
        else:
            sys.stderr.write("ERROR connecting with the database!.")
            sys.exit(-1)


if __name__ == "__main__":
    db_url = None
    if len(sys.argv) > 1:
        db_url = sys.argv[1]
    else:
        from IM.config import Config
        db_url = Config.DATA_DB

    sys.stdout.write("Updating IM DB at %s.\n" % db_url)

    from IM.InfrastructureList import InfrastructureList

    sys.stdout.write("Loading Data...\n")
    inf_list = DB110to112.load_data(db_url)
    if inf_list:
        now = str(int(time.time() * 100))
        sys.stdout.write("Previous table inf_list will be renamed to inf_list_%s.\n" % now)
        DB110to112.rename_old_data(db_url, now)
        # To create the new table
        sys.stdout.write("Saving Data...\n")
        DB110to112.save_data(db_url, inf_list)
