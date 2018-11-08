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

sys.path.append("..")
sys.path.append(".")

from IM.config import Config
from IM.db import DataBase


if __name__ == "__main__":
    if not Config.DATA_DB:
        sys.stderr.write("No DATA_DB defined in the im.cfg file!!")
        sys.exit(-1)

    db = DataBase(Config.DATA_DB)
    if db.connect():
        if db.table_exists("inf_list"):
            if db.db_type == DataBase.MYSQL:
                sys.stdout.write("Updating DB: %s.\n" % Config.DATA_DB)
                db.execute("ALTER TABLE `inf_list` ADD COLUMN `rowid` INT AUTO_INCREMENT UNIQUE FIRST;")
            else:
                sys.stdout.write("SQLite DB does not need to be updated.")
            db.close()
        else:
            sys.stdout.write("There are no inf_list table. Do not need to update.")
    else:
        sys.stderr.write("Error connecting with DB: %s\n" % Config.DATA_DB)
        sys.exit(-1)

    sys.exit(0)
