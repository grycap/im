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

from IM.db import DataBase


if __name__ == "__main__":

    if len(sys.argv) != 3:
        sys.stderr.write("Usage: %s <MySQL uri> <MongoDB URI>\n" % sys.argv[0])
        sys.exit(-1)

    mydb = DataBase(sys.argv[1])
    mongodb = DataBase(sys.argv[2])
    if mydb.connect():
        if mydb.table_exists("inf_list"):
            if mydb.db_type not in DataBase.DB_TYPES:
                sys.stderr.write("First DB must be an Relational DB.\n")
                sys.exit(-1)

            if mongodb.connect():
                if mongodb.db_type != DataBase.MONGO:
                    sys.stderr.write("Second DB must be a MongoDB DB.\n")
                    sys.exit(-1)
            else:
                sys.stderr.write("Error connecting with DB: %s\n" % sys.argv[2])
                sys.exit(-1)

            res = mydb.select("select id, deleted, data, date, auth from inf_list order by rowid desc")
            for elem in res:
                ok = mongodb.replace("inf_list", {"id": elem[0]}, {"id": elem[0], "deleted": int(elem[1]),
                                                                   "data": elem[2], "date": elem[3],
                                                                   "auth": elem[4]})
                if ok:
                    sys.stdout.write("Inf ID: %s inserted.\n" % elem[0])
                else:
                    sys.stderr.write("Error inserting Inf ID: %s\n" % elem[0])

            mongodb.close()
        else:
            sys.stdout.write("There are no inf_list table.")
        mydb.close()
    else:
        sys.stderr.write("Error connecting with DB: %s\n" % sys.argv[1])
        sys.exit(-1)

    sys.exit(0)
