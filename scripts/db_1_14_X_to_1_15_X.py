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

from IM.InfrastructureList import InfrastructureList
from IM.db import DataBase


if __name__ == "__main__":
    DATA_DB= "sqlite:///etc/im/inf.dat"

    db = DataBase(DATA_DB)
    if db.connect():
        if db.table_exists("inf_list"):
            if db.db_type != DataBase.MONGO:
                sys.stdout.write("Updating DB: %s.\n" % DATA_DB)
                db.execute("ALTER TABLE `inf_list` ADD COLUMN `auth` BLOB;")

            infs = []
            for inf_id in InfrastructureList._get_inf_ids_from_db():
                res = InfrastructureList._get_data_from_db(DATA_DB, inf_id, True)
                if res:
                    auth = res[inf_id].auth.serialize()
                    res = db.execute("UPDATE `inf_list` SET `auth` = %s WHERE id = %s", (auth, inf_id))

            db.close()
        else:
            sys.stdout.write("There are no inf_list table. Do not need to update.")
    else:
        sys.stderr.write("Error connecting with DB: %s\n" % DATA_DB)
        sys.exit(-1)

    sys.exit(0)
