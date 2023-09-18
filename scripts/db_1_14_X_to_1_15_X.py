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
import json

sys.path.append("..")
sys.path.append(".")

from IM.InfrastructureList import InfrastructureList
from IM.InfrastructureInfo import InfrastructureInfo
from IM.db import DataBase
from IM.auth import Authentication


def get_data_from_db(db, inf_id):
    """
    Get data from DB.
    """

    if db.db_type == DataBase.MONGO:
        res = db.find("inf_list", {"id": inf_id}, {"data": True})
    else:
        res = db.select("select data from inf_list where id = %s", (inf_id,))

    if len(res) > 0:
        elem = res[0]
        if db.db_type == DataBase.MONGO:
            data = elem[data]
        else:
            data = elem[0]
        try:
            newinf = InfrastructureInfo()
            dic = json.loads(data)
            newinf.deleted = dic['deleted']
            newinf.id = dic['id']
            if dic['auth']:
                newinf.auth = Authentication.deserialize(dic['auth'])
            return newinf
        except Exception:
            print("ERROR reading infrastructure from database, ignoring it!.")
    else:
        return None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: %s <db_file>\n" % sys.argv[0])
        sys.exit(-1)

    DATA_DB = sys.argv[1]

    db = DataBase(DATA_DB)
    if db.connect():
        if db.table_exists("inf_list"):
            if db.db_type != DataBase.MONGO:
                sys.stdout.write("Updating DB: %s.\n" % DATA_DB)
                db.execute("ALTER TABLE `inf_list` ADD COLUMN `auth` BLOB;")

            infs = []
            for inf_id in InfrastructureList._get_inf_ids_from_db(get_all=True):
                try:
                    inf = get_data_from_db(db, inf_id)
                    print(inf_id)
                    if inf:
                        auth = inf.auth.serialize()
                        res = db.execute("UPDATE `inf_list` SET `auth` = %s WHERE id = %s", (auth, inf_id))
                except Exception as e:
                    sys.stderr.write("Error updating auth field in Inf ID: %s. Ignoring.\n" % inf_id)
        else:
            sys.stdout.write("There are no inf_list table. Do not need to update.")

        db.close()
    else:
        sys.stderr.write("Error connecting with DB: %s\n" % DATA_DB)
        sys.exit(-1)

    sys.exit(0)
