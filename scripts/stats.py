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

import os.path
import sys
import datetime

sys.path.append("..")
sys.path.append(".")

import json
import yaml
from IM.db import DataBase
from IM.auth import Authentication


class Stats():

    def get_data(str_data):
        dic = json.loads(str_data)
        creation_date = ''
        if 'creation_date' in dic and dic['creation_date']:
            creation_date = datetime.datetime.fromtimestamp(float(dic['creation_date']))
        auth = Authentication.deserialize(dic['auth'])
        icon = ""
        im_user = auth.getAuthInfo("InfrastructureManager")[0].get('username', "")
        if 'extra_info' in dic and dic['extra_info'] and "TOSCA" in dic['extra_info']:
            try:
                tosca = yaml.safe_load(dic['extra_info']['TOSCA'])
                icon = tosca.get("metadata", {}).get("icon", "")
                icon = os.path.basename(icon)[:-4]
            except Exception as ex:
                print("Error loading TOSCA: %s" & ex)
        return icon, im_user, creation_date

    @staticmethod
    def get_stats(db_url, date):
        stats = [("Inf ID.", "TOSCA", "User", "Creation Date", "Last Date")]
        db = DataBase(db_url)
        if db.connect():
            res = db.select("SELECT data, date, id FROM inf_list WHERE date > %s order by rowid desc;", (date,))
            for elem in res:
                data = elem[0]
                date = elem[1]
                inf_id = elem[2]
                icon, im_user, creation_date = Stats.get_data(data.decode())
                stats.append((inf_id, icon, im_user, str(creation_date), str(date)))

            db.close()
            return stats
        else:
            sys.stderr.write("ERROR connecting with the database!.\n")
            return None


if __name__ == "__main__":
    date = None
    im_db = "mysql://user:pass@mysql_server/im-db"
    if len(sys.argv) > 2:
        im_db = sys.argv[1]
        date = sys.argv[2]
        date = date.replace("/", "-")
        parts = date.split("-")
        try:
            year = int(parts[0])
            month = int(parts[1])
            day = int(parts[2])
            datetime.date(year, month, day)
        except Exception:
            sys.stdout.write("Incorrect date format (YYYY-MM-DD).\n")
            sys.exit(1)
    elif len(sys.argv) > 1:
        im_db = sys.argv[1]
        date = "2021-01-01"
    else:
        sys.stderr.write("IM DB connection URI must be prvided.\n")
        sys.exit(-1)

    res = Stats.get_stats(im_db, date)
    if res is None:
        sys.exit(-1)
    else:
        for elem in res:
            print(";".join(elem))
