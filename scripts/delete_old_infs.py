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
import datetime

sys.path.append("..")
sys.path.append(".")

from IM.config import Config
from IM.db import DataBase


class DeleteInfs():

    @staticmethod
    def delete_data_from_db(db_url, date):
        db = DataBase(db_url)
        if db.connect():
            db.execute("DELETE FROM inf_list WHERE deleted = 1 and date < '%s';" % date)
            db.close()
        else:
            sys.stderr.write("ERROR connecting with the database!.")
            sys.exit(-1)

if __name__ == "__main__":
    if not Config.DATA_DB:
        sys.stderr.write("No DATA_DB defined in the im.cfg file!!\n")
        sys.exit(-1)

    sys.stdout.write("Deleting old data from DB: %s.\n" % Config.DATA_DB)

    date = None
    if len(sys.argv) > 1:
        date = sys.argv[1]
        date = date.replace("/", "-")
        parts = date.split("-")
        try:
            year = int(parts[0])
            month = int(parts[1])
            day = int(parts[2])
            datetime.date(year, month, day)
        except:
            sys.stdout.write("Incorrect date format (YYYY-MM-DD).\n")
            sys.exit(1)
    else:
        sys.stdout.write("No Date specified.\n")
        sys.exit(1)

    DeleteInfs.delete_data_from_db(Config.DATA_DB, date)
