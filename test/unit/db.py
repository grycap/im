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
import os

from IM.db import DataBase
from mock import patch, MagicMock


class TestDataBase(unittest.TestCase):
    """
    Class to test the DataBase class
    """

    @patch('IM.db.mdb.connect')
    def test_db(self, mdb_conn):
        filename = "/tmp/inf.dat"
        if os.path.exists(filename):
            os.unlink(filename)
        db_url = "sqlite://" + filename
        db = DataBase(db_url)
        self.assertTrue(db.connect())
        if not db.table_exists("test"):
            db.execute("CREATE TABLE test(id int PRIMARY KEY, date TIMESTAMP, data LONGBLOB)")
        self.assertTrue(db.table_exists("test"))
        db.execute("insert into test (id, data, date) values (%s, %s, now())", (1, "Data"))
        res = db.select("select data from test where id = %s", (1,))
        self.assertEqual(res, [("Data",)])
        db.close()

        connection = MagicMock()
        mdb_conn.return_value = connection

        db_url = "mysql://username:password@server/db_name"
        db = DataBase(db_url)
        self.assertTrue(db.connect())
        if not db.table_exists("test"):
            db.execute("CREATE TABLE test(id int PRIMARY KEY, date TIMESTAMP, data LONGBLOB)")
        db.execute("insert into test (id, data, date) values (%s, %s, now())", (1, "Data"))

        cursor = MagicMock()
        cursor.fetchall.return_value = [("Data",)]
        connection.cursor.return_value = cursor
        res = db.select("select data from test where id = %s", (1,))
        self.assertEqual(res, [("Data",)])

        db.close()

if __name__ == '__main__':
    unittest.main()
