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

    def test_sqlite_db(self):
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
        db.executemany("insert into test (id, data, date) values (%s, %s, now())",
                       [(2, "Data"), (3, "Data2")])
        res = db.select("select count(id) from test")
        self.assertEqual(res, [(3,)])
        db.close()

    @patch('IM.db.mdb.connect')
    def test_mysql_db(self, mdb_conn):
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

        db.executemany("insert into test (id, data, date) values (%s, %s, now())",
                       [(2, "Data"), (3, "Data2")])

        db.close()

    @patch('IM.db.MongoClient')
    def test_mongo_db(self, mongo):
        client = MagicMock()
        mongo.return_value = client
        database = MagicMock()
        client.__getitem__.return_value = database
        database.client = client
        table = MagicMock()
        database.__getitem__.return_value = table
        table.database = database

        db_url = "mongodb://username:password@server/db_name"
        db = DataBase(db_url)
        self.assertTrue(db.connect())

        database.list_collection_names.return_value = ['table1']
        res = db.table_exists("test")
        self.assertFalse(res)
        res = db.table_exists("table1")
        self.assertTrue(res)

        res = db.replace('table', {}, {'id': 1, 'data': 'test1'})
        self.assertTrue(res)
        self.assertEqual(table.replace_one.call_args_list[0][0], ({}, {'data': 'test1', 'id': 1}, True))

        res = db.update('table', {'id': 1}, {'data': 'test1'})
        self.assertTrue(res)
        self.assertEqual(table.update_one.call_args_list[0][0], ({'id': 1}, {'data': 'test1'}, True))

        table.find.return_value = [{'id': 2, 'data': 'test2', '_id': 2}]
        res = db.find('table', {'id': 2}, {'data': True})
        self.assertEqual(len(res), 1)
        self.assertEqual(table.find.call_args_list[0][0], ({'id': 2}, {'_id': False, 'data': True}))

        del_res = MagicMock()
        del_res.deleted_count = 1
        table.delete_many.return_value = del_res
        res = db.delete('table', {'id': 1})
        self.assertEqual(res, 1)
        self.assertEqual(table.delete_many.call_args_list[0][0], ({'id': 1},))

        db.close()


if __name__ == '__main__':
    unittest.main()
