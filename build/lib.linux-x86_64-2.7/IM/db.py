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

"""Class to manage de DB operations"""
import time

try:
    import sqlite3 as sqlite
    SQLITE3_AVAILABLE = True
    SQLITE_AVAILABLE = True
except:
    SQLITE3_AVAILABLE = False
    SQLITE_AVAILABLE = False

if not SQLITE_AVAILABLE:
    try:
        import sqlite
        SQLITE_AVAILABLE = True
    except:
        SQLITE_AVAILABLE = False

# Class to manage de DB operations
class DataBase:
    """Class to manage de DB operations"""

    db_available = SQLITE_AVAILABLE
    RETRY_SLEEP = 2
    MAX_RETRIES = 15
    DB_TYPE = "SQLite"
    
    def __init__(self, db_filename):
        self.db_filename = db_filename
        self.connection = None
        
    def connect(self):
        """ Function to connecto to the DB
        
            Returns: True if the connection is established correctly
                     of False in case of errors.
        """
        if SQLITE_AVAILABLE:
            self.connection = sqlite.connect(self.db_filename)
            return True
        else:
            return False
    
    def _execute_retry(self, sql, args, fetch = False):
        """ Function to execute a SQL function, retrying in case of locked DB
        
            Arguments:
            - sql: The SQL sentence
            - args: A List of arguments to substitute in the SQL sentence
            - fetch: If the function must fetch the results.
                    (Optional, default False)
                    
            Returns: True if fetch is False and the operation is performed
                     correctly or a list with the "Fetch" of the results
        """

        if self.connection is None:
            raise Exception("DataBase object not connected")
        else:
            retries_cont = 0
            while retries_cont < self.MAX_RETRIES:
                try:
                    cursor = self.connection.cursor()
                    if args is not None:
                        if not SQLITE3_AVAILABLE:
                            new_sql = sql.replace("?","%s")
                        else:
                            new_sql = sql
                        cursor.execute(new_sql, args)
                    else:
                        cursor.execute(sql)
                    
                    if fetch:
                        res = cursor.fetchall()
                    else:
                        self.connection.commit()
                        res = True
                    return res
                # If the operational error is db lock, retry
                except sqlite.OperationalError, ex:
                    if str(ex).lower() == 'database is locked':
                        retries_cont += 1
                        # release the connection
                        self.close()
                        time.sleep(self.RETRY_SLEEP)
                        # and get it again
                        self.connect()
                    else:
                        raise ex
                except sqlite.IntegrityError, ex:
                    raise IntegrityError()
    
    def execute(self, sql, args = None):
        """ Executes a SQL sentence without returning results
        
            Arguments:
            - sql: The SQL sentence
            - args: A List of arguments to substitute in the SQL sentence
                    (Optional, default None)
                    
            Returns: True if the operation is performed correctly 
        """
        return self._execute_retry(sql, args)
    
    def select(self, sql, args = None):
        """ Executes a SQL sentence that returns results
        
            Arguments:
            - sql: The SQL sentence
            - args: A List of arguments to substitute in the SQL sentence
                    (Optional, default None)
                    
            Returns: A list with the "Fetch" of the results
        """
        return self._execute_retry(sql, args, fetch = True) 
    
    def close(self):
        """ Closes the DB connection """
        if self.connection is None:
            return False
        else:
            try:
                self.connection.close()
                return True
            except Exception:
                return False
            
    def table_exists(self, table_name):
        """ Checks if a table exists in the DB
        
            Arguments:
            - table_name: The name of the table
            
            Returns: True if the table exists or False otherwise
        """
        res = self.select('select name from sqlite_master where type="table" and name="' + table_name + '"')
        if (len(res) == 0):
            return False
        else:
            return True

try:
    class IntegrityError(sqlite.IntegrityError):
        """ Class to return IntegrityError independently of the DB used"""
        pass
except:
    class IntegrityError:
        pass