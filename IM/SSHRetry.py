#! /usr/bin/env python
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

from IM.retry import retry
from IM.SSH import SSH


class SSHRetry(SSH):
    """ SSH class decorated to perform a number of retries """
    TRIES = 3
    DELAY = 3
    BACKOFF = 2

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def execute(self, command, timeout=None):
        return SSH.execute(self, command, timeout)

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def sftp_get(self, src, dest):
        return SSH.sftp_get(self, src, dest)

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def sftp_get_files(self, src, dest):
        return SSH.sftp_get_files(self, src, dest)

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def sftp_put_files(self, files):
        return SSH.sftp_put_files(self, files)

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def sftp_put(self, src, dest):
        return SSH.sftp_put(self, src, dest)

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def sftp_put_dir(self, src, dest):
        return SSH.sftp_put_dir(self, src, dest)

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def sftp_put_content(self, content, dest):
        return SSH.sftp_put_content(self, content, dest)

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def sftp_mkdir(self, directory):
        return SSH.sftp_mkdir(self, directory)

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def sftp_list(self, directory):
        return SSH.sftp_list(self, directory)

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def sftp_list_attr(self, directory):
        return SSH.sftp_list_attr(self, directory)

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def getcwd(self):
        return SSH.getcwd(self)

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def sftp_remove(self, path):
        return SSH.sftp_remove(self, path)

    @retry(Exception, tries=TRIES, delay=DELAY, backoff=BACKOFF)
    def sftp_chmod(self, path, mode):
        return SSH.sftp_chmod(self, path, mode)
