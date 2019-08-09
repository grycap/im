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

from IM.SSHRetry import SSHRetry, SSH
from mock import patch, MagicMock


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestSSH(unittest.TestCase):
    """
    Class to test the SSH class
    """

    def test_str(self):
        ssh = SSH("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))
        expected_res = ("SSH: host: host, port: 22, user: user, password: passwd, "
                        "private_key: %s" % read_file_as_string("../files/privatekey.pem"))
        self.assertEqual(str(ssh), expected_res)

    @patch('paramiko.SSHClient')
    def test_test_connectivity(self, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))
        success = ssh.test_connectivity(5)
        self.assertTrue(success)

    @patch('paramiko.SSHClient')
    def test_execute(self, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        client = MagicMock()
        ssh_client.return_value = client
        transport = MagicMock()
        channel = MagicMock()
        client.get_transport.return_value = transport
        transport.open_session.return_value = channel
        channel.makefile.return_value = ["out"]
        channel.makefile_stderr.return_value = ["err"]
        channel.recv_exit_status.return_value = 0

        (res_stdout, res_stderr, exit_status) = ssh.execute("ls")
        self.assertEqual(res_stdout, "out")
        self.assertEqual(res_stderr, "err")
        self.assertEqual(exit_status, 0)

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient')
    def test_sftp_get(self, sftp_client, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_get("some_file", "some_file")

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient')
    def test_sftp_get_files(self, sftp_client, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_get_files(["some_file"], ["some_file"])

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient')
    def test_sftp_put(self, sftp_client, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_put("some_file", "some_file")

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient')
    def test_sftp_put_files(self, sftp_client, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_put_files([("some_file", "some_file")])

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient')
    def test_sftp_put_dir(self, sftp_client, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_put_dir("/tmp", "/tmp")

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient')
    def test_sftp_get_dir(self, sftp_client, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_get_dir("/tmp", "/tmp")

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient')
    def test_sftp_put_content(self, sftp_client, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_put_content("some_file", "some_content")

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient')
    def test_sftp_mkdir(self, sftp_client, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_mkdir("/some_dir")

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient.from_transport')
    def test_sftp_list(self, from_transport, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        client = MagicMock()
        from_transport.return_value = client
        client.listdir.return_value = ["file"]

        res = ssh.sftp_list("/some_dir")
        self.assertEqual(res, ["file"])

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient.from_transport')
    def test_sftp_list_attr(self, from_transport, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        client = MagicMock()
        from_transport.return_value = client
        client.listdir_attr.return_value = ["file"]

        res = ssh.sftp_list_attr("/some_dir")
        self.assertEqual(res, ["file"])

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient.from_transport')
    def test_getcwd(self, from_transport, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        client = MagicMock()
        from_transport.return_value = client
        client.getcwd.return_value = "some_dir"

        res = ssh.getcwd()
        self.assertEqual(res, "some_dir")

    @patch('paramiko.SSHClient')
    def test_execute_timeout(self, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        client = MagicMock()
        ssh_client.return_value = client
        tansport = MagicMock()
        client.get_transport.return_value = tansport
        channel = MagicMock()
        tansport.open_session.return_value = channel
        channel.makefile.return_value = "out"
        channel.makefile_stderr.return_value = "err"
        channel.recv_exit_status.return_value = 0

        res_stdout, res_stderr, code = ssh.execute_timeout("ls", 5)
        self.assertEqual(res_stdout, "out")
        self.assertEqual(res_stderr, "err")
        self.assertEqual(code, 0)

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient.from_transport')
    def test_sftp_remove(self, from_transport, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        client = MagicMock()
        from_transport.return_value = client
        client.remove.return_value = True

        res = ssh.sftp_remove("some_file")
        self.assertTrue(res)

    @patch('paramiko.SSHClient')
    @patch('paramiko.SFTPClient.from_transport')
    def test_sftp_chmod(self, from_transport, ssh_client):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        client = MagicMock()
        from_transport.return_value = client

        res = ssh.sftp_chmod("some_file", 0o644)
        self.assertTrue(res)


if __name__ == '__main__':
    unittest.main()
