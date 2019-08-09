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
import tempfile

from ssh2.exceptions import SFTPProtocolError
from ssh2.sftp import LIBSSH2_SFTP_S_IFDIR
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

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_test_connectivity(self, session, socket):
        sess = MagicMock()
        session.return_value = sess
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))
        success = ssh.test_connectivity(5)
        self.assertTrue(success)
        self.assertEquals(sess.userauth_password.call_args_list[0][0], ("user", "passwd"))

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_execute(self, session, socket):
        sess = MagicMock()
        session.return_value = sess

        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        channel = MagicMock()
        sess.open_session.return_value = channel

        channel.read.side_effect = [(3, "out"), (0, "")]
        channel.read_stderr.side_effect = [(3, "err"), (0, "")]
        channel.get_exit_status.return_value = 0

        (res_stdout, res_stderr, exit_status) = ssh.execute("ls")
        self.assertEqual(res_stdout, "out")
        self.assertEqual(res_stderr, "err")
        self.assertEqual(exit_status, 0)

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_sftp_put(self, session, socket):
        sess = MagicMock()
        session.return_value = sess
        sftp = MagicMock()
        sess.sftp_init.return_value = sftp
        remote_fh = MagicMock()
        sftp.open.return_value = remote_fh

        fh = tempfile.NamedTemporaryFile(delete=False)
        src = fh.name
        fh.write(b"some_data")
        fh.close()

        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))
        ssh.sftp_put(src, src)

        self.assertEqual(remote_fh.write.call_args_list[0][0][0], b"some_data")

    @staticmethod
    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_sftp_get_files(session, socket):
        sess = MagicMock()
        session.return_value = sess
        sftp = MagicMock()
        sess.sftp_init.return_value = sftp

        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_get_files(["some_file"], ["some_file"])

    @staticmethod
    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_sftp_get(session, socket):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_get("some_file", "some_file")

    @staticmethod
    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_sftp_put_files(session, socket):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_put_files([("some_file", "some_file")])

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    @patch('os.walk')
    def test_sftp_put_dir(self, walk, session, socket):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        tmp_dir = tempfile.gettempdir()
        walk.return_value = [(tmp_dir, ["dir"], ["file1"]),
                             ("%s/dir" % tmp_dir, [], ["file2"])]

        files = ssh.sftp_put_dir(tmp_dir, tmp_dir)
        self.assertEqual(files, ['%s/file1' % tmp_dir, '%s/dir/file2' % tmp_dir])

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_sftp_get_dir(self, session, socket):
        sess = MagicMock()
        session.return_value = sess
        sftp = MagicMock()
        sess.sftp_init.return_value = sftp
        fh = MagicMock()
        sftp.opendir.return_value = fh
        attrsd = MagicMock()
        attrsd.permissions = LIBSSH2_SFTP_S_IFDIR
        attrsf = MagicMock()
        attrsf.permissions = 0
        fh.readdir.side_effect = [[(None, "dir", attrsd), (None, "file1", attrsf)],
                                  [(None, "file2", attrsf)]]

        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        tmp_dir = tempfile.gettempdir()
        files = ssh.sftp_get_dir(tmp_dir, tmp_dir)
        self.assertEqual(files, ['%s/file1' % tmp_dir, '%s/dir/file2' % tmp_dir])

    @staticmethod
    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_sftp_put_content(session, socket):
        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_put_content("some_file", "some_content")

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_sftp_mkdir(self, session, socket):
        sess = MagicMock()
        session.return_value = sess
        sftp = MagicMock()
        sess.sftp_init.return_value = sftp
        sftp.stat.side_effect = Exception()

        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        ssh.sftp_mkdir("/some_dir")
        self.assertEqual(sftp.mkdir.call_args_list[0][0], ("/some_dir", 0o777))

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_sftp_list(self, session, socket):
        sess = MagicMock()
        session.return_value = sess
        sftp = MagicMock()
        sess.sftp_init.return_value = sftp
        d = MagicMock()
        d.readdir.return_value = [("", "file", "")]
        sftp.opendir.return_value = d

        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        res = ssh.sftp_list("/some_dir")
        self.assertEqual(res, ["file"])

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_sftp_list_attr(self, session, socket):
        sess = MagicMock()
        session.return_value = sess
        sftp = MagicMock()
        sess.sftp_init.return_value = sftp
        d = MagicMock()
        d.readdir.return_value = [("", "", "attrs")]
        sftp.opendir.return_value = d

        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        res = ssh.sftp_list_attr("/some_dir")
        self.assertEqual(res, ["attrs"])

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_getcwd(self, session, socket):
        sess = MagicMock()
        session.return_value = sess

        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        channel = MagicMock()
        sess.open_session.return_value = channel

        channel.read.side_effect = [(3, "some_dir"), (0, "")]
        channel.read_stderr.side_effect = [(3, "err"), (0, "")]
        channel.get_exit_status.return_value = 0

        res = ssh.getcwd()
        self.assertEqual(res, "some_dir")

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_execute_timeout(self, session, socket):
        sess = MagicMock()
        session.return_value = sess

        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        channel = MagicMock()
        sess.open_session.return_value = channel

        channel.read.side_effect = [(3, "out"), (0, "")]
        channel.read_stderr.side_effect = [(3, "err"), (0, "")]
        channel.get_exit_status.return_value = 0

        res_stdout, res_stderr, code = ssh.execute_timeout("ls", 5)
        self.assertEqual(res_stdout, "out")
        self.assertEqual(res_stderr, "err")
        self.assertEqual(code, 0)

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_sftp_remove(self, session, socket):
        sess = MagicMock()
        session.return_value = sess
        sftp = MagicMock()
        sess.sftp_init.return_value = sftp

        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        res = ssh.sftp_remove("some_file")
        self.assertTrue(res)

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_sftp_chmod(self, session, socket):
        sess = MagicMock()
        session.return_value = sess
        sftp = MagicMock()
        sess.sftp_init.return_value = sftp

        ssh = SSHRetry("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        res = ssh.sftp_chmod("some_file", 0o644)
        self.assertTrue(res)

    @patch('socket.socket')
    @patch('IM.SSH.Session')
    def test_sftp_error(self, session, socket):
        sess = MagicMock()
        session.return_value = sess
        sftp = MagicMock()
        sess.sftp_init.return_value = sftp
        sftp.open.side_effect = SFTPProtocolError()
        sftp.last_error.return_value = 3

        ssh = SSH("host", "user", "passwd", read_file_as_string("../files/privatekey.pem"))

        tmp_dir = tempfile.gettempdir()
        with self.assertRaises(IOError) as ex:
            ssh.sftp_get("%s/some_file" % tmp_dir, "%s/some_file" % tmp_dir)
        self.assertEquals("Error code: 3. Permission denied.", str(ex.exception))


if __name__ == '__main__':
    unittest.main()
