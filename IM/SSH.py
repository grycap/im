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
""" Classes to encapsulate SSH operations using paramiko """

import socket
from ssh2.session import Session
from ssh2.exceptions import AuthenticationError
from ssh2.sftp import LIBSSH2_FXF_CREAT, LIBSSH2_FXF_WRITE, \
    LIBSSH2_SFTP_S_IRUSR, LIBSSH2_SFTP_S_IRGRP, LIBSSH2_SFTP_S_IWUSR, \
    LIBSSH2_SFTP_S_IROTH, LIBSSH2_FXF_READ, LIBSSH2_SFTP_S_IFDIR
from ssh2.sftp_handle import SFTPAttributes

import os
from io import BytesIO
from threading import Thread
from stat import S_ISDIR


class TimeOutException(Exception):
    """Timeout in the SSH execution"""
    pass


class AuthenticationException(Exception):
    """Authentication error in the SSH connection"""
    pass


class ThreadSSH(Thread):
    """Thread class to execute SSH with timeout"""

    def __init__(self, ssh):
        Thread.__init__(self)

        self.ssh = ssh
        self.command = None
        self.command_return = None
        self.client = None

    def close(self):
        """
        Close the SSH client connection
        """
        if self.client:
            self.client.close()
            self.client = None

    def run(self):
        if self.command:
            self.client = self.ssh.connect()

            channel = self.client.open_session()
            if self.ssh.tty:
                channel.pty()

            channel.execute(self.command + "\n")
            channel.wait_eof()
            channel.close()
            channel.wait_closed()

            stdout = ""
            size, data = channel.read()
            while size > 0:
                stdout += data
                size, data = channel.read()

            stderr = ""
            size, data = channel.read_stderr()
            while size > 0:
                stderr += data
                size, data = channel.read_stderr()

            exit_status = channel.get_exit_status()

            self.command_return = (stdout, stderr, exit_status)


class SSH:
    """ Class to encapsulate SSH operations using paramiko """

    def __init__(self, host, user, passwd, private_key=None, port=22):
        # Atributo para la version "thread"
        self.thread = None

        self.tty = False
        self.port = port
        self.host = host
        self.username = user
        self.password = passwd
        if private_key:
            self.private_key = ""
            if (private_key is not None and private_key.strip() != ""):
                if os.path.isfile(private_key):
                    pkfile = open(private_key)
                    for line in pkfile.readlines():
                        self.private_key += line
                    pkfile.close()
                else:
                    self.private_key = str(private_key)

    def __str__(self):
        res = "SSH: host: " + self.host + ", port: " + \
            str(self.port) + ", user: " + self.username
        if self.password is not None:
            res += ", password: " + self.password
        if self.private_key is not None:
            res += ", private_key: " + self.private_key
        return res

    def connect(self, time_out=None):
        """ Establishes the connection with the SSH server

            Arguments:
            - time_out: Timeout to connect.

            Returns: a ssh2 Session connected with the server.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if time_out:
            sock.settimeout(time_out)
        sock.connect((self.host, self.port))

        # Initialise
        session = Session()
        session.handshake(sock)

        if self.password and self.private_key:
            # If both credentials are provided first try to use the password
            try:
                session.userauth_password(self.username, self.password)
            except AuthenticationError:
                session.userauth_publickey_frommemory(self.username, self.private_key, '', '')
        elif self.private_key:
            session.userauth_publickey_frommemory(self.username, self.private_key, '', '')
        elif self.password:
            session.userauth_password(self.username, self.password)
        else:
            return None

        return session

    def test_connectivity(self, time_out=None):
        """ Tests if the SSH is active

            Arguments:
            - time_out: Timeout to connect.

            Returns: True if the connection is established or False otherwise

            Raises:
                Exception
        """
        try:
            self.connect(time_out)
            return True
        except AuthenticationError:
            raise AuthenticationException("Authentication Error!!")
        except:
            return False

    def execute(self, command, timeout=None):
        """ Executes a command in the remote server
            The object must be connected.

            Arguments:
            - command: The command to execute.
            - timeout: Timeout to connect.

            Returns: A tuple (stdout, stderr, exit_code) with the output of the command and the exit code
        """
        session = self.connect(time_out=timeout)
        channel = session.open_session()

        if self.tty:
            channel.pty()

        channel.execute(command + "\n")
        channel.wait_eof()
        channel.close()
        channel.wait_closed()

        stdout = ""
        size, data = channel.read()
        while size > 0:
            stdout += data
            size, data = channel.read()

        stderr = ""
        size, data = channel.read_stderr()
        while size > 0:
            stderr += data
            size, data = channel.read_stderr()

        exit_status = channel.get_exit_status()

        return (stdout, stderr, exit_status)

    @staticmethod
    def _sftp_get(sftp, src, dest):
        with sftp.open(src, LIBSSH2_FXF_READ, LIBSSH2_SFTP_S_IRUSR) as fh, open(dest, "wb+") as fdest:
            for _, data in fh:
                fdest.write(data)

    def sftp_get(self, src, dest):
        """ Gets a file from the remote server

            Arguments:
            - src: Source file in the remote server.
            - dest: Local destination path to copy.
        """
        client = self.connect()
        sftp = client.sftp_init()
        self._sftp_get(sftp, src, dest)

    @staticmethod
    def _sftp_put(sftp, src, dest):
        f_flags = LIBSSH2_FXF_CREAT | LIBSSH2_FXF_WRITE
        fileinfo = os.stat(src)
        remote_fh = sftp.open(dest, f_flags, fileinfo.st_mode)
        with open(src, 'rb') as local_fh:
            for data in local_fh:
                remote_fh.write(data)
        remote_fh.close()

    def sftp_put(self, src, dest):
        """ Puts a file to the remote server

            Arguments:
            - src: Source local file to copy.
            - dest: Destination path in the remote server.
        """
        client = self.connect()
        sftp = client.sftp_init()
        self._sftp_put(sftp, src, dest)

    def sftp_get_files(self, src, dest):
        """ Gets a list of files from the remote server

            Arguments:
            - src: A list with the source files in the remote server.
            - dest: A list with the local destination paths to copy.
        """
        client = self.connect()

        sftp = client.sftp_init()
        for file0, file1 in zip(src, dest):
            self._sftp_get(sftp, file0, file1)

    def sftp_put_files(self, files):
        """ Puts a list of files to the remote server

            Arguments:
            - files: A tuple where the first elements is the local source file to copy and the second
                     element the destination paths in the remote server.
        """
        client = self.connect()
        sftp = client.sftp_init()
        for src, dest in files:
            self._sftp_put(sftp, src, dest)

    def sftp_walk(self, src, files=None, sftp=None):
        """ Gets recursively the list of items in a directory from the remote server

            Arguments:
            - src: Source directory in the remote server to copy.
        """
        if not sftp:
            client = self.connect()
            sftp = client.sftp_init()

        folders = []
        if not files:
            files = []

        with sftp.opendir(src) as fh:
            for _, name, attrs in fh.readdir():
                if attrs.permissions & LIBSSH2_SFTP_S_IFDIR > 0:
                    if name not in [".", ".."]:
                        folder = os.path.join(src, name)
                        folders.append(folder)
                else:
                    filename = os.path.join(src, name)
                    files.append(filename)

        for folder in folders:
            self.sftp_walk(folder, files, sftp)

        return files

    def sftp_get_dir(self, src, dest):
        """ Gets recursively a directory from the remote server

            Arguments:
            - src: Source directory in the remote server to copy.
            - dest: Local destination path.
        """
        client = self.connect()
        sftp = client.sftp_init()

        files = self.sftp_walk(src, None, sftp)

        for filename in files:
            dirname = os.path.dirname(filename)
            if not os.path.exists(dirname):
                os.mkdir(dirname)
            full_dest = filename.replace(src, dest)
            self._sftp_get(sftp, filename, full_dest)

    def sftp_put_dir(self, src, dest):
        """ Puts recursively the contents of a directory to the remote server

            Arguments:
            - src: Source local directory to copy.
            - dest: Destination path in the remote server.
        """
        if os.path.isdir(src):
            if src.endswith("/"):
                src = src[:-1]

            client = self.connect()
            sftp = client.sftp_init()
            for dirname, dirnames, filenames in os.walk(src):
                for subdirname in dirnames:
                    src_path = os.path.join(dirname, subdirname)
                    dest_path = os.path.join(dest, src_path[len(src) + 1:])
                    fileinfo = os.stat(src_path)
                    try:
                        # if it exists we do not try to create it
                        sftp.stat(dest_path)
                    except:
                        sftp.mkdir(dest_path, fileinfo.st_mode & 777)
                for filename in filenames:
                    src_file = os.path.join(dirname, filename)
                    dest_file = os.path.join(dest, dirname[len(src) + 1:],
                                             filename)
                    self._sftp_put(sftp, src_file, dest_file)

    def sftp_put_content(self, content, dest):
        """ Puts the contents of a string in a remote file

            Arguments:
            - content: The string to put into the remote file.
            - dest: Destination path in the remote server.
        """
        mode = LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR | LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IROTH
        client = self.connect()
        sftp = client.sftp_init()
        f_flags = LIBSSH2_FXF_CREAT | LIBSSH2_FXF_WRITE
        with sftp.open(dest, f_flags, mode) as remote_fh:
            remote_fh.write(content)

    def sftp_mkdir(self, directory, mode=420):
        """ Creates a remote directory

            Arguments:
            - directory: Name of the directory in the remote server.

            Returns: True if the directory is created or False if it exists.
        """
        client = self.connect()
        sftp = client.sftp_init()
        try:
            # if it exists we do not try to create it
            sftp.stat(directory)
            res = False
        except:
            sftp.mkdir(directory, mode)
            res = True

        return res

    def sftp_list(self, directory):
        """ List the contents of a remote directory

            Arguments:
            - directory: Name of the directory in the remote server.

            Returns: A list with the contents of the directory
        """
        client = self.connect()
        sftp = client.sftp_init()
        res = []
        fh = sftp.opendir(directory)
        for _, name, _ in fh.readdir():
            res.append(name)
        fh.close()
        return res

    def sftp_list_attr(self, directory):
        """ Return a list containing SFTPAttributes objects corresponding to
            files in the given path.

            Arguments:
            - directory: Name of the directory in the remote server.

            Returns: A list containing SFTPAttributes object
                     (see paramiko.SFTPClient.listdir_attr)
        """
        client = self.connect()
        sftp = client.sftp_init()
        res = []
        fh = sftp.opendir(directory)
        for _, _, attrs in fh.readdir():
            res.append(attrs)
        fh.close()
        return res

    def getcwd(self):
        """ Get the current working directory.

            Returns: The current working directory.
        """
        # use pwd over ssh to delete the cwd
        cwd, _, _ = self.execute("pwd")

        return str(cwd.strip("\n"))

    def execute_timeout(self, command, timeout, retry=1, kill_command=None):
        """ Executes a command waiting for a timeout, and send a kill comand

            Arguments:
            - command: Command to execute.
            - timeout: Timeout to wait for.
            - retry: Number of times the command will be retried.
                (Optional, default 1)
            - kill_command: A command sent when the timeout is expired,
                to clean the environment.
                (Optional, default None)

            Returns: A tuple (stdout, stderr) with the output of the command
        """
        cont = 0
        while cont < retry:
            cont += 1
            self.thread = ThreadSSH(self)
            self.thread.command = command
            self.thread.start()
            self.thread.join(timeout)

            if self.thread.isAlive():
                self.thread.close()
                self.thread.join(2)
                if kill_command:
                    self.execute(kill_command)
                self.thread = None
            else:
                res = self.thread.command_return
                self.thread.close()
                self.thread = None
                return res

        raise TimeOutException("Error: Timeout")

    def sftp_remove(self, path):
        """ Delete a file, if possible.

            Arguments:
            - path: Name of the file in the remote server to delete.

            Returns: True if the file is deleted or False if it exists.
        """
        client = self.connect()
        sftp = client.sftp_init()
        try:
            # if it exists we do not try to delete it
            sftp.stat(path)
            res = False
        except:
            sftp.unlink(path)
            res = True
        return res

    def sftp_chmod(self, path, mode):
        """
        Change the mode (permissions) of a file.  The permissions are
        unix-style and identical to those used by python's C{os.chmod}
        function.

            Arguments:
            - path: String with the path of the file to change the permissions of
            - mode: Int with the new permissions
        """
        client = self.connect()
        sftp = client.sftp_init()

        attrs = sftp.stat(path)
        attrs.permissions = attrs.permissions | mode
        sftp.setstat(path, attrs)

        return True
