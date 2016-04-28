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

import paramiko
import scp
import os
import StringIO
from threading import Thread


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

    def run(self):
        if self.command:
            self.client = self.ssh.connect()

            if self.ssh.tty:
                channel = self.client.get_transport().open_session()
                channel.get_pty()
                channel.exec_command(self.command + "\n")
                stdout = channel.makefile()
                stderr = channel.makefile_stderr()
            else:
                _, stdout, stderr = self.client.exec_command(self.command)

            res_stdout = ""
            for line in stdout:
                res_stdout += line
            res_stderr = ""
            for line in stderr:
                res_stderr += line

            if self.ssh.tty:
                channel.close()

            self.command_return = (res_stdout, res_stderr)


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
        self.private_key = private_key
        self.private_key_obj = None
        if (private_key is not None and private_key.strip() != ""):
            private_key_obj = StringIO.StringIO()
            if os.path.isfile(private_key):
                pkfile = open(private_key)
                for line in pkfile.readlines():
                    private_key_obj.write(line)
                pkfile.close()
            else:
                private_key_obj.write(private_key)

            private_key_obj.seek(0)
            self.private_key_obj = paramiko.RSAKey.from_private_key(
                private_key_obj)

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

            Returns: a paramiko SSHClient connected with the server.
        """
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if self.password and self.private_key_obj:
            # If both credentials are provided first try to use the password
            try:
                client.connect(self.host, self.port, username=self.username,
                               password=self.password, timeout=time_out)
            except paramiko.AuthenticationException:
                # and then use the private key
                client.connect(self.host, self.port, username=self.username,
                               pkey=self.private_key_obj, timeout=time_out)
        else:
            client.connect(self.host, self.port, username=self.username,
                           password=self.password, timeout=time_out,
                           pkey=self.private_key_obj)

        return client

    def test_connectivity(self, time_out=None):
        """ Tests if the SSH is active

            Arguments:
            - time_out: Timeout to connect.

            Returns: True if the connection is established or False otherwise

            Raises:
                Exception
        """
        try:
            client = self.connect(time_out)
            client.close()
            return True
        except paramiko.AuthenticationException:
            raise AuthenticationException("Authentication Error!!")
        except paramiko.SSHException, e:
            if str(e) == "No authentication methods available":
                raise AuthenticationException("Authentication Error!!")
            return False
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
        client = self.connect(time_out=timeout)
        channel = client.get_transport().open_session()

        if self.tty:
            channel.get_pty()

        channel.exec_command(command + "\n")
        stdout = channel.makefile()
        stderr = channel.makefile_stderr()
        exit_status = channel.recv_exit_status()

        res_stdout = ""
        for line in stdout:
            res_stdout += line
        res_stderr = ""
        for line in stderr:
            res_stderr += line

        channel.close()
        client.close()
        return (res_stdout, res_stderr, exit_status)

    def _get_sftp(self):
        """ Gets a Transport and a SFTPClient to perform sftp operations
        """
        client = self.connect()
        transport = client.get_transport()
        sftp = paramiko.SFTPClient.from_transport(transport)
        return transport, sftp

    def sftp_get(self, src, dest):
        """ Gets a file from the remote server

            Arguments:
            - src: Source file in the remote server.
            - dest: Local destination path to copy.
        """
        client = self.connect()
        transport = client.get_transport()

        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            if not transport.active:
                sftp = scp.SCPClient(transport)
        except:
            # in case of failure try to use scp
            sftp = scp.SCPClient(transport)

        sftp.get(src, dest)
        sftp.close()
        transport.close()

    def sftp_get_files(self, src, dest):
        """ Gets a list of files from the remote server

            Arguments:
            - src: A list with the source files in the remote server.
            - dest: A list with the local destination paths to copy.
        """
        client = self.connect()
        transport = client.get_transport()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            if not transport.active:
                sftp = scp.SCPClient(transport)
        except:
            # in case of failure try to use scp
            sftp = scp.SCPClient(transport)

        for file0, file1 in zip(src, dest):
            sftp.get(file0, file1)
        sftp.close()
        transport.close()

    def sftp_put_files(self, files):
        """ Puts a list of files to the remote server

            Arguments:
            - files: A tuple where the first elements is the local source file to copy and the second
                     element the destination paths in the remote server.
        """
        client = self.connect()
        transport = client.get_transport()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            if not transport.active:
                sftp = scp.SCPClient(transport)
        except:
            # in case of failure try to use scp
            sftp = scp.SCPClient(transport)

        for src, dest in files:
            sftp.put(src, dest)
        sftp.close()
        transport.close()

    def sftp_put(self, src, dest):
        """ Puts a file to the remote server

            Arguments:
            - src: Source local file to copy.
            - dest: Destination path in the remote server.
        """
        client = self.connect()
        transport = client.get_transport()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            if not transport.active:
                sftp = scp.SCPClient(transport)
        except:
            # in case of failure try to use scp
            sftp = scp.SCPClient(transport)
        sftp.put(src, dest)
        sftp.close()
        transport.close()

    def sftp_put_dir(self, src, dest):
        """ Puts recursively the contents of a directory to the remote server

            Arguments:
            - src: Source local directory to copy.
            - dest: Destination path in the remote server.
        """
        if os.path.isdir(src):
            client = self.connect()
            transport = client.get_transport()
            try:
                sftp = paramiko.SFTPClient.from_transport(transport)
                sftp_avail = transport.active
            except:
                # in case of failure try to use scp
                sftp = scp.SCPClient(transport)
                sftp_avail = False

            for dirname, dirnames, filenames in os.walk(src):
                for subdirname in dirnames:
                    src_path = os.path.join(dirname, subdirname)
                    dest_path = os.path.join(dest, src_path[len(src) + 1:])
                    if sftp_avail:
                        try:
                            # if it exists we do not try to create it
                            sftp.stat(dest_path)
                        except:
                            sftp.mkdir(dest_path)
                    else:
                        out, err, code = self.execute(
                            "mkdir -p %s" % dest_path)
                        print out, err
                for filename in filenames:
                    src_file = os.path.join(dirname, filename)
                    dest_file = os.path.join(dest, dirname[len(src) + 1:],
                                             filename)
                    sftp.put(src_file, dest_file)

            sftp.close()
            transport.close()

    def sftp_put_content(self, content, dest):
        """ Puts the contents of a string in a remote file

            Arguments:
            - content: The string to put into the remote file.
            - dest: Destination path in the remote server.
        """
        transport, sftp = self._get_sftp()
        dest_file = sftp.file(dest, "w")
        dest_file.write(content)
        dest_file.close()
        sftp.close()
        transport.close()

    def sftp_mkdir(self, directory):
        """ Creates a remote directory

            Arguments:
            - directory: Name of the directory in the remote server.

            Returns: True if the directory is created or False if it exists.
        """
        try:
            transport, sftp = self._get_sftp()
            sftp_avail = transport.active
        except:
            sftp_avail = False

        if sftp_avail:
            try:
                # if it exists we do not try to create it
                sftp.stat(directory)
                res = False
            except:
                sftp.mkdir(directory)
                res = True

            sftp.close()
            transport.close()
        else:
            # use mkdir over ssh to create the directory
            _, _, status = self.execute("mkdir -p %s" % directory)
            res = status == 0

        return res

    def sftp_list(self, directory):
        """ List the contents of a remote directory

            Arguments:
            - directory: Name of the directory in the remote server.

            Returns: A list with the contents of the directory
                     (see paramiko.SFTPClient.listdir)
        """
        transport, sftp = self._get_sftp()
        res = sftp.listdir(directory)
        sftp.close()
        transport.close()
        return res

    def sftp_list_attr(self, directory):
        """ Return a list containing SFTPAttributes objects corresponding to
            files in the given path.

            Arguments:
            - directory: Name of the directory in the remote server.

            Returns: A list containing SFTPAttributes object
                     (see paramiko.SFTPClient.listdir_attr)
        """
        transport, sftp = self._get_sftp()
        res = sftp.listdir_attr(directory)
        sftp.close()
        transport.close()
        return res

    def getcwd(self):
        """ Get the current working directory.

            Returns: The current working directory.
        """
        try:
            transport, sftp = self._get_sftp()
            sftp_avail = transport.active
        except:
            sftp_avail = False

        if sftp_avail:
            cwd = sftp.getcwd()
            sftp.close()
            transport.close()
        else:
            # use rm over ssh to delete the file
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
                self.thread.client.close()
                self.thread.join(2)
                if kill_command:
                    self.execute(kill_command)
                self.thread = None
            else:
                res = self.thread.command_return
                self.thread.client.close()
                self.thread = None
                return res

        raise TimeOutException("Error: Timeout")

    def sftp_remove(self, path):
        """ Delete a file, if possible.

            Arguments:
            - path: Name of the file in the remote server to delete.

            Returns: True if the file is deleted or False if it exists.
        """
        try:
            transport, sftp = self._get_sftp()
            sftp_avail = transport.active
        except:
            sftp_avail = False

        if sftp_avail:
            res = sftp.remove(path)
            sftp.close()
            transport.close()
        else:
            # use rm over ssh to delete the file
            _, _, status = self.execute("rm -f %s" % path)
            res = status == 0

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
        try:
            transport, sftp = self._get_sftp()
            sftp_avail = transport.active
        except:
            sftp_avail = False

        if sftp_avail:
            sftp.chmod(path, mode)
            res = True
            sftp.close()
            transport.close()
        else:
            # use chmod over ssh to change permissions
            _, _, status = self.execute("chmod %s %s" % (oct(mode), path))
            res = status == 0

        return res
