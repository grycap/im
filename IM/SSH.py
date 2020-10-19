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
"""Classes to encapsulate SSH operations using paramiko."""

import paramiko
try:
    import scp
except Exception:
    print("WARN: Python Azure SDK not correctly installed. AzureCloudConnector will not work!.")
import os
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
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
        self.proxy = None

    def close(self):
        """
        Close the SSH client connection
        """
        if self.client:
            self.client.close()
            self.client = None
        if self.proxy:
            self.proxy.close()
            self.proxy = None

    def run(self):
        if self.command:
            self.client, self.proxy = self.ssh.connect()

            channel = self.client.get_transport().open_session()
            if self.ssh.tty:
                channel.get_pty()
            channel.exec_command(self.command + "\n")
            stdout = channel.makefile()
            stderr = channel.makefile_stderr()
            exit_status = channel.recv_exit_status()

            res_stdout = ""
            for line in stdout:
                res_stdout += line
            res_stderr = ""
            for line in stderr:
                res_stderr += line

            if self.ssh.tty:
                channel.close()

            self.command_return = (res_stdout, res_stderr, exit_status)


class SSH:
    """ Class to encapsulate SSH operations using paramiko """

    def __init__(self, host, user, passwd=None, private_key=None, port=22, proxy_host=None, auto_close=True):
        # Atributo para la version "thread"
        self.thread = None

        self.client = None
        self.proxy = None
        self.auto_close = auto_close

        self.proxy_host = proxy_host
        self.tty = False
        self.port = port
        self.host = host
        self.username = user
        self.password = passwd
        self.private_key = private_key
        self.private_key_obj = None
        if (private_key is not None and private_key.strip() != ""):
            private_key_obj = StringIO()
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

    def close(self):
        """
        Close the SSH client connection
        """
        if self.client:
            self.client.close()
            self.client = None
        if self.proxy:
            self.proxy.close()
            self.proxy = None

    def __str__(self):
        res = "SSH: host: " + self.host + ", port: " + \
            str(self.port) + ", user: " + self.username
        if self.password is not None:
            res += ", password: " + self.password
        if self.private_key is not None:
            res += ", private_key: " + self.private_key
        if self.proxy_host:
            res += " via proxy: %s" % str(self.proxy_host)
        return res

    def connect(self, time_out=None):
        """ Establishes the connection with the SSH server

            Arguments:
            - time_out: Timeout to connect.

            Returns: a paramiko SSHClient connected with the server.
        """
        if self.client and self.client.get_transport() and self.client.get_transport().is_authenticated():
            return self.client, self.proxy

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        proxy = None
        proxy_channel = None
        if self.proxy_host:
            proxy = paramiko.SSHClient()
            proxy.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            proxy.connect(self.proxy_host.host, self.proxy_host.port, username=self.proxy_host.username,
                          password=self.proxy_host.password, pkey=self.proxy_host.private_key_obj)
            proxy_transport = proxy.get_transport()
            dest_addr = (self.host, self.port)
            local_addr = (self.proxy_host.host, self.proxy_host.port)
            proxy_channel = proxy_transport.open_channel("direct-tcpip", dest_addr, local_addr)

            # proxy_command = "sshpass -p %s ssh %s %s@%s nc %s 22" % (self.proxy_host.password,
            #                                                         '-o StrictHostKeyChecking=no',
            #                                                         self.proxy_host.username,
            #                                                         self.proxy_host.host,
            #                                                         self.host)
            # proxy_channel =  paramiko.ProxyCommand(proxy_command)

        if self.password and self.private_key_obj:
            # If both credentials are provided first try to use the password
            try:
                client.connect(self.host, self.port, username=self.username,
                               password=self.password, timeout=time_out, sock=proxy_channel)
            except paramiko.AuthenticationException:
                # and then use the private key
                client.connect(self.host, self.port, username=self.username,
                               pkey=self.private_key_obj, timeout=time_out, sock=proxy_channel)
        else:
            client.connect(self.host, self.port, username=self.username,
                           password=self.password, timeout=time_out, sock=proxy_channel,
                           pkey=self.private_key_obj)

        self.client = client
        self.proxy = proxy

        return client, proxy

    def test_connectivity(self, time_out=None):
        """ Tests if the SSH is active

            Arguments:
            - time_out: Timeout to connect.

            Returns: True if the connection is established or False otherwise

            Raises:
                Exception
        """
        try:
            client, proxy = self.connect(time_out)
            client.close()
            if proxy:
                proxy.close()
            return True
        except paramiko.AuthenticationException:
            raise AuthenticationException("Authentication Error!!")
        except paramiko.SSHException as e:
            if str(e) == "No authentication methods available":
                raise AuthenticationException("Authentication Error!!")
            return False
        except Exception:
            return False

    def execute(self, command, timeout=None):
        """ Executes a command in the remote server
            The object must be connected.

            Arguments:
            - command: The command to execute.
            - timeout: Timeout to connect.

            Returns: A tuple (stdout, stderr, exit_code) with the output of the command and the exit code
        """
        client, proxy = self.connect(time_out=timeout)
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

        if self.auto_close:
            channel.close()
            client.close()
            if proxy:
                proxy.close()
        return (res_stdout, res_stderr, exit_status)

    def sftp_get(self, src, dest):
        """ Gets a file from the remote server

            Arguments:
            - src: Source file in the remote server.
            - dest: Local destination path to copy.
        """
        client, proxy = self.connect()
        transport = client.get_transport()

        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            if not transport.active:
                sftp = scp.SCPClient(transport)
        except Exception:
            # in case of failure try to use scp
            sftp = scp.SCPClient(transport)

        sftp.get(src, dest)
        if self.auto_close:
            sftp.close()
            if proxy:
                proxy.close()
            transport.close()

    def sftp_get_files(self, src, dest):
        """ Gets a list of files from the remote server

            Arguments:
            - src: A list with the source files in the remote server.
            - dest: A list with the local destination paths to copy.
        """
        client, proxy = self.connect()
        transport = client.get_transport()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            if not transport.active:
                sftp = scp.SCPClient(transport)
        except Exception:
            # in case of failure try to use scp
            sftp = scp.SCPClient(transport)

        for file0, file1 in zip(src, dest):
            sftp.get(file0, file1)
        if self.auto_close:
            sftp.close()
            if proxy:
                proxy.close()
            transport.close()

    def sftp_put_files(self, files):
        """ Puts a list of files to the remote server

            Arguments:
            - files: A tuple where the first elements is the local source file to copy and the second
                     element the destination paths in the remote server.
        """
        client, proxy = self.connect()
        transport = client.get_transport()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            if not transport.active:
                sftp = scp.SCPClient(transport)
        except Exception:
            # in case of failure try to use scp
            sftp = scp.SCPClient(transport)

        for src, dest in files:
            sftp.put(src, dest)
        if self.auto_close:
            sftp.close()
            if proxy:
                proxy.close()
            transport.close()

    def sftp_put(self, src, dest):
        """ Puts a file to the remote server

            Arguments:
            - src: Source local file to copy.
            - dest: Destination path in the remote server.
        """
        client, proxy = self.connect()
        transport = client.get_transport()
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            if not transport.active:
                sftp = scp.SCPClient(transport)
        except Exception:
            # in case of failure try to use scp
            sftp = scp.SCPClient(transport)
        sftp.put(src, dest)
        if self.auto_close:
            sftp.close()
            if proxy:
                proxy.close()
            transport.close()

    def sftp_get_dir(self, src, dest):
        """ Gets recursively a directory from the remote server

            Arguments:
            - src: Source directory in the remote server to copy.
            - dest: Local destination path.
        """
        client, proxy = self.connect()
        transport = client.get_transport()
        sftp = paramiko.SFTPClient.from_transport(transport)

        files = self.sftp_walk(src, None, sftp)

        for filename in files:
            dirname = os.path.dirname(filename)
            if not os.path.exists(dirname):
                os.mkdir(dirname)
            full_dest = filename.replace(src, dest)
            sftp.get(filename, full_dest)

        if self.auto_close:
            sftp.close()
            if proxy:
                proxy.close()
            transport.close()

    def sftp_walk(self, src, files=None, sftp=None):
        """ Gets recursively the list of items in a directory from the remote server

            Arguments:
            - src: Source directory in the remote server to copy.
        """
        close = False
        if not sftp:
            client, proxy = self.connect()
            transport = client.get_transport()
            sftp = paramiko.SFTPClient.from_transport(transport)
            close = True

        folders = []
        if not files:
            files = []
        for f in sftp.listdir_attr(src):
            if S_ISDIR(f.st_mode):
                folder = os.path.join(src, f.filename)
                folders.append(folder)
            else:
                filename = os.path.join(src, f.filename)
                files.append(filename)

        for folder in folders:
            self.sftp_walk(folder, files, sftp)

        if close:
            sftp.close()
            transport.close()
            if proxy:
                proxy.close()

        return files

    def sftp_put_dir(self, src, dest):
        """ Puts recursively the contents of a directory to the remote server

            Arguments:
            - src: Source local directory to copy.
            - dest: Destination path in the remote server.
        """
        if os.path.isdir(src):
            if src.endswith("/"):
                src = src[:-1]
            client, proxy = self.connect()
            transport = client.get_transport()
            try:
                sftp = paramiko.SFTPClient.from_transport(transport)
                sftp_avail = transport.active
            except Exception:
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
                        except Exception:
                            sftp.mkdir(dest_path)
                    else:
                        self.execute("mkdir -p %s" % dest_path)
                for filename in filenames:
                    src_file = os.path.join(dirname, filename)
                    dest_file = os.path.join(dest, dirname[len(src) + 1:],
                                             filename)
                    sftp.put(src_file, dest_file)

            sftp.close()
            if proxy:
                proxy.close()
            transport.close()

    def sftp_put_content(self, content, dest):
        """ Puts the contents of a string in a remote file

            Arguments:
            - content: The string to put into the remote file.
            - dest: Destination path in the remote server.
        """
        client, proxy = self.connect()
        transport = client.get_transport()
        sftp = paramiko.SFTPClient.from_transport(transport)
        dest_file = sftp.file(dest, "w")
        dest_file.write(content)
        dest_file.close()
        sftp.close()
        if proxy:
            proxy.close()
        transport.close()

    def sftp_mkdir(self, directory, mode=0o777):
        """ Creates a remote directory

            Arguments:
            - directory: Name of the directory in the remote server.

            Returns: True if the directory is created or False if it exists.
        """
        try:
            client, proxy = self.connect()
            transport = client.get_transport()
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp_avail = transport.active
        except Exception:
            sftp_avail = False

        if sftp_avail:
            try:
                # if it exists we do not try to create it
                sftp.stat(directory)
                res = False
            except Exception:
                sftp.mkdir(directory, mode)
                res = True

            if self.auto_close:
                sftp.close()
                if proxy:
                    proxy.close()
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
        client, proxy = self.connect()
        transport = client.get_transport()
        sftp = paramiko.SFTPClient.from_transport(transport)
        res = sftp.listdir(directory)
        if self.auto_close:
            sftp.close()
            if proxy:
                proxy.close()
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
        client, proxy = self.connect()
        transport = client.get_transport()
        sftp = paramiko.SFTPClient.from_transport(transport)
        res = sftp.listdir_attr(directory)
        if self.auto_close:
            sftp.close()
            transport.close()
            if proxy:
                proxy.close()
        return res

    def getcwd(self):
        """ Get the current working directory.

            Returns: The current working directory.
        """
        try:
            client, proxy = self.connect()
            transport = client.get_transport()
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp_avail = transport.active
        except Exception:
            sftp_avail = False

        if sftp_avail:
            cwd = sftp.getcwd()
            if self.auto_close:
                sftp.close()
                if proxy:
                    proxy.close()
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
        try:
            client, proxy = self.connect()
            transport = client.get_transport()
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp_avail = transport.active
        except Exception:
            sftp_avail = False

        if sftp_avail:
            res = sftp.remove(path)
            if self.auto_close:
                sftp.close()
                if proxy:
                    proxy.close()
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
            client, proxy = self.connect()
            transport = client.get_transport()
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp_avail = transport.active
        except Exception:
            sftp_avail = False

        if sftp_avail:
            sftp.chmod(path, mode)
            res = True
            if self.auto_close:
                sftp.close()
                if proxy:
                    proxy.close()
                transport.close()
        else:
            # use chmod over ssh to change permissions
            _, _, status = self.execute("chmod %s %s" % (oct(mode), path))
            res = status == 0

        return res
