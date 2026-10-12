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

try:
    # To avoid annoying InsecureRequestWarning messages in some Connectors
    import requests.packages
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    pass

import json
import os
import subprocess
import tempfile
import time
from optparse import OptionParser, Option, IndentedHelpFormatter, Values
from typing import Any, Dict, Generator, List, Optional, Tuple, Union, Literal

from radl import radl_parse


class PosOptionParser(OptionParser):
    """
    Class to add Help to operations
    """
    def format_help(self, formatter=None):
        """
        Format help
        """
        class Positional(object):
            """
            Positional argument
            """
            def __init__(self, arguments):
                self.option_groups = []
                self.option_list = arguments

        positional = Positional(self.positional)
        formatter = IndentedHelpFormatter()
        formatter.store_option_strings(positional)
        output = ['\n', formatter.format_heading("Operation")]
        formatter.indent()
        pos_help = [formatter.format_option(opt) for opt in self.positional]
        pos_help = [line.replace('--', '') for line in pos_help]
        output += pos_help
        return OptionParser.format_help(self, formatter) + ''.join(output)

    def add_operation_help(self, arg, helpstr):
        """
        Add operation help
        """
        try:
            arguments = self.positional
        except AttributeError:
            arguments = []
        arguments.append(Option('--' + arg, action='store_true', help=helpstr))
        self.positional = arguments

    def set_out(self, out):
        """
        Set out param
        """
        self.out = out


class CmdSsh:
    """
    Class to execute a ssh directly to a VM (from EC3)
    """

    @staticmethod
    def run(radl, show_only=False, cmd=None):
        try:
            if radl.systems[0].getValue("disk.0.os.credentials.private_key"):
                ops = CmdSsh._connect_key(radl)
            else:
                ops = CmdSsh._connect_password(radl)

            if cmd:
                if isinstance(cmd, list):
                    ops.extend(cmd)
                else:
                    ops.append(cmd)

            if show_only:
                for op in ops:
                    if "ProxyCommand" in op:
                        op = "'" + op + "'"
                    print(op, end=" ")
            else:
                os.execlp(ops[0], *ops)
        except OSError as e:
            raise Exception("Error connecting to VM: %s\nProbably 'sshpass' or 'ssh' "
                            "programs are not installed!" % str(e))
        except Exception as e:
            raise Exception("Error connecting to VM: %s" % str(e))

    @staticmethod
    def _get_ssh_port(radl):
        """
        Get the SSH port from the RADL

        Returns: str with the port
        """
        ssh_port = 22

        public_net = None
        for net in radl.networks:
            if net.isPublic():
                public_net = net

        if public_net:
            outports = public_net.getOutPorts() if public_net.getOutPorts() else {}
            for outport in outports:
                if outport.get_local_port() == 22 and outport.get_protocol() == "tcp":
                    ssh_port = outport.get_remote_port()

        return str(ssh_port)

    @staticmethod
    def get_user_pass_host_port(url):
        """
        Returns a tuple parsing values for this kind of urls:
        username:pass@servername.com:port
        """
        username = None
        password = None
        port = None
        if "@" in url:
            parts = url.split("@")
            user_pass = parts[0]
            server_port = parts[1]
            user_pass = user_pass.split(':')
            username = user_pass[0]
            if len(user_pass) > 1:
                password = user_pass[1]
        else:
            server_port = url

        server_port = server_port.split(':')
        server = server_port[0]
        if len(server_port) > 1:
            port = int(server_port[1])

        return username, password, server, port

    @staticmethod
    def _get_proxy_host(radl):
        """
        Return the proxy_host data if available
        """
        for netid in radl.systems[0].getNetworkIDs():
            net = radl.get_network_by_id(netid)
            if net.getValue("proxy_host"):
                user, passwd, ip, port = CmdSsh.get_user_pass_host_port(net.getValue("proxy_host"))
                if not port:
                    port = 22
                return ip, user, passwd, net.getValue("proxy_key"), port
        return None

    @staticmethod
    def _get_proxy_command(radl, ip, username):
        ssh_args = None
        if CmdSsh._get_proxy_host(radl):
            proxy_ip, proxy_user, proxy_pass, proxy_key, proxy_port = CmdSsh._get_proxy_host(radl)
            if proxy_key:
                # we assume that IM has copied it to the proxy host
                proxy_key_filename = "/var/tmp/%s_%s_%s.pem" % (proxy_user, username, ip)
                proxy_command = "ssh -W %%h:%%p -i %s -p %d %s %s@%s" % (proxy_key_filename,
                                                                         proxy_port,
                                                                         "-o StrictHostKeyChecking=no",
                                                                         proxy_user,
                                                                         proxy_ip)
            else:
                proxy_command = "sshpass -p %s ssh -W %%h:%%p -p %d %s %s@%s" % (proxy_pass,
                                                                                 proxy_port,
                                                                                 "-o StrictHostKeyChecking=no",
                                                                                 proxy_user,
                                                                                 proxy_ip)
            ssh_args = ["-o", "ProxyCommand=%s" % proxy_command]

        return ssh_args

    @staticmethod
    def _connect_password(radl):
        ssh_port = CmdSsh._get_ssh_port(radl)
        s = radl.systems[0]
        ip = radl.getPublicIP()
        ssh_args = None
        if not ip:
            ip = radl.getPrivateIP()
            ssh_args = CmdSsh._get_proxy_command(radl, ip, s.getValue("disk.0.os.credentials.username"))

        res = ["sshpass", "-p%s" % s.getValue("disk.0.os.credentials.password"),
               "ssh", "-p", ssh_port, "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no"]

        if ssh_args:
            res.extend(ssh_args)

        res.append("%s@%s" % (s.getValue("disk.0.os.credentials.username"), ip))

        return res

    @staticmethod
    def _connect_key(radl):
        ssh_port = CmdSsh._get_ssh_port(radl)
        s = radl.systems[0]
        f = tempfile.NamedTemporaryFile(mode="w", delete=False)
        f.write(s.getValue("disk.0.os.credentials.private_key"))
        f.close()

        ip = radl.getPublicIP()
        ssh_args = None
        if not ip:
            ip = radl.getPrivateIP()
            ssh_args = CmdSsh._get_proxy_command(radl, ip, s.getValue("disk.0.os.credentials.username"))

        res = ["ssh", "-p", ssh_port, "-i", f.name, "-o", "UserKnownHostsFile=/dev/null",
               "-o", "StrictHostKeyChecking=no"]
        if ssh_args:
            res.extend(ssh_args)
        res.append("%s@%s" % (s.getValue("disk.0.os.credentials.username"), ip))

        return res


class CmdScp():
    """
    Class to execute a scp directly to a VM (from EC3)
    """

    @staticmethod
    def run(radl, op, cmd, show_only=False):
        try:
            if radl.systems[0].getValue("disk.0.os.credentials.private_key"):
                ops = CmdSsh._connect_key(radl)
            else:
                ops = CmdSsh._connect_password(radl)

            pos = ops.index("ssh")
            ops[pos] = "scp"
            ops.insert(pos + 1, "-r")
            pos = ops.index("-p", pos)
            ops[pos] = "-P"

            if op == "put":
                ops[-1] += f":{cmd[1]}"
                ops.insert(-1, cmd[0])
            elif op == "get":
                ops[-1] += f":{cmd[0]}"
                ops.append(cmd[1])
            else:
                raise Exception("Invalid operation: %s" % op)

            if show_only:
                for op in ops:
                    if "ProxyCommand" in op:
                        op = "'" + op + "'"
                    print(op, end=" ")
            else:
                os.execlp(ops[0], *ops)
        except OSError as e:
            raise Exception("Error connecting to VM: %s\nProbably 'sshpass' or 'ssh' "
                            "programs are not installed!" % str(e))
        except Exception as e:
            raise Exception("Error connecting to VM: %s" % str(e))


VMGenerator = Generator[Tuple[str, Optional[str]], None, None]


DescTypes = Literal["radl", "json", "yaml", "yml"]


class IMClient:
    """
    Class to connect with the Infrastructure Manager
    """

    def __init__(self, options: Values, auth_data: Union[str, List[Dict[str, str]], None], args: List[str]) -> None:
        self.args: List[str] = args
        self.server: Optional[str] = None
        self.rest_auth_data: str = IMClient.build_auth_data(auth_data)
        self.options: Values = options
        self.auth_data: Union[str, List[Dict[str, str]], None] = auth_data

    @staticmethod
    def build_auth_data(auth_data: Union[str, List[Dict[str, str]], None]) -> str:
        """
        Build the value of the Authorization header used to authenticate with the IM REST API.

        Arguments:
           - auth_data(string or :py:class:`list` of :py:class:`dict` of str objects): Authentication
             data to access the cloud providers and the IM (as returned by `read_auth_data` function).
        Returns(string): The string to use as the value of the Authorization header.
        """
        rest_auth_data = ""
        if auth_data:
            if isinstance(auth_data, str):
                rest_auth_data = auth_data
            else:
                for item in auth_data:
                    for key, value in item.items():
                        value = value.replace("\n", "\\\\n")
                        rest_auth_data += "%s = %s;" % (key, value)
                    rest_auth_data += "\\n"
        return rest_auth_data

    @staticmethod
    def init_client(im_url: str, auth_data: Union[str, List[Dict[str, str]]], ssl_verify: bool = False) -> "IMClient":
        """
        Create and initialize the IMClient class
        Arguments:
           - im_url(string): URL to the IM API
           - auth_data(:py:class:`dict` of str objects): Authentication data to access cloud provider
                                                         (as returned by `read_auth_data` function).
           - ssl_verify(boolean): Flag to specify if ssl certificates must be validated.
                                  Default `False`.
        Returns(:py:class:`imclient.IMClient`): A client ready to interact with an IM instance.
        """
        options = {"force": False, "quiet": True, "name": None, "system_name": None}
        options["restapi"] = im_url
        options["verify"] = ssl_verify
        return IMClient(Values(options), auth_data, [])

    @staticmethod
    def _replace_auth_values(value: str) -> str:
        # Enable to specify a commnad and set the contents of the output
        if value.startswith("command(") and value.endswith(")"):
            command = value[8:-1]
            return "'%s'" % IMClient._run_command(command)
        # Enable to specify a filename and set the contents of it
        elif value.startswith("file(") and value.endswith(")"):
            try:
                with open(value[5:-1], 'r') as f:
                    data = f.read()
                return "'%s'" % data.strip()
            except Exception:
                pass
        return value

    @staticmethod
    def _split_line(line: str, separator: str = ";", maintain_quotes: bool = False) -> List[str]:
        """
        Split line using ; as separator char
        considering single quotes as a way to delimit
        tokens. (in particular to enable using char ; inside a token)
        """
        tokens = []
        token = ""
        in_qoutes = False
        in_dqoutes = False
        has_quotes = False
        for char in line:
            if char == '"' and not in_qoutes:
                has_quotes = True
                in_dqoutes = not in_dqoutes
                if maintain_quotes:
                    token += char
            elif char == "'" and not in_dqoutes:
                has_quotes = True
                in_qoutes = not in_qoutes
                if maintain_quotes:
                    token += char
            elif char == separator and not in_qoutes and not in_dqoutes:
                tokens.append(token)
                token = ""
            else:
                token += char
        # Add the last token
        if token.strip() != "" or has_quotes:
            tokens.append(token)

        return tokens

    # From IM.auth
    @staticmethod
    def read_auth_data(filename: Union[str, List[str]]) -> Union[str, List[Dict[str, str]]]:
        """
        Read an IM auth data file.
        Arguments:
           - filename(string): path to the IM auth file.
        Returns(:py:class:`list` of `dict` of str objects): Authentication data to access cloud provider and the IM.
        One entry per line, each line splitted in a dictionary of pairs key/value.
        """
        if isinstance(filename, list):
            lines = filename
        else:
            auth_file = open(filename, 'r')
            lines = auth_file.readlines()
            auth_file.close()

        res = []

        if len(lines) == 1 and lines[0].startswith("Bearer "):
            token = lines[0].strip()[7:]
            return "Bearer %s" % IMClient._replace_auth_values(token)

        for line in lines:
            line = line.strip()
            if len(line) > 0 and not line.startswith("#"):
                auth = {}
                for token in IMClient._split_line(line, maintain_quotes=True):
                    key_value = IMClient._split_line(token, "=")
                    if len(key_value) != 2:
                        break
                    else:
                        key = key_value[0].strip()
                        value = key_value[1].strip().replace("\\n", "\n")
                        auth[key] = IMClient._replace_auth_values(value)
                res.append(auth)

        return res

    # fetch the output using the command
    @staticmethod
    def _run_command(cmd: str) -> str:
        proc = subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        outs, errs = proc.communicate()
        if proc.returncode != 0:
            if errs == b'':
                errs = outs
            raise ValueError("Failed to get auth value using command %s: %s" % (cmd, errs.decode('utf-8')))
        return outs.decode('utf-8').replace('\n', '')

    @staticmethod
    def _get_input_params(radl: str) -> str:
        """
        Search for input parameters, ask the user for the values and replace them in the RADL
        """
        pos = 0
        while pos != -1:
            pos = radl.find("@input.", pos)
            if pos != -1:
                pos = pos + 7
                pos_fin = radl.find("@", pos)
                param_name = radl[pos:pos_fin]
                valor = input("Specify parameter " + param_name + ": ")
                radl = radl.replace("@input." + param_name + "@", valor)

        return radl

    @staticmethod
    def _get_master_vm_id(inf_id: str) -> int:
        return 0

    def _get_inf_id(self) -> str:
        if len(self.args) >= 1:
            inf_id = self.args[0]
            if inf_id.isdigit():
                inf_id = int(self.args[0])

            if self.options.name:
                infras = self.list_infras(flt=".*description\\s*.*\\s*(\\s*name\\s*=\\s*'%s'.*).*" % inf_id)
                if len(infras) == 0:
                    raise ValueError("Infrastructure Name not found")
                elif len(infras) >= 1:
                    if len(infras) > 1:
                        print("WARNING!: more that one infrastructure with the same name. First one returned.")
                    return infras[0]
            else:
                return inf_id
        else:
            raise ValueError("Infrastructure ID not specified")

    def _get_vm_id(self) -> str:
        if len(self.args) >= 2:
            return self.args[1]
        else:
            raise ValueError("VM ID not specified")

    def _get_radl(self, param_index: int, fail_if_not_set: bool = True) -> str:
        if len(self.args) > param_index:
            if not os.path.isfile(self.args[param_index]):
                raise ValueError("RADL file '%s' does not exist" % self.args[param_index])
            return self.args[param_index]
        elif fail_if_not_set:
            raise ValueError("RADL file not specified")

    @staticmethod
    def read_input_file(filename: str) -> Tuple[Any, str]:
        # Read the file
        _, file_extension = os.path.splitext(filename)
        f = open(filename)
        radl_data = "".join(f.readlines())
        f.close()
        desc_type = "radl"
        if file_extension in [".yaml", ".yml"]:
            radl = radl_data
            desc_type = "yaml"
        elif file_extension in [".json", ".jsn"]:
            radl = radl_data
            desc_type = "json"
        else:
            # check for input parameters @input.[param_name]@
            radl_data = IMClient._get_input_params(radl_data)
            radl = radl_parse.parse_radl(radl_data)
            radl.check()

        return radl, desc_type

    def create(self, inf_desc: str, desc_type: DescTypes = "radl", asyncr: bool = False, dry_run: bool = False) -> Any:
        """
        Create an infrastructure
        Arguments:
           - inf_desc(string): Infrastructure description in RADL (plain or JSON) or TOSCA.
           - desc_type(string): Infrastructure description type ("radl", "json", "yaml" or "yml")
           - asyncr(boolean): Flag to specify if the creation call will be asynchronous.
                              Default `False`.
           - dry_run(boolean): Flag to specify if the creation call will be a dry run (i.e.,
                               no actual creation). Default `False`.
        Returns: The ID of the created infrastructure.
        Raises: HTTPError if the creation fails.
        """
        inf_id = None
        headers = {"Authorization": self.rest_auth_data}
        if desc_type == "json":
            headers["Content-Type"] = "application/json"
        elif desc_type in "yaml":
            headers["Content-Type"] = "text/yaml"
        url = "%s/infrastructures" % self.options.restapi
        params = {}
        if asyncr:
            params["async"] = "yes"
        if dry_run:
            params["dry_run"] = "yes"
        resp = requests.request("POST", url, verify=self.options.verify, headers=headers,
                                params=params, data=str(inf_desc))
        resp.raise_for_status()
        if dry_run:
            return resp.json()
        else:
            return os.path.basename(resp.text)

    def _create(self) -> Any:
        radl_file = self._get_radl(0)
        asyncr = False
        # by default asyncr is False, but in case of REST API, it is True
        if self.options.restapi:
            asyncr = True
        if len(self.args) >= 2:
            asyncr = bool(int(self.args[1]))

        # Read the file
        radl, desc_type = self.read_input_file(radl_file)

        return self.create(radl, desc_type, asyncr)

    def removeresource(self, inf_id: str, vm_list: List[int], context: Optional[bool] = None) -> List[int]:
        """
        Remove resources from an infrastructure
        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_list(list of strings): List of VM IDs to delete.
           - context(boolean): Flag to disable the contextualization at the end.
        Returns: The list of deleted VM IDs.
        Raises: HTTPError if the deletion fails.
        """
        vm_list_str = ",".join(str(vm_id) for vm_id in vm_list)
        headers = {"Authorization": self.rest_auth_data}
        url = "%s/infrastructures/%s/vms/%s" % (self.options.restapi.rstrip("/"), inf_id, vm_list_str)
        if context is False:
            url += "?context=0"
        resp = requests.request("DELETE", url, verify=self.options.verify, headers=headers)
        resp.raise_for_status()
        return vm_list

    def _removeresource(self) -> List[int]:
        inf_id = self._get_inf_id()
        context = None
        if len(self.args) >= 2:
            vm_list = [int(vm_id) for vm_id in self.args[1].split(",")]

            if len(self.args) >= 3:
                if self.args[2] in ["0", "1"]:
                    context = bool(int(self.args[2]))
                else:
                    raise ValueError("The ctxt flag must be 0 or 1")
        else:
            raise ValueError("VM ID to remove not specified")

        return self.removeresource(inf_id, vm_list, context)

    def addresource(self, inf_id: str, inf_desc: str, desc_type: DescTypes,
                    context: Optional[bool] = None) -> List[str]:
        """
        Add resources into an infrastructure
        Arguments:
           - inf_id(string): Infrastructure ID.
           - inf_desc(string): Infrastructure description in RADL (plain or JSON) or TOSCA.
           - desc_type(string): Infrastructure description type ("radl", "json", "yaml" or "yml")
           - context(boolean): Flag to disable the contextualization at the end.
        Returns: The list of added VM IDs.
        Raises: HTTPError if the addition fails.
        """
        headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
        if desc_type in "yaml":
            headers["Content-Type"] = "text/yaml"
        elif desc_type == "json":
            headers["Content-Type"] = "application/json"
        url = "%s/infrastructures/%s" % (self.options.restapi, inf_id)
        params = {}
        if context is False:
            params["context"] = "0"
        resp = requests.request("POST", url, verify=self.options.verify, headers=headers,
                                data=str(inf_desc), params=params)
        resp.raise_for_status()
        vms_id = []
        for elem in resp.json()["uri-list"]:
            vms_id.append(os.path.basename(list(elem.values())[0]))

        return vms_id

    def _addresource(self) -> List[str]:
        inf_id = self._get_inf_id()
        radl_file = self._get_radl(1)
        context = None
        if len(self.args) >= 3:
            if self.args[2] in ["0", "1"]:
                context = bool(int(self.args[2]))
            else:
                raise ValueError("The ctxt flag must be 0 or 1")

        radl, desc_type = self.read_input_file(radl_file)

        return self.addresource(inf_id, radl, desc_type, context)

    def alter(self, inf_id: str, vm_id: str, inf_desc: str) -> str:
        """
        Modifies the features of a VM
        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_id(string): VM ID.
           - inf_desc(string): Infrastructure description in RADL (plain).
        Returns: The RADL of the modified VM.
        Raises: HTTPError if the alteration fails.
        """
        headers = {"Authorization": self.rest_auth_data}
        url = "%s/infrastructures/%s/vms/%s" % (self.options.restapi, inf_id, vm_id)
        resp = requests.request("PUT", url, verify=self.options.verify, headers=headers, data=str(inf_desc))
        resp.raise_for_status()
        return resp.text

    def _alter(self) -> str:
        inf_id = self._get_inf_id()
        vm_id = self._get_vm_id()
        radl_file = self._get_radl(2)

        radl = radl_parse.parse_radl(radl_file)

        return self.alter(inf_id, vm_id, radl)

    def reconfigure(self, inf_id: str, inf_desc: str, desc_type: DescTypes = "radl",
                    vm_list: Optional[List[int]] = None) -> None:
        """
        Reconfigure the infrastructure
        Arguments:
           - inf_id(string): Infrastructure ID.
           - inf_desc(string): Infrastructure description in RADL (plain), JSON or YAML.
           - vm_list(list of strings): Optional list of VM IDs to reconfigure (default all).
        Raises: HTTPError if the reconfiguration fails.
        """
        headers = {"Authorization": self.rest_auth_data}
        if desc_type == "json":
            headers["Content-Type"] = "application/json"
        elif desc_type in "yaml":
            headers["Content-Type"] = "text/yaml"
        url = "%s/infrastructures/%s/reconfigure" % (self.options.restapi, inf_id)
        params = {}
        if vm_list:
            params["vm_list"] = ",".join(str(vm_id) for vm_id in vm_list)
        resp = requests.request("PUT", url, verify=self.options.verify, headers=headers,
                                data=str(inf_desc), params=params)
        resp.raise_for_status()

    def _reconfigure(self) -> None:
        inf_id = self._get_inf_id()
        radl = ""
        vm_list = None
        radl_file = self._get_radl(1, False)
        desc_type = "radl"
        if len(self.args) >= 3:
            vm_list = [int(vm_id) for vm_id in self.args[2].split(",")]

        if radl_file:
            # Read the file
            radl, desc_type = self.read_input_file(radl_file)

        return self.reconfigure(inf_id, radl, desc_type, vm_list)

    def get_infra_property(self, inf_id: str, prop: str) -> Any:
        """
        Get an infrastructure property.

        Arguments:
           - inf_id(string): Infrastructure ID.
           - prop(string): Property to get. Valid values: "radl", "contmsg", "state", "outputs"
        Returns: The value of the property.
        Raises: HTTPError if the operation fails.
        """
        headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
        url = "%s/infrastructures/%s/%s" % (self.options.restapi, inf_id, prop)
        resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
        resp.raise_for_status()
        return resp.json()[prop]

    def _get_infra_property(self, prop: str) -> Any:
        inf_id = self._get_inf_id()
        return self.get_infra_property(inf_id, prop)

    def _getvmcontmsg(self) -> str:
        inf_id = self._get_inf_id()
        vm_id = self._get_vm_id()
        return self.getvminfo(inf_id, vm_id, "contmsg")

    def getvminfo(self, inf_id: str, vm_id: str, prop: Optional[str] = None, system_name: Optional[str] = None) -> str:
        """
        Get VM info.

        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_id(string): VM ID.
           - prop(string): Optional RADL property to get.
           - system_name(string): Optional system name to filter the VMs.
        Returns: The value of the property.
        Raises: HTTPError if the operation fails.
        """
        headers = {"Authorization": self.rest_auth_data}
        url = "%s/infrastructures/%s/vms/%s" % (self.options.restapi, inf_id, vm_id)
        if prop and not system_name:
            url += "/" + prop
        resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
        resp.raise_for_status()
        if system_name:
            radl_info = radl_parse.parse_radl(resp.text)
            if radl_info.systems[0].name == system_name:
                if prop:
                    info = radl_info.systems[0].getValue(prop)
                else:
                    info = resp.text
            else:
                info = ""
        else:
            info = resp.text

        return info

    def _getvminfo(self) -> str:
        inf_id = self._get_inf_id()
        vm_id = self._get_vm_id()

        prop = None
        if len(self.args) >= 3:
            prop = self.args[2]

        return self.getvminfo(inf_id, vm_id, prop)

    def _get_vms_info_generator(self, inf_id: str, vm_ids: List[str], prop: Optional[str],
                                system_name: Optional[str]) -> VMGenerator:
        """Helper function to return a generator."""
        for vm_id in vm_ids:
            try:
                radl = self.getvminfo(inf_id, vm_id, prop, system_name)
            except Exception:
                radl = None
            yield vm_id, radl

    def getinfo(self, inf_id: str, prop: Optional[str] = None, system_name: Optional[str] = None) -> VMGenerator:
        """
        Get infrastructure info.

        Arguments:
           - inf_id(string): Infrastructure ID.
           - prop(string): Optional RADL property to get.
           - system_name(string): Optional system name to filter the VMs.
        Returns: A generator yielding the property for each VM in the infrastructure.
        Raises: HTTPError if the operation fails.
        """
        headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
        url = "%s/infrastructures/%s" % (self.options.restapi, inf_id)
        resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
        resp.raise_for_status()
        vm_ids = []
        for elem in resp.json()["uri-list"]:
            vm_ids.append(os.path.basename(list(elem.values())[0]))

        return self._get_vms_info_generator(inf_id, vm_ids, prop, system_name)

    def _getinfo(self) -> VMGenerator:
        inf_id = self._get_inf_id()
        prop = None
        if len(self.args) >= 2:
            prop = self.args[1]

        return self.getinfo(inf_id, prop, self.options.system_name)

    def destroy(self, inf_id: str, asyncr: bool = False) -> None:
        """
        Destroy an infrastructure

        Arguments:
           - inf_id(string): Infrastructure ID.
           - asyncr(boolean): Flag to specify if the deletion call will be asynchronous.
                              Default `False`.
        Raises: HTTPError if the deletion fails.
        """
        headers = {"Authorization": self.rest_auth_data}
        url = "%s/infrastructures/%s" % (self.options.restapi, inf_id)
        params = {}
        if self.options.force:
            params["force"] = "yes"
        if asyncr:
            params["async"] = "yes"
        resp = requests.request("DELETE", url, verify=self.options.verify, headers=headers, params=params)
        resp.raise_for_status()

    def _destroy(self):
        inf_id = self._get_inf_id()
        if not self.options.yes:
            res = input(f"Are you sure you want to destroy Inf:{inf_id}?\n"
                        "This process cannot be undone!!.\n(yes/no):").strip().lower()
        else:
            res = "yes"

        if res == "yes":
            return self.destroy(inf_id)
        else:
            raise ValueError("Canceled by the user.")

    def list_infras(self, flt: Optional[str] = None) -> List[str]:
        """
        Get the list of user infrastructures

        Arguments:
           - flt(string): Optional filter (as regular expression) to filter the infrastructures.
        Returns: The list of infrastructure IDs matching the filter.
        Raises: HTTPError if the operation fails.
        """
        headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
        url = "%s/infrastructures" % self.options.restapi
        if flt:
            url += "?filter=%s" % flt
        resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
        resp.raise_for_status()
        res = []
        for elem in resp.json()["uri-list"]:
            res.append(os.path.basename(list(elem.values())[0]))

        return res

    def _list_infras(self, show_name: bool = False, flt: Optional[str] = None) -> Union[List[str], Dict[str, str]]:
        if flt is None and len(self.args) >= 1:
            flt = self.args[0]

        res = self.list_infras(flt)

        if show_name:
            inf_names = {}
            for inf_id in res:
                inf_names[inf_id] = "N/A"
                try:
                    radl_data = self.get_infra_property(inf_id, "radl")
                    radl = radl_parse.parse_radl(radl_data)
                    if radl.description and radl.description.getValue("name"):
                        inf_names[inf_id] = radl.description.getValue("name")
                except Exception:
                    pass
            res = inf_names

        return res

    def start_infra(self, inf_id: str) -> None:
        """
        Start an infrastructure (previously stopped)

        Arguments:
           - inf_id(string): Infrastructure ID.
        Raises: HTTPError if the operation fails.
        """
        self.infra_op(inf_id, "start")

    def stop_infra(self, inf_id: str) -> None:
        """
        Stop an infrastructure

        Arguments:
           - inf_id(string): Infrastructure ID.
        Raises: HTTPError if the operation fails.
        """
        self.infra_op(inf_id, "stop")

    def infra_op(self, inf_id: str, operation: str) -> None:
        """
        Call an infrastructure operation (start or stop)

        Arguments:
           - inf_id(string): Infrastructure ID.
           - operation(string): Operation to call: "start" or "stop".
        Raises: HTTPError if the operation fails.
        """
        headers = {"Authorization": self.rest_auth_data}
        url = "%s/infrastructures/%s/%s" % (self.options.restapi, inf_id, operation)
        resp = requests.request("PUT", url, verify=self.options.verify, headers=headers)
        resp.raise_for_status()

    def _infra_op(self, operation: str) -> None:
        inf_id = self._get_inf_id()
        self.infra_op(inf_id, operation)

    def start_vm(self, inf_id: str, vm_id: str) -> None:
        """
        Start an VM (previously stopped)

        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_id(string): VM ID.
        Raises: HTTPError if the operation fails.
        """
        self.vm_op(inf_id, vm_id, "start")

    def stop_vm(self, inf_id: str, vm_id: str) -> None:
        """
        Stop an VM

        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_id(string): VM ID.
        Raises: HTTPError if the operation fails.
        """
        self.vm_op(inf_id, vm_id, "stop")

    def reboot_vm(self, inf_id: str, vm_id: str) -> None:
        """
        Reboot an VM

        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_id(string): VM ID.
        Raises: HTTPError if the operation fails.
        """
        self.vm_op(inf_id, vm_id, "reboot")

    def vm_op(self, inf_id: str, vm_id: str, operation: str) -> None:
        """
        Call a VM operation (start, stop or reboot)

        Arguments:
           - inf_id(string): Infrastructure ID.
           - vm_id(string): VM ID.
           - operation(string): Operation to call: "start", "stop" or "reboot".
        Raises: HTTPError if the operation fails.
        """
        headers = {"Authorization": self.rest_auth_data}
        url = "%s/infrastructures/%s/vms/%s/%s" % (self.options.restapi, inf_id, vm_id, operation)
        resp = requests.request("PUT", url, verify=self.options.verify, headers=headers)
        resp.raise_for_status()

    def _vm_op(self, operation: str) -> None:
        inf_id = self._get_inf_id()
        vm_id = self._get_vm_id()
        self.vm_op(inf_id, vm_id, operation)

    def _ssh(self, operation: str) -> Tuple[radl_parse.RADL, bool, List[str] | None]:
        inf_id = self._get_inf_id()
        show_only = False
        master_vm_id = None
        cmd = None
        if operation in ["ssh", "put", "get"]:
            master_vm_id = self._get_master_vm_id(inf_id)
            vm_id = master_vm_id
            if len(self.args) >= 2:
                if self.args[1] in ["0", "1"]:
                    show_only = bool(int(self.args[1]))
                else:
                    raise ValueError("The show_only flag must be 0 or 1")
                if len(self.args) >= 3:
                    cmd = self.args[2:]
        else:
            if len(self.args) >= 2:
                vm_id = self.args[1]
                if len(self.args) >= 3:
                    if self.args[2] in ["0", "1"]:
                        show_only = bool(int(self.args[2]))
                    else:
                        raise ValueError("The show_only flag must be 0 or 1")
                    if len(self.args) >= 4:
                        cmd = self.args[3:]
            else:
                raise ValueError("VM ID to get info not specified")

        self.args = [inf_id, vm_id]
        vm_info = self._getvminfo()
        radl = radl_parse.parse_radl(vm_info)

        proxy_host = False
        for netid in radl.systems[0].getNetworkIDs():
            net = radl.get_network_by_id(netid)
            if net.getValue("proxy_host"):
                proxy_host = True

        if not radl.getPublicIP() and master_vm_id is None and not proxy_host:
            vm_id = IMClient._get_master_vm_id(inf_id)
            if not self.options.quiet:
                print("VM ID %s does not has public IP, try to access via VM ID 0." % vm_id)

            self.args = [inf_id, vm_id]
            vm_info = self._getvminfo()

            radl2 = radl_parse.parse_radl(vm_info)
            host = radl2.getPublicIP()
            username = radl2.systems[0].getValue("disk.0.os.credentials.username")
            password = radl2.systems[0].getValue("disk.0.os.credentials.password")
            priv_key = radl2.systems[0].getValue("disk.0.os.credentials.private_key")

            for netid in radl.systems[0].getNetworkIDs():
                net = radl.get_network_by_id(netid)
                if password:
                    proxy_host = "%s:%s@%s" % (username, password, host)
                elif priv_key:
                    proxy_host = "%s@%s" % (username, host)
                    net.setValue('proxy_key', priv_key)
                    proxy_key_filename = "/var/tmp/%s_%s_%s.pem" % (username, username, radl.getPrivateIP())
                    with open(proxy_key_filename, "w") as f:
                        f.write(priv_key)
                    os.chmod(proxy_key_filename, 0o600)
                else:
                    raise ValueError("Error, no valid credentials in VM 0")
                net.setValue('proxy_host', proxy_host)

        return radl, show_only, cmd

    def getversion(self) -> str:
        """
        Get IM server version

        Returns: The version string.
        Raises: HTTPError if the operation fails.
        """
        url = "%s/version" % self.options.restapi
        resp = requests.request("GET", url, verify=self.options.verify)
        resp.raise_for_status()
        return resp.text

    def export_data(self, inf_id: str, delete: Optional[bool] = None) -> dict:
        """
        Export infrastructure data

        Arguments:
           - inf_id(string): Infrastructure ID.
           - delete(boolean): Flag to specify if the infrastructure will be deleted after exporting the data.
                              Default `False`.
        Returns: The json data of the infrastructure.
        Raises: HTTPError if the operation fails.
        """
        if len(self.args) >= 2:
            delete = bool(int(self.args[1]))

        headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
        url = "%s/infrastructures/%s/data" % (self.options.restapi, inf_id)
        if delete:
            url += "?delete=yes"
        resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
        resp.raise_for_status()
        return resp.json()["data"]

    def _export_data(self) -> dict:
        inf_id = self._get_inf_id()
        delete = None
        if len(self.args) >= 2:
            delete = bool(int(self.args[1]))
        return self.export_data(inf_id, delete)

    def import_data(self, data: str) -> str:
        """
        Import infrastructure data

        Arguments:
           - data(string): Json data with the Infrastructure info.
        Returns: The ID of the imported infrastructure.
        Raises: HTTPError if the operation fails.
        """
        headers = {"Authorization": self.rest_auth_data}
        url = "%s/infrastructures" % self.options.restapi
        resp = requests.request("PUT", url, verify=self.options.verify, headers=headers, data=data)
        resp.raise_for_status()
        return os.path.basename(resp.text)

    def _import_data(self) -> str:
        if len(self.args) >= 1:
            if not os.path.isfile(self.args[0]):
                raise ValueError("JSON file '" + self.args[0] + "' does not exist")
        else:
            raise ValueError("JSON file to create inf. not specified")

        f = open(self.args[0])
        data = "".join(f.readlines())
        f.close()

        return self.import_data(data)

    def get_cloud_images(self, cloud_id: str) -> list:
        """
        Get Cloud provider images

        Arguments:
           - cloud_id(string): ID of the cloud provider (as defined in the auth data).
        Returns: The list of images available in the cloud provider.
        Raises: HTTPError if the operation fails.
        """
        return self.get_cloud_info(cloud_id, "images")

    def get_cloud_quotas(self, cloud_id: str) -> dict:
        """
        Get Cloud provider quotas

        Arguments:
           - cloud_id(string): ID of the cloud provider (as defined in the auth data).
        Returns: The quotas available in the cloud provider.
        Raises: HTTPError if the operation fails.
        """
        return self.get_cloud_info(cloud_id, "quotas")

    def get_cloud_info(self, cloud_id: str, operation: str) -> requests.Response:
        """
        Get Cloud provider info

        Arguments:
           - cloud_id(string): ID of the cloud provider (as defined in the auth data).
           - operation(string): Type of information to get: "images" or "quotas".
        Returns: The response of the REST API call with the requested information.
        Raises: HTTPError if the operation fails.
        """
        headers = {"Authorization": self.rest_auth_data, "Accept": "application/json"}
        url = "%s/clouds/%s/%s" % (self.options.restapi, cloud_id, operation)
        resp = requests.request("GET", url, verify=self.options.verify, headers=headers)
        resp.raise_for_status()
        return resp.json()[operation]

    def _get_cloud_info(self, operation: str) -> list | dict:
        if not len(self.args) >= 1:
            raise ValueError("Cloud ID not specified")

        cloud_id = self.args[0]
        return self.get_cloud_info(cloud_id, operation)

    def _wait(self):
        self._get_inf_id()
        max_time = 36000  # 10h
        if len(self.args) >= 2:
            max_time = int(self.args[1])
        unknown_count = 0
        wait = 0
        state = "pending"
        while state in ["pending", "running", "unknown"] and unknown_count < 3 and wait < max_time:

            try:
                res = self._get_infra_property("state")
                state = res['state']
            except Exception:
                state = "unknown"

            if state == "unknown":
                unknown_count += 1

            if state in ["pending", "running", "unknown"]:
                if not self.options.quiet:
                    print("The infrastructure is in state: %s. Wait ..." % state)
                time.sleep(30)
                wait += 30

        if state == "configured":
            return "The infrastructure is in state: %s" % state
        elif wait >= max_time:
            raise TimeoutError("Timeout waiting.")
        else:
            raise Exception("The infrastructure is in state: %s" % state)

    def change_auth(self, inf_id: str, new_auth_data: List[Dict[str, str]], overwrite: Optional[bool] = None) -> None:
        """
        Change ownership of an infrastructure

        Arguments:
           - inf_id(string): Infrastructure ID.
           - new_auth_data(string): New Infrastructure Manager auth data to set.
           - overwrite(boolean): Flag to specify if the auth data will be overwrited.
                                 Default `False`.
        Raises: HTTPError if the operation fails.
        """
        headers = {"Authorization": self.rest_auth_data}
        url = "%s/infrastructures/%s/authorization" % (self.options.restapi, inf_id)
        if overwrite:
            url += "?overwrite=1"
        resp = requests.request("POST", url, verify=self.options.verify,
                                headers=headers, data=json.dumps(new_auth_data[0]))
        resp.raise_for_status()

    def _change_auth(self):
        inf_id = self._get_inf_id()
        if len(self.args) >= 2:
            if not os.path.isfile(self.args[1]):
                raise ValueError("New auth file '" + self.args[1] + "' does not exist")
        else:
            raise ValueError("JSON file to create inf. not specified")

        new_auth_data = []
        for elem in IMClient.read_auth_data(self.args[1]):
            if "type" in elem and elem["type"] == "InfrastructureManager":
                new_auth_data.append(elem)
                break

        if not new_auth_data:
            raise ValueError("No new InfrastructureManager auth provided.")

        overwrite = False
        if len(self.args) >= 3:
            if self.args[2] in ["0", "1"]:
                overwrite = bool(int(self.args[2]))
            else:
                raise ValueError("The overwrite flag must be 0 or 1")

        self.change_auth(inf_id, new_auth_data, overwrite)
