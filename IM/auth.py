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

import json
import re


class Authentication:
    """
    Class to manage the Authentication in the IM to all the components

    This object has a list of dicts with this format:

    id = one; type = OpenNebula; host = osenserve:2633; username = user; password = pass
    type = InfrastructureManager; username = user; password = pass
    type = VMRC; host = http://server:8080/vmrc; username = user; password = pass
    id = ec2; type = EC2; username = ACCESS_KEY; password = SECRET_KEY
    id = oshost; type = OpenStack; host = oshost:8773; username = ACCESS_KEY; key = SECRET_KEY
    id = occi; type = OCCI; host = occiserver:4567; username = user; password = pass

    Arguments:
        - auth_data(list of dicts or :py:class:`IM.Authentication`): Data to initialize the Authentication object
    """

    def __init__(self, auth_data):
        if isinstance(auth_data, Authentication):
            self.auth_list = auth_data.auth_list
        else:
            self.auth_list = auth_data

        for auth in self.auth_list:
            if 'id' in auth and auth['id']:
                pattern = re.compile(r'[a-zA-Z_.][\w\d_.-]*')
                if not pattern.match(auth['id']):
                    raise Exception('Incorrect value in auth item id: %s' % auth['id'])

    def getAuthInfo(self, auth_type, host=None):
        """
        Get the auth data of the specified type

        Arguments:
           - auth_type(str): The auth type
           - host(str): The host of the auth (optional)

        Returns: a list with all the auth data for the specified type
        """
        res = []
        for auth in self.auth_list:
            if 'type' in auth and auth['type'] == auth_type:
                if host:
                    if 'host' in auth and auth['host'].find(host) != -1:
                        res.append(auth)
                else:
                    res.append(auth)

        return res

    def getAuthInfoByID(self, auth_id):
        """
        Get the auth data of the specified id

        Arguments:
           - auth_id(str): The auth id

        Returns: a list with all the auth data for the specified id
        """
        res = []
        for auth in self.auth_list:
            if 'id' in auth and auth['id'] == auth_id:
                res.append(auth)
        return res

    def compare(self, other_auth, auth_type, host=None):
        """
        Compare this auth object with other_auth for the specified type

        Arguments:
           - other_auth(:py:class:`Authentication`): The Authentication object to compare
           - auth_type(str): The auth type
           - host(str): The host of the auth (optional)

        Returns: True if the auth are equal or False otherwise
        """
        try:
            auth_with_type = None
            for auth in self.auth_list:
                if auth['type'] == auth_type:
                    if host:
                        if 'host' in auth and auth['host'].find(host) != -1:
                            auth_with_type = auth
                            break
                    else:
                        auth_with_type = auth
                        break

            other_auth_with_type = None
            for auth in other_auth.auth_list:
                if auth['type'] == auth_type:
                    if host:
                        if 'host' in auth and auth['host'].find(host) != -1:
                            other_auth_with_type = auth
                            break
                    else:
                        other_auth_with_type = auth
                        break

            if auth_with_type is not None and other_auth_with_type is not None:
                if len(auth_with_type) != len(other_auth_with_type):
                    return False

                for key in auth_with_type.keys():
                    if key != "id":
                        if auth_with_type[key] != other_auth_with_type[key]:
                            return False
            else:
                return False

        except Exception:
            return False

        return True

    @staticmethod
    def split_line(line):
        """
        Split line using ; as separator char
        considering single quotes as a way to delimit
        tokens. (in particular to enable using char ; inside a token)
        """
        tokens = []
        token = ""
        in_qoutes = False
        in_dqoutes = False
        for char in line:
            if char == '"' and not in_qoutes:
                in_dqoutes = not in_dqoutes
            elif char == "'" and not in_dqoutes:
                in_qoutes = not in_qoutes
            elif char == ";" and not in_qoutes and not in_dqoutes:
                tokens.append(token)
                token = ""
            else:
                token += char
        # Add the last token
        if token.strip() != "":
            tokens.append(token)

        return tokens

    @staticmethod
    def read_auth_data(filename):
        """
        Read a file to load the Authentication data.
        The file has the following format:

        id = one; type = OpenNebula; host = oneserver:2633; username = user; password = pass
        type = InfrastructureManager; username = user; password = 'pass;test'
        type = VMRC; host = http://server:8080/vmrc; username = user; password = "pass';test"
        id = ec2; type = EC2; username = ACCESS_KEY; password = SECRET_KEY
        id = oshost; type = OpenStack; host = oshost:8773; username = ACCESS_KEY; key = SECRET_KEY
        id = occi; type = OCCI; host = occiserver:4567; username = user; password = file(/tmp/filename)
        id = occi; type = OCCI; proxy = file(/tmp/proxy.pem)

        Arguments:
           - filename(str or list): The filename to read or list of auth lines

        Returns: a list with all the auth data
        """
        if isinstance(filename, list):
            lines = filename
        else:
            auth_file = open(filename, 'r')
            lines = auth_file.readlines()
            auth_file.close()

        res = []

        for line in lines:
            line = line.strip()
            if len(line) > 0 and not line.startswith("#"):
                auth = {}
                tokens = Authentication.split_line(line)
                for token in tokens:
                    key_value = token.split(" = ")
                    if len(key_value) != 2:
                        break
                    else:
                        value = key_value[1].strip().replace("\\n", "\n")
                        # Enable to specify a filename and set the contents of
                        # it
                        if value.startswith("file(") and value.endswith(")"):
                            filename = value[5:len(value) - 1]
                            try:
                                value_file = open(filename, 'r')
                                value = value_file.read()
                                value_file.close()
                            except Exception:
                                pass
                        auth[key_value[0].strip()] = value
                res.append(auth)

        return res

    def serialize(self):
        return json.dumps(self.auth_list, sort_keys=True)

    @staticmethod
    def deserialize(str_data):
        return Authentication(json.loads(str_data))
