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

    def getAuthInfo(self, auth_type, host=None):
        """
        Get the auth data of the specified type

        Arguments:
           - auth_type(str): The auth type

        Returns: a list with all the auth data for the specified type
        """
        res = []
        for auth in self.auth_list:
            if auth['type'] == auth_type:
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
            if auth['id'] == auth_id:
                res.append(auth)
        return res

    def compare(self, other_auth, auth_type):
        """
        Compare this auth object with other_auth for the specified type

        Arguments:
           - other_auth(:py:class:`Authentication`): The Authentication object to compare
           - auth_type(str): The auth type

        Returns: True if the auth are equal or False otherwise
        """
        try:
            auth_with_type = None
            for auth in self.auth_list:
                if auth['type'] == auth_type:
                    auth_with_type = auth
                    break

            other_auth_with_type = None
            for auth in other_auth.auth_list:
                if auth['type'] == auth_type:
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
    def read_auth_data(filename):
        """
        Read a file to load the Authentication data.
        The file has the following format:

        id = one; type = OpenNebula; host = osenserve:2633; username = user; password = pass
        type = InfrastructureManager; username = user; password = pass
        type = VMRC; host = http://server:8080/vmrc; username = user; password = pass
        id = ec2; type = EC2; username = ACCESS_KEY; password = SECRET_KEY
        id = oshost; type = OpenStack; host = oshost:8773; username = ACCESS_KEY; key = SECRET_KEY
        id = occi; type = OCCI; host = occiserver:4567; username = user; password = file(/tmp/filename)
        id = occi; type = OCCI; proxy = file(/tmp/proxy.pem)

        Arguments:
           - filename(str): The filename to read

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
                tokens = line.split(";")
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
                            except:
                                pass
                        auth[key_value[0].strip()] = value
                res.append(auth)

        return res
