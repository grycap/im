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

import sys
from IM.connectors import *
from IM.uriparse import uriparse


class CloudInfo:
    """
    Class to represent the information of a cloud provider
    """

    def __init__(self):
        self.id = None
        """Identifier of the cloud provider"""
        self.type = ""
        """Type of the cloud provider"""
        self.server = ""
        """Server of the cloud provider"""
        self.port = -1
        """Port of the cloud provider"""
        self.protocol = ""
        """Protocol to connect to the cloud provider"""
        self.path = ""
        """Path to connect to the cloud provider"""

    def getCloudConnector(self):
        """
        Returns the appropriate object to contact the cloud provider
        """
        if len(self.type) > 15 or "." in self.type:
            raise Exception("Not valid cloud provider.")
        try:
            return getattr(sys.modules['IM.connectors.' + self.type], self.type + "CloudConnector")(self)
        except Exception, ex:
            raise Exception("Cloud provider not supported: %s (error: %s)" % (self.type, str(ex)))

    def __str__(self):
        res = ""

        if self.id:
            res += "id = " + self.id + ", "
        res += "type = " + self.type + ", "
        if self.server:
            res += "server = " + self.server + ", "
        if self.protocol:
            res += "protocol = " + self.protocol + ", "
        if self.port != -1:
            res += "port = " + str(self.port) + ", "

        return res

    @staticmethod
    def get_cloud_list(auth_data):
        """
        Get the list of cloud providers from the authentication data
        """
        res = []

        for i, auth in enumerate(auth_data.auth_list):
            if auth['type'] not in ['InfrastructureManager', 'VMRC']:
                cloud_item = CloudInfo()
                cloud_item.type = auth['type']
                if 'id' in auth.keys() and auth['id']:
                    cloud_item.id = auth['id']
                else:
                    # We need an ID, so generate one
                    cloud_item.id = cloud_item.type + str(i)
                try:
                    if 'host' in auth and auth['host']:
                        if auth['host'].find('://') == -1:
                            uri = uriparse("NONE://" + auth['host'])
                        else:
                            uri = uriparse(auth['host'])
                            if uri[0]:
                                cloud_item.protocol = uri[0]

                        if not uri[1]:
                            raise Exception("Incorrect format of host in auth line: %s" % str(auth))

                        parts = uri[1].split(":")
                        cloud_item.server = parts[0]
                        if len(parts) > 1:
                            if parts[1].isdigit():
                                cloud_item.port = int(parts[1])
                            else:
                                raise Exception("Incorrect value for port '%s'. It must be an integer." % parts[1])

                        # If there is a path
                        if uri[2]:
                            cloud_item.path = uri[2]
                except:
                    pass

                res.append(cloud_item)

        return res
