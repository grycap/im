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
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


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
        self.extra = {}
        """Extra fields needed to represent the cloud provider (e.g. tenant, domain ...)"""

    def getCloudConnector(self, inf):
        """
        Returns the appropriate object to contact the cloud provider
        """
        if len(self.type) > 15 or "." in self.type:
            raise Exception("Not valid cloud provider.")
        try:
            module = __import__('IM.connectors.' + self.type, fromlist=[self.type + "CloudConnector"])
            return getattr(module, self.type + "CloudConnector")(self, inf)
        except Exception as ex:
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
    def add_extra_fields(auth, cloud_item):
        # Add extra fields in case of OpenStack and EGI sites
        if 'type' in auth and auth['type'] == "OpenStack":
            # This should be the same as OpenStackCloudConnector.DEFAULT_AUTH_VERSION
            auth_version = auth['auth_version'] if 'auth_version' in auth else "2.0_password"
            cloud_item.extra['auth_version'] = auth_version
            if auth_version == "3.x_oidc_access_token":
                # in this case username represents the identity provider
                if 'username' in auth and auth['username']:
                    cloud_item.extra['username'] = auth['username']
                # and the domain the project/tenant name
                if 'domain' in auth and auth['domain']:
                    cloud_item.extra['domain'] = auth['domain']
            elif "password" in auth_version:
                if 'tenant' in auth and auth['tenant']:
                    cloud_item.extra['tenant'] = auth['tenant']
        elif 'type' in auth and auth['type'] == "EGI":
            if 'vo' in auth and auth['vo']:
                cloud_item.extra["vo"] = auth['vo']

    @staticmethod
    def get_cloud_list(auth_data):
        """
        Get the list of cloud providers from the authentication data
        """
        res = []

        for i, auth in enumerate(auth_data.auth_list):
            if 'type' in auth and auth['type'] not in ['InfrastructureManager', 'VMRC', 'AppDBIS']:
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
                            uri = urlparse("NONE://" + auth['host'])
                        else:
                            uri = urlparse(auth['host'])
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
                except Exception:
                    pass

                # Add extra fields in case of OpenStack and EGI sites
                CloudInfo.add_extra_fields(auth, cloud_item)

                res.append(cloud_item)

        return res

    def serialize(self):
        return json.dumps(self.__dict__)

    @staticmethod
    def deserialize(str_data):
        dic = json.loads(str_data)
        nwecloud = CloudInfo()
        nwecloud.__dict__.update(dic)
        return nwecloud

    def get_port(self):
        protocol = self.protocol or "http"
        port = self.port
        if port == -1:
            if protocol == "http":
                port = 80
            elif protocol == "https":
                port = 443
        return port

    def get_url(self):
        protocol = self.protocol or "http"
        if not protocol:
            protocol = "http"
        return protocol + "://" + self.server + ":" + str(self.get_port()) + self.path
