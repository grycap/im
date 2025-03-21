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


import requests
from .CloudConnector import CloudConnector


class EGI(CloudConnector):
    """
    Cloud connector for the EGI cloud provider, that allows to manage the DNS entries with DyDNS service
    """

    type = "EGI"
    """str with the name of the provider."""
    DYDNS_URL = "https://nsupdate.fedcloud.eu"
    DEFAULT_TIMEOUT = 10

    def add_dns_entry(self, hostname, domain, ip, auth_data, extra_args=None):
        """
        Add a DNS entry to the DNS server
        """
        try:
            token = auth_data.getAuthInfo("InfrastructureManager")[0].get("token")
            commennt = 'IM created DNS entry'
            url = f'{self.DYDNS_URL}/nic/register?name={hostname}&domain={domain}&comment={commennt}&ip={ip}'
            resp = requests.get(url, headers={'Authorization Bearer': token}, timeout=self.DEFAULT_TIMEOUT)
            if resp.status_code != 200:
                self.log_error(f"Error registering DNS entry {hostname}.{domain}: {resp.text}")
                return False
            return True
        except Exception as e:
            self.log_error(f"Error registering DNS entry {hostname}.{domain}: {str(e)}")
            return False

    def delete_dns_entry(self, hostname, domain, auth_data, extra_args=None):
        """
        Delete a DNS entry from the DNS server
        """
        raise NotImplementedError("Should have implemented this")
