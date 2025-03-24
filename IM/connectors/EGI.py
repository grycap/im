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


import base64
import requests
from .CloudConnector import CloudConnector


class EGICloudConnector(CloudConnector):
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
        im_auth = auth_data.getAuthInfo("InfrastructureManager")
        try:
            if im_auth and im_auth[0].get("token"):
                self.log_debug(f"Registering DNS entry {hostname}.{domain} with DyDNS oauth token")
                token = im_auth[0].get("token")
                commennt = 'IM created DNS entry'
                if hostname == "*":
                    url = f'{self.DYDNS_URL}/nic/register?fqdn={domain}&comment={commennt}&wildcard=true'
                else:
                    url = f'{self.DYDNS_URL}/nic/register?fqdn={hostname}.{domain}&comment={commennt}'
                resp = requests.get(url, headers={'Authorization': f'Bearer {token}'}, timeout=self.DEFAULT_TIMEOUT)
                if resp.status_code != 200:
                    self.log_error(f"Error registering DNS entry {hostname}.{domain}: {resp.text}")
                    return False

                resp_json = resp.json()
                if resp_json.get("status") != "ok":
                    self.log_error(f"Error registering DNS entry {hostname}.{domain}:"
                                   f" {resp_json.get('message', 'Unknown error')}")
                    return False
                secret = resp_json.get("host", {}).get("update_secret", "")
            elif hostname.startswith("dydns:") and "@" in hostname:
                self.log_debug(f"Updating DNS entry {hostname}.{domain} with secret")
                parts = hostname[6:].split("@")
                secret = parts[0]
                hostname = parts[1]
                domain = domain[:-1]
            else:
                self.log_error(f"Error updating DNS entry {hostname}.{domain}: No secret nor token provided")
                return False

            auth = f"{hostname}.{domain}:{secret}"
            headers = {"Authorization": "Basic %s" % base64.b64encode(auth.encode()).decode()}
            url = f"https://nsupdate.fedcloud.eu/nic/update?hostname={hostname}.{domain}&myip={ip}"
            resp = requests.get(url, headers=headers, timeout=self.DEFAULT_TIMEOUT)
            if resp.status_code != 200:
                self.log_error(f"Error updating DNS entry {hostname}.{domain}: {resp.text}")
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
