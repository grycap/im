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

    @staticmethod
    def _get_domains(token, domain_name=None):
        """
        List the domains available in the DyDNS service
        """
        url = f'{EGICloudConnector.DYDNS_URL}/nic/domains'
        resp = requests.get(url, headers={'Authorization': f'Bearer {token}'},
                            timeout=EGICloudConnector.DEFAULT_TIMEOUT)
        if resp.status_code != 200:
            return None, resp.text
        output = resp.json()
        if output.get("status") != "ok":
            return None, output.get('message', 'Unknown error')
        domains = []
        for domain in output.get("private", []) + output.get("public", []):
            if domain.get("available"):
                domains.append(domain["name"])
        # If a specific domain name is requested, check if it exists
        if domain_name:
            if domain_name in domains:
                return domain_name, ""
            return None, f"Domain {domain_name} not found in DyDNS service"
        return domains, ""

    @staticmethod
    def _get_host(hostname, domain, token):
        """
        Look for a host registered in the DyDNS service
        """
        if hostname == "*":
            parts = domain.split(".")
            domain = ".".join(parts[1:])
            hostname = parts[0]
        url = f'{EGICloudConnector.DYDNS_URL}/nic/hosts?domain={domain}'
        resp = requests.get(url, headers={'Authorization': f'Bearer {token}'},
                            timeout=EGICloudConnector.DEFAULT_TIMEOUT)
        if resp.status_code != 200:
            return None, resp.text

        output = resp.json()
        if output.get("status") != "ok":
            return None, output.get('message', 'Unknown error')

        for host in output.get("hosts", []):
            if host.get("name") == hostname:
                return host, ""

        return None, ""

    @staticmethod
    def _get_wildcard_host_domain(hostname, domain):
        wildcard = False
        if hostname == "*":
            parts = domain.split(".")
            domain = ".".join(parts[1:])
            hostname = parts[0]
            wildcard = True
        return hostname, domain, wildcard

    def add_dns_entry(self, hostname, domain, ip, auth_data, extra_args=None):
        """
        Add a DNS entry to the DNS server
        """
        domain = domain[:-1] if domain.endswith(".") else domain
        im_auth = auth_data.getAuthInfo("InfrastructureManager")
        try:
            secret = None
            if im_auth and im_auth[0].get("token"):
                self.log_debug(f"Registering DNS entry {hostname}.{domain} with DyDNS oauth token")
                token = im_auth[0].get("token")

                hostname, domain, wildcard = EGICloudConnector._get_wildcard_host_domain(hostname, domain)

                _, error = EGICloudConnector._get_domains(token, domain)
                if error:
                    self.log_error(f"Error getting domains: {error}")
                    return False

                # Check if the host already exists
                host, error = EGICloudConnector._get_host(hostname, domain, token)
                if error:
                    self.log_error(f"Error getting host {hostname}.{domain}: {error}")
                if host:
                    self.log_debug(f"DNS entry {hostname}.{domain} already exists")
                    if ip in [host.get("ipv4"), host.get("ipv6")]:
                        print(f"DNS entry {hostname}.{domain} already has the IP {ip}")
                        return True
                else:
                    commennt = 'IM created DNS entry'
                    url = f'{EGICloudConnector.DYDNS_URL}/nic/register?fqdn={hostname}.{domain}&comment={commennt}'
                    if wildcard:
                        url += '&wildcard=true'
                    resp = requests.get(url, headers={'Authorization': f'Bearer {token}'},
                                        timeout=EGICloudConnector.DEFAULT_TIMEOUT)
                    if resp.status_code != 200:
                        self.log_error(f"Error registering DNS entry {hostname}.{domain}: {resp.text}")
                        return False

                    resp_json = resp.json()
                    if resp_json.get("status") != "ok":
                        self.log_error(f"Error registering DNS entry {hostname}.{domain}:"
                                       f" {resp_json.get('message', 'Unknown error')}")
                        return False
            elif hostname.startswith("dydns:") and "@" in hostname:
                self.log_debug(f"Updating DNS entry {hostname}.{domain} with secret")
                parts = hostname[6:].split("@")
                secret = parts[0]
                hostname = parts[1]
            else:
                self.log_error(f"Error updating DNS entry {hostname}.{domain}: No secret nor token provided")
                return False

            if secret:
                auth = f"{hostname}.{domain}:{secret}"
                headers = {"Authorization": "Basic %s" % base64.b64encode(auth.encode()).decode()}
            else:
                headers = {'Authorization': f'Bearer {token}'}

            fqdn = f'{hostname}.{domain}'
            if hostname == "*":
                fqdn = domain
            url = f'{EGICloudConnector.DYDNS_URL}/nic/update?hostname={fqdn}&myip={ip}'
            resp = requests.get(url, headers=headers, timeout=EGICloudConnector.DEFAULT_TIMEOUT)
            if resp.status_code != 200:
                self.log_error(f"Error updating DNS entry {hostname}.{domain}: {resp.text}")
                return False
            return True
        except Exception as e:
            self.log_error(f"Error registering DNS entry {hostname}.{domain}: {str(e)}")
            return False

    def del_dns_entry(self, hostname, domain, ip, auth_data, extra_args=None):
        """
        Delete a DNS entry from the DNS server
        """
        domain = domain[:-1] if domain.endswith(".") else domain
        im_auth = auth_data.getAuthInfo("InfrastructureManager")
        try:
            if im_auth and im_auth[0].get("token"):
                self.log_debug(f"Deleting DNS entry {hostname}.{domain} with DyDNS oauth token")
                token = im_auth[0].get("token")

                hostname, domain, _ = EGICloudConnector._get_wildcard_host_domain(hostname, domain)

                _, error = EGICloudConnector._get_domains(token, domain)
                if error:
                    self.log_error(f"Error getting domains: {error}")
                    return False

                host, error = EGICloudConnector._get_host(hostname, domain, token)
                if error:
                    self.log_error(f"Error getting host {hostname}.{domain}: {error}")
                if not host:
                    self.log_debug(f"DNS entry {hostname}.{domain} does not exist. Do not need to delete.")
                    return True

                url = f'{EGICloudConnector.DYDNS_URL}/nic/unregister?fqdn={hostname}.{domain}'
                resp = requests.get(url, headers={'Authorization': f'Bearer {token}'},
                                    timeout=EGICloudConnector.DEFAULT_TIMEOUT)
                if resp.status_code != 200:
                    self.log_error(f"Error deleting DNS entry {hostname}.{domain}: {resp.text}")
                    return False
            else:
                self.log_error(f"Error updating DNS entry {hostname}.{domain}: No token provided")
                return False
        except Exception as e:
            self.log_error(f"Error deleting DNS entry {hostname}.{domain}: {str(e)}")
            return False

        return True
