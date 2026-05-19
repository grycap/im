# IM - Infrastructure Manager
# Copyright (C) 2024 - GRyCAP - Universitat Politecnica de Valencia
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

import uuid
import re
import requests

from urllib.parse import urlparse
from IM.VirtualMachine import VirtualMachine
from IM.connectors.exceptions import NoAuthData, NoCorrectAuthData, CloudConnectorException
from .CloudConnector import CloudConnector
from radl.radl import Feature
from IM.SSH import SSH


class HetznerCloudConnector(CloudConnector):
    """
    Cloud Launcher to Hetzner Cloud using the REST API
    https://docs.hetzner.cloud/
    """

    type = "Hetzner"
    """str with the name of the provider."""

    DEFAULT_USER = 'root'
    """ default user to SSH access the VM """
    DEFAULT_LOCATION = 'fsn1'
    """ Hetzner default location (Falkenstein, Germany) """
    HETZNER_API_URL = "https://api.hetzner.cloud/v1"
    """ Hetzner Cloud API URL """
    HETZNER_DNS_API_URL = "https://dns.hetzner.com/api/v1"
    """ Hetzner DNS API URL """

    # Mapping of Hetzner server status to IM VM states
    VM_STATE_MAP = {
        "initializing": VirtualMachine.PENDING,
        "starting": VirtualMachine.PENDING,
        "running": VirtualMachine.RUNNING,
        "stopping": VirtualMachine.RUNNING,
        "stopped": VirtualMachine.STOPPED,
        "deleting": VirtualMachine.RUNNING,
        "deleted": VirtualMachine.OFF,
        "migrating": VirtualMachine.RUNNING,
        "rebuilding": VirtualMachine.PENDING
    }
    """State map"""

    def __init__(self, cloud_info, inf):
        self.api_token = None
        super().__init__(cloud_info, inf)

    def _get_auth_token(self, auth_data):
        """
        Get the API token from auth data

        Arguments:
            - auth_data(Authentication): Authentication data

        Returns: str with the API token
        """
        auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise NoAuthData(self.type)

        auth = auths[0]
        if 'token' not in auth:
            raise NoCorrectAuthData(self.type, "token")

        return auth['token']

    def _make_request(self, method, endpoint, auth_data, data=None):
        """
        Make an HTTP request to the Hetzner API

        Arguments:
            - method(str): HTTP method (GET, POST, DELETE, etc.)
            - endpoint(str): API endpoint path (e.g., '/servers')
            - auth_data(Authentication): Authentication data
            - data(dict): Request body data

        Returns: response object
        """
        if not self.api_token:
            self.api_token = self._get_auth_token(auth_data)

        url = self.HETZNER_API_URL + endpoint
        headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }

        try:
            resp = requests.request(method.upper(), url, headers=headers, json=data, verify=self.verify_ssl)
            if resp.status_code >= 400:
                error_msg = f"Hetzner API error ({resp.status_code}): {resp.text}"
                self.log_error(error_msg)
                raise CloudConnectorException(error_msg)

            return resp
        except requests.RequestException as ex:
            raise CloudConnectorException(f"Error communicating with Hetzner API: {str(ex)}")

    def _get_dns_token(self, auth_data):
        """
        Get the DNS API token from auth data.

        It first tries the explicit field 'dns_token' and falls back to
        provider 'token'.
        """
        auths = auth_data.getAuthInfo(self.type)
        if not auths:
            raise NoAuthData(self.type)

        auth = auths[0]
        if auth.get('dns_token'):
            return auth.get('dns_token')
        if auth.get('token'):
            return auth.get('token')

        raise NoCorrectAuthData(self.type, "dns_token")

    def _make_dns_request(self, method, endpoint, auth_data, data=None):
        """
        Make an HTTP request to Hetzner DNS API.
        """
        dns_token = self._get_dns_token(auth_data)
        url = self.HETZNER_DNS_API_URL + endpoint
        headers = {
            'Auth-API-Token': dns_token,
            'Content-Type': 'application/json'
        }

        try:
            resp = requests.request(method.upper(), url, headers=headers, json=data,
                                    verify=self.verify_ssl, timeout=30)
            if resp.status_code >= 400:
                error_msg = f"Hetzner DNS API error ({resp.status_code}): {resp.text}"
                raise CloudConnectorException(error_msg)
            return resp
        except requests.RequestException as ex:
            raise CloudConnectorException(f"Error communicating with Hetzner DNS API: {str(ex)}")

    def _get_dns_zone(self, domain, auth_data):
        """
        Get (or create) the DNS zone for a domain.
        """
        clean_domain = domain[:-1] if domain.endswith('.') else domain
        resp = self._make_dns_request('GET', f'/zones?name={clean_domain}', auth_data)
        zones = resp.json().get('zones', [])
        if zones:
            self.log_info("DNS zone %s exists. Do not create." % clean_domain)
            return zones[0]

        self.log_info("Creating DNS zone %s" % clean_domain)
        resp = self._make_dns_request('POST', '/zones', auth_data, data={'name': clean_domain})
        return resp.json().get('zone')


    def get_instance_type(self, radl, auth_data=None, location_id=None):
        """
        Get the best matching server type for the RADL requirements

        Arguments:
            - radl(RADL): RADL document with VM requirements
            - auth_data(Authentication): Authentication data
            - location_id(str): Optional location ID

        Returns: dict with server type info
        """
        try:
            resp = self._make_request('GET', '/server_types', auth_data)
            resp.raise_for_status()
            server_types = resp.json()['server_types']
        except Exception as ex:
            self.log_error(f"Error getting server types: {str(ex)}")
            return None

        instance_type_name = radl.getValue('instance_type')
        (cpu, cpu_op, memory, memory_op, disk_free, disk_free_op) = self.get_instance_selectors(radl, mem_unit='G', disk_unit='G')

        # Filter and sort server types
        valid_types = []
        for stype in server_types:
            comparison = cpu_op(stype['cores'], cpu)
            comparison = comparison and memory_op(stype['memory'], memory)
            comparison = comparison and disk_free_op(stype['disk'], disk_free)

            if comparison:
                if not instance_type_name or stype['name'] == instance_type_name:
                    valid_types.append(stype)
                elif instance_type_name and "*" in instance_type_name:
                    instance_type_re = re.escape(instance_type_name).replace("\\*", ".*")
                    if re.match(instance_type_re, stype['name']):
                        valid_types.append(stype)

        if not valid_types:
            self.log_error("No compatible server type found")
            return None

        # Sort by price (ascending)
        valid_types.sort(key=lambda x: x['prices'][0]['monthly'] if x['prices'] else float('inf'))
        return valid_types[0]

    def get_image_id(self, path):
        """
        Get image ID from the image URL

        Arguments:
            - path(str): Image URL (e.g., 'htz://ubuntu-22.04')

        Returns: str with image ID/name
        """
        url = urlparse(path)
        return url.netloc + url.path if url.netloc else url.path

    def get_location(self, location_name, auth_data):
        """
        Get location by name or ID

        Arguments:
            - location_name(str): Location ID or name
            - auth_data(Authentication): Authentication data

        Returns: dict with location info or None
        """
        try:
            resp = self._make_request('GET', '/locations', auth_data)
            resp.raise_for_status()
            locations = resp.json()['locations']

            for loc in locations:
                if loc['id'] == location_name or loc['name'].lower() == location_name.lower():
                    return loc

            self.log_error(f"Location not found: {location_name}")
            return None
        except Exception as ex:
            self.log_error(f"Error getting locations: {str(ex)}")
            return None

    def get_image(self, image_id, auth_data):
        """
        Get image by ID or name

        Arguments:
            - image_id(str): Image ID or name
            - auth_data(Authentication): Authentication data

        Returns: dict with image info or None
        """
        try:
            resp = self._make_request('GET', '/images', auth_data)
            resp.raise_for_status()
            images = resp.json()['images']

            for img in images:
                if str(img['id']) == image_id or img['name'] == image_id or img['description'] == image_id:
                    return img

            self.log_error(f"Image not found: {image_id}")
            return None
        except Exception as ex:
            self.log_error(f"Error getting images: {str(ex)}")
            return None

    def get_ssh_keys(self, auth_data):
        """
        Get list of SSH keys

        Arguments:
            - auth_data(Authentication): Authentication data

        Returns: list of SSH key dicts
        """
        try:
            resp = self._make_request('GET', '/ssh_keys', auth_data)
            resp.raise_for_status()
            return resp.json()['ssh_keys']
        except Exception as ex:
            self.log_error(f"Error getting SSH keys: {str(ex)}")
            return []

    def create_ssh_key(self, key_name, public_key, auth_data):
        """
        Create an SSH key in Hetzner

        Arguments:
            - key_name(str): Name for the key
            - public_key(str): Public key content
            - auth_data(Authentication): Authentication data

        Returns: dict with SSH key info or None
        """
        try:
            data = {
                'name': key_name,
                'public_key': public_key
            }
            resp = self._make_request('POST', '/ssh_keys', auth_data, data=data)
            resp.raise_for_status()
            return resp.json()['ssh_key']
        except Exception as ex:
            self.log_error(f"Error creating SSH key: {str(ex)}")
            return None

    def concrete_system(self, radl_system, str_url, auth_data):
        """
        Get a concrete system for Hetzner based on image URL

        Arguments:
            - radl_system(RADL system): System RADL
            - str_url(str): Image URL
            - auth_data(Authentication): Authentication data

        Returns: RADL system or None
        """
        url = urlparse(str_url)
        protocol = url.scheme

        if protocol == "htz":
            res_system = radl_system.clone()
            image_id = self.get_image_id(str_url)

            # Get image info
            image = self.get_image(image_id, auth_data)
            if not image:
                return None

            # Get server type info
            instance_type = self.get_instance_type(res_system, auth_data)
            if instance_type:
                res_system.addFeature(Feature("instance_type", "=", instance_type['name']),
                                      conflict="other", missing="other")
                res_system.addFeature(Feature("cpu.count", "=", instance_type['cores']),
                                      conflict="me", missing="other")
                res_system.addFeature(Feature("memory.size", "=", instance_type['memory'], 'G'),
                                      conflict="me", missing="other")
                res_system.addFeature(Feature("disk.0.free_size", "=", instance_type['disk'], 'G'),
                                      conflict="other", missing="other")

            res_system.setValue('disk.0.os.credentials.username', self.DEFAULT_USER)
            return res_system
        else:
            return None

    def get_server_by_id(self, server_id, auth_data):
        """
        Get server info by ID

        Arguments:
            - server_id(str): Server ID
            - auth_data(Authentication): Authentication data

        Returns: dict with server info or None
        """
        try:
            resp = self._make_request('GET', f'/servers/{server_id}', auth_data)
            resp.raise_for_status()
            return resp.json()['server']
        except Exception as ex:
            self.log_error(f"Error getting server {server_id}: {str(ex)}")
            return None

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        """
        Create new VMs in Hetzner Cloud

        Arguments:
            - inf(InfrastructureInfo): Infrastructure info
            - radl(RADL): System RADL
            - requested_radl(RADL): Requested RADL
            - num_vm(int): Number of VMs to create
            - auth_data(Authentication): Authentication data

        Returns: list of tuples (success, vm)
        """
        self.api_token = self._get_auth_token(auth_data)
        system = radl.systems[0]

        # Get required resources
        image_id = self.get_image_id(system.getValue("disk.0.image.url"))
        image = self.get_image(image_id, auth_data)
        if not image:
            return [(False, f"Image not found: {image_id}") for _ in range(num_vm)]

        # Get server type
        instance_type = self.get_instance_type(system)
        if not instance_type:
            return [(False, "No compatible server type found") for _ in range(num_vm)]

        # Get location
        availability_zone = system.getValue('availability_zone')
        if availability_zone:
            location = self.get_location(availability_zone, auth_data)
        else:
            location = self.get_location(self.DEFAULT_LOCATION, auth_data)

        if not location:
            return [(False, "Location not found") for _ in range(num_vm)]

        # Handle SSH keys
        public_key = system.getValue("disk.0.os.credentials.public_key")
        private_key = system.getValue('disk.0.os.credentials.private_key')

        if not public_key:
            (public_key, private_key) = SSH.keygen()
            system.setValue('disk.0.os.credentials.private_key', private_key)

        # Create or find SSH key
        ssh_key_id = None
        key_name = f"im-key-{str(uuid.uuid1())[:8]}"
        ssh_key = self.create_ssh_key(key_name, public_key, auth_data)
        if ssh_key:
            ssh_key_id = ssh_key['id']

        res = []
        for i in range(num_vm):
            instance_name = self.gen_instance_name(system)[:63]
            if instance_name[-1:] == "-":
                instance_name = instance_name[:-1]

            data = {
                'name': instance_name,
                'server_type': instance_type['id'],
                'image': image['id'],
                'location': location['id']
            }

            if ssh_key_id:
                data['ssh_keys'] = [ssh_key_id]

            # Add labels from tags
            labels = self.get_instance_tags(system, auth_data, inf)
            if labels:
                data['labels'] = labels

            try:
                resp = self._make_request('POST', '/servers', auth_data, data=data)
                resp.raise_for_status()
                server_data = resp.json()['server']

                vm = VirtualMachine(inf, None, self.cloud, radl, requested_radl,
                                   self.cloud.getCloudConnector(inf))
                vm.id = str(server_data['id'])
                vm.info.systems[0].setValue('instance_id', str(server_data['id']))
                vm.info.systems[0].setValue('instance_name', server_data['name'])

                user = system.getValue('disk.0.os.credentials.username')
                if not user:
                    user = self.DEFAULT_USER
                    vm.info.systems[0].setValue('disk.0.os.credentials.username', user)

                inf.add_vm(vm)
                res.append((True, vm))
                self.log_debug(f"Server {server_data['id']} successfully created")

            except Exception as ex:
                res.append((False, f"Error creating server: {str(ex)}"))
                self.log_exception("Error creating server")

        return res

    def updateVMInfo(self, vm, auth_data):
        """
        Update VM info from Hetzner

        Arguments:
            - vm(VirtualMachine): VM to update
            - auth_data(Authentication): Authentication data

        Returns: tuple (success, vm)
        """
        server = self.get_server_by_id(vm.id, auth_data)
        if not server:
            self.log_warn(f"Server {vm.id} not found")
            return (False, f"Server {vm.id} not found")

        # Update state
        vm.state = self.VM_STATE_MAP.get(server['status'], VirtualMachine.UNKNOWN)

        # Update IPs
        self.setIPsFromInstance(vm, server)
        self.manage_dns_entries("add", vm, auth_data)

        return (True, vm)

    def setIPsFromInstance(self, vm, server):
        """
        Set VM IPs from server info

        Arguments:
            - vm(VirtualMachine): VM to update
            - server(dict): Server info from API
        """
        if 'public_net' in server and server['public_net']:
            public_net = server['public_net']
            if 'ipv4' in public_net and public_net['ipv4']:
                vm.info.systems[0].setValue('net_interface.0.ip', public_net['ipv4']['ip'])
            if 'ipv6' in public_net and public_net['ipv6']:
                vm.info.systems[0].setValue('net_interface.1.ip', public_net['ipv6']['ip'])

    def finalize(self, vm, last, auth_data):
        """
        Destroy a VM in Hetzner

        Arguments:
            - vm(VirtualMachine): VM to destroy
            - last(boolean): True if last VM
            - auth_data(Authentication): Authentication data

        Returns: tuple (success, message)
        """
        try:
            self._make_request('DELETE', f'/servers/{vm.id}', auth_data)
            self.manage_dns_entries("del", vm, auth_data)
            self.log_debug(f"Server {vm.id} successfully destroyed")
            return (True, "")
        except Exception as ex:
            self.log_error(f"Error destroying server {vm.id}: {str(ex)}")
            return (False, str(ex))

    def add_dns_entry(self, hostname, domain, ip, auth_data, extra_args=None):
        """
        Add DNS A record in Hetzner DNS.
        """
        try:
            zone = self._get_dns_zone(domain, auth_data)
            if not zone:
                self.log_warn("Cannot create/find DNS zone %s" % domain)
                return False

            zone_id = zone.get('id')
            if not zone_id:
                self.log_warn("DNS zone %s has no id" % domain)
                return False

            record_name = hostname if hostname != "@" else "@"
            fqdn = "%s.%s" % (hostname, domain[:-1] if domain.endswith('.') else domain)

            resp = self._make_dns_request('GET', f'/records?zone_id={zone_id}', auth_data)
            records = resp.json().get('records', [])
            record = [r for r in records if r.get('type') == 'A' and
                      r.get('name') == record_name and r.get('value') == ip]
            if record:
                self.log_info("DNS record %s exists. Do not create." % fqdn)
                return True

            self.log_info("Creating DNS record %s." % fqdn)
            data = {
                'zone_id': zone_id,
                'type': 'A',
                'name': record_name,
                'value': ip,
                'ttl': 300
            }
            self._make_dns_request('POST', '/records', auth_data, data=data)
            return True
        except NoCorrectAuthData:
            self.log_warn("No Hetzner DNS token configured. DNS record not created.")
            return False
        except Exception:
            self.log_exception("Error creating DNS entries")
            return False

    def del_dns_entry(self, hostname, domain, ip, auth_data, extra_args=None):
        """
        Delete DNS A record in Hetzner DNS.
        """
        try:
            clean_domain = domain[:-1] if domain.endswith('.') else domain
            zone_resp = self._make_dns_request('GET', f'/zones?name={clean_domain}', auth_data)
            zones = zone_resp.json().get('zones', [])
            if not zones:
                self.log_info("The DNS zone %s does not exists. Do not delete records." % clean_domain)
                return True

            zone = zones[0]
            zone_id = zone.get('id')
            if not zone_id:
                self.log_warn("DNS zone %s has no id" % clean_domain)
                return False

            record_name = hostname if hostname != "@" else "@"
            fqdn = "%s.%s" % (hostname, clean_domain)
            resp = self._make_dns_request('GET', f'/records?zone_id={zone_id}', auth_data)
            records = resp.json().get('records', [])
            record = [r for r in records if r.get('type') == 'A' and r.get('name') == record_name]
            if not record:
                self.log_info("DNS record %s does not exists. Do not delete." % fqdn)
                return True

            record = record[0]
            if record.get('value') != ip:
                self.log_info("DNS record %s mapped to unexpected IP: %s != %s."
                              "Do not delete." % (fqdn, record.get('value'), ip))
                return True

            self.log_info("Deleting DNS record %s." % fqdn)
            self._make_dns_request('DELETE', '/records/%s' % record.get('id'), auth_data)
            return True
        except NoCorrectAuthData:
            self.log_warn("No Hetzner DNS token configured. DNS record not deleted.")
            return False
        except Exception:
            self.log_exception("Error deleting DNS entries")
            return False

    def start(self, vm, auth_data):
        """
        Start a stopped VM

        Arguments:
            - vm(VirtualMachine): VM to start
            - auth_data(Authentication): Authentication data

        Returns: tuple (success, message)
        """
        try:
            data = {'action': 'poweron'}
            self._make_request('POST', f'/servers/{vm.id}/actions/power_on', auth_data, data={})
            return (True, "")
        except Exception as ex:
            return (False, str(ex))

    def stop(self, vm, auth_data):
        """
        Stop a running VM

        Arguments:
            - vm(VirtualMachine): VM to stop
            - auth_data(Authentication): Authentication data

        Returns: tuple (success, message)
        """
        try:
            self._make_request('POST', f'/servers/{vm.id}/actions/power_off', auth_data, data={})
            return (True, "")
        except Exception as ex:
            return (False, str(ex))

    def reboot(self, vm, auth_data):
        """
        Reboot a VM

        Arguments:
            - vm(VirtualMachine): VM to reboot
            - auth_data(Authentication): Authentication data

        Returns: tuple (success, message)
        """
        try:
            self._make_request('POST', f'/servers/{vm.id}/actions/reboot', auth_data, data={})
            return (True, "")
        except Exception as ex:
            return (False, str(ex))

    def alterVM(self, vm, radl, auth_data):
        """
        Modify VM configuration (not fully supported in Hetzner)

        Arguments:
            - vm(VirtualMachine): VM to modify
            - radl(str): RADL with desired configuration
            - auth_data(Authentication): Authentication data

        Returns: tuple (success, message)
        """
        return (False, "Altering VM is not fully supported in Hetzner Cloud connector")

    def list_images(self, auth_data, filters=None):
        """
        List available images in Hetzner Cloud, optionally filtered by distribution/version.
        Returns a list of dicts with 'uri' and 'name' keys, matching the format of other connectors.
        """
        try:
            resp = self._make_request('GET', '/images', auth_data)
            resp.raise_for_status()
            images = resp.json().get('images', [])
        except Exception as ex:
            self.log_error(f"Error getting images: {str(ex)}")
            return []

        def match(img):
            if not filters:
                return True
            # Distribution
            if 'distribution' in filters and filters['distribution']:
                dist = filters['distribution'].lower()
                if dist not in img.get('name','').lower() and dist not in img.get('description','').lower():
                    return False
            # Version
            if 'version' in filters and filters['version']:
                ver = filters['version'].lower()
                if ver not in img.get('name','').lower() and ver not in img.get('description','').lower():
                    return False
            # Name
            if 'name' in filters and filters['name']:
                if filters['name'].lower() not in img.get('name','').lower():
                    return False
            # Type
            if 'type' in filters and filters['type']:
                if img.get('type') != filters['type']:
                    return False
            return True

        result = []
        for img in images:
            if match(img):
                # Compose a URI similar to other connectors: htz://<name>
                uri = f"htz://{img.get('name')}"
                name = img.get('description') or img.get('name')
                result.append({'uri': uri, 'name': name})
        return result
