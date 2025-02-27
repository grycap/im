# IM - Infrastructure Manager
# Copyright (C) 2022 - GRyCAP - Universitat Politecnica de Valencia
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
import json
import requests
from IM.VirtualMachine import VirtualMachine
from .CloudConnector import CloudConnector
from IM.connectors.exceptions import NoAuthData, NoCorrectAuthData, CloudConnectorException
from radl.radl import Feature
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


class OSCARCloudConnector(CloudConnector):
    """
    Cloud Launcher to create OSCAR functions.
    """

    type = "OSCAR"
    """str with the name of the provider."""

    def __init__(self, cloud_info, inf):
        self.auth = None
        if cloud_info.path and cloud_info.path.endswith("/"):
            cloud_info.path = cloud_info.path[:-1]
        CloudConnector.__init__(self, cloud_info, inf)

    def concrete_system(self, radl_system, str_url, auth_data):
        url = urlparse(str_url)
        protocol = url[0]
        src_host = url[1].split(':')[0]

        # protocol should be oscar, docker, or empty in case of using a single image string
        # but the system must have the name and script properties
        if ((radl_system.getValue('name') and radl_system.getValue('script')) and
                (not radl_system.getValue('provider.type') or radl_system.getValue('provider.type') == "oscar") and
                ((protocol == "oscar" and self.cloud.server == src_host) or protocol in ["docker", ""])):
            res_system = radl_system.clone()
            res_system.setValue('disk.0.os.credentials.username', 'oscar')
            return res_system
        else:
            return None

    def _get_auth_header(self, auth_data):
        auths = auth_data.getAuthInfo(self.type, self.cloud.server)
        if not auths:
            raise NoAuthData(self.type)
        else:
            auth = auths[0]

        # Store auth to get it from TOSCA get_attribute
        if self.auth is None:
            self.auth = auth

        if 'username' in auth and 'password' in auth:
            user_pass = "%s:%s" % (auth['username'], auth['password'])
            encoded = base64.b64encode(user_pass.encode("utf-8")).decode("utf-8")
            return "Basic %s" % encoded
        elif 'token' in auth:
            return "Bearer %s" % auth['token']
        else:
            self.log_error("No correct auth data has been specified to OSCAR: username and password or token")
            raise NoCorrectAuthData(self.type, "username and password or token")

    @staticmethod
    def _get_storage_info(radl_system, service):
        for elem in ["input", "output"]:
            ioelems = []
            i = 0
            while radl_system.getValue("%s.%d.provider" % (elem, i)):
                ioelem = {
                    "storage_provider": radl_system.getValue("%s.%d.provider" % (elem, i)),
                    "path": radl_system.getValue("%s.%d.path" % (elem, i))
                }
                if radl_system.getValue("%s.%d.suffix" % (elem, i)):
                    ioelem['suffix'] = radl_system.getValue("%s.%d.suffix" % (elem, i))
                if radl_system.getValue("%s.%d.prefix" % (elem, i)):
                    ioelem['prefix'] = radl_system.getValue("%s.%d.prefix" % (elem, i))
                ioelems.append(ioelem)
                i += 1

            if ioelems:
                service[elem] = ioelems

        storage_providers = {}
        cont = {"minio": 0, "s3": 0, "onedata": 0}
        for provider_type in ["minio", "s3", "onedata"]:
            provider_pref = "%s.0" % provider_type
            while radl_system.getValue("%s.id" % provider_pref):
                sid = radl_system.getValue("%s.id" % provider_pref)
                if provider_type not in storage_providers:
                    storage_providers[provider_type] = {}
                if sid not in storage_providers[provider_type]:
                    storage_providers[provider_type][sid] = {}
                for elem in ['access_key', 'secret_key', 'region', 'endpoint',
                             'verify', 'oneprovider_host', 'token', 'space']:
                    value = radl_system.getValue("%s.%s" % (provider_pref, elem))
                    if value:
                        storage_providers[provider_type][sid][elem] = value

                cont[provider_type] += 1
                provider_pref = "%s.%d" % (provider_type, cont[provider_type])

        if storage_providers:
            service["storage_providers"] = storage_providers

    @staticmethod
    def _get_env_variables(radl_system):
        env_vars = {}
        for elem in radl_system.getValue("environment.variables", []):
            parts = elem.split(":")
            env_vars[parts[0]] = ":".join(parts[1:])
        return env_vars

    @staticmethod
    def _get_service_json(radl_system):
        service = {}

        if radl_system.getValue("name"):
            service["name"] = radl_system.getValue("name")
        if radl_system.getValue("memory.size"):
            service["memory"] = "%dMi" % radl_system.getFeature('memory.size').getValue('Mi')
        if radl_system.getValue("cpu.count"):
            service["cpu"] = "%g" % radl_system.getValue("cpu.count")
        if radl_system.getValue("gpu.count"):
            service["enable_gpu"] = True
        if radl_system.getValue("cpu.sgx"):
            service["enable_sgx"] = True
        if radl_system.getValue("script"):
            service["script"] = radl_system.getValue("script")
        if radl_system.getValue("alpine"):
            service["alpine"] = True
        if radl_system.getValue("image_pull_secrets"):
            secrets = radl_system.getValue("image_pull_secrets")
            if not isinstance(secrets, list):
                secrets = [secrets]
            service["image_pull_secrets"] = secrets

        expose = {}
        for elem in ["min_scale", "max_scale", "port", "cpu_threshold"]:
            if radl_system.getValue("expose.%s" % elem):
                expose[elem] = radl_system.getValue("expose.%s" % elem)
        if expose:
            service["expose"] = expose

        if radl_system.getValue("disk.0.image.url"):
            url_image = urlparse(radl_system.getValue("disk.0.image.url"))
            image = ""
            if url_image.scheme == "docker":
                image = "%s%s" % (url_image[1], url_image[2])
            elif url_image.scheme == "":
                image = url_image[2]
            elif url_image.scheme == "oscar":
                image = url_image[2][1:]
            else:
                raise CloudConnectorException("Invalid image protocol: oscar, docker or empty are supported.")
            service["image"] = image

        env_vars = OSCARCloudConnector._get_env_variables(radl_system)
        if env_vars:
            service["environment"] = {"Variables": env_vars}

        OSCARCloudConnector._get_storage_info(radl_system, service)

        return service

    def wait_for_dependencies(self, radl, inf):
        deps = radl.systems[0].getValue("dependencies")
        if deps:
            vm_deps = {}
            for elem in deps:
                for vm in inf.get_vm_list():
                    if vm.info.systems[0].name == elem:
                        vm_deps[elem] = vm.is_configured()
                        break
                if elem not in vm_deps:
                    self.log_warn("Dependency '%s' not found in VMs." % elem)
                    vm_deps[elem] = False
            return not all(vm_deps.values())
        else:
            return False

    def launch(self, inf, radl, requested_radl, num_vm, auth_data):
        res = []

        if num_vm != 1:
            self.log_warn("Num VM is not 1. Ignoring.")

        vm_id = radl.systems[0].getValue("name")
        vm = VirtualMachine(inf, vm_id, self.cloud,
                            requested_radl, requested_radl)
        vm.destroy = True
        vm.info.systems[0].setValue('provider.type', self.type)
        vm.info.systems[0].setValue('instance_id', str(vm_id))
        inf.add_vm(vm)

        if self.wait_for_dependencies(radl, inf):
            vm.destroy = False
            vm.state = VirtualMachine.PENDING
            res.append((True, vm))
        else:
            try:
                url = "%s/system/services" % self.cloud.get_url()
                service = self._get_service_json(radl.systems[0])
                headers = {"Authorization": self._get_auth_header(auth_data)}
                response = requests.request("POST", url, data=json.dumps(service),
                                            headers=headers, verify=self.verify_ssl)
                if response.status_code == 201:
                    vm.destroy = False
                    vm.state = VirtualMachine.RUNNING
                    res.append((True, vm))
                else:
                    msg = "Error code %d: %s" % (response.status_code, response.text)
                    res.append((False, msg))
            except Exception as ex:
                self.log_exception("Error creating OSCAR function: %s." % ex)
                res.append((False, "%s" % ex))

        return res

    def finalize(self, vm, last, auth_data):
        if vm.state == VirtualMachine.PENDING:
            vm.state = VirtualMachine.OFF
            return True, ""

        try:
            url = "%s/system/services/%s" % (self.cloud.get_url(), vm.id)
            headers = {"Authorization": self._get_auth_header(auth_data)}
            response = requests.request("DELETE", url, headers=headers, verify=self.verify_ssl)
            if response.status_code == 404:
                self.log_warn("OSCAR function '%s' does not exist. Ignore." % vm.id)
                return True, ""
            elif response.status_code != 204:
                msg = "Error code %d: %s" % (response.status_code, response.text)
                return False, msg
        except Exception as ex:
            self.log_exception("Error deletting OSCAR function: %s." % ex)
            return False, "%s" % ex

        return True, ""

    def update_system_info_from_service_info(self, system, service_info):
        if "cpu" in service_info and service_info["cpu"]:
            system.addFeature(Feature("cpu.count", "=", float(service_info["cpu"])),
                              conflict="other", missing="other")
        if "memory" in service_info and service_info["memory"]:
            memory = self.convert_memory_unit(service_info["memory"], "Mi")
            system.addFeature(Feature("memory.size", "=", memory, "Mi"),
                              conflict="other", missing="other")
        if "script" in service_info and service_info["script"]:
            system.addFeature(Feature("script", "=", service_info["script"]),
                              conflict="other", missing="other")
        if "image" in service_info and service_info["image"]:
            image = "oscar://%s/%s" % (self.cloud.server, service_info["image"])
            system.addFeature(Feature("disk.0.image.url", "=", image),
                              conflict="other", missing="other")
        if "token" in service_info and service_info["token"]:
            system.addFeature(Feature("token", "=", service_info["token"]),
                              conflict="other", missing="other")
        # TODO: Complete with all fields

    def updateVMInfo(self, vm, auth_data):
        if vm.state == VirtualMachine.PENDING:
            if self.wait_for_dependencies(vm.info, vm.inf):
                self.log_info("OSCAR function '%s' waiting for dependencies." % vm.id)
                return True, vm
            else:
                try:
                    self.log_info("OSCAR function '%s' dependencies fullfiled. Creating." % vm.id)
                    url = "%s/system/services" % self.cloud.get_url()
                    service = self._get_service_json(vm.info.systems[0])
                    headers = {"Authorization": self._get_auth_header(auth_data)}
                    response = requests.request("POST", url, data=json.dumps(service),
                                                headers=headers, verify=self.verify_ssl)
                    if response.status_code == 201:
                        vm.state = VirtualMachine.RUNNING
                    else:
                        self.log_error("Error creating OSCAR function: %s." % response.text)
                        vm.state = VirtualMachine.FAILED
                        vm.error_msg = response.text
                except Exception as ex:
                    self.log_exception("Error creating OSCAR function.")
                    vm.state = VirtualMachine.FAILED
                    vm.error_msg = "%s" % ex

                return True, vm
        else:
            try:
                url = "%s/system/services/%s" % (self.cloud.get_url(), vm.id)
                headers = {"Authorization": self._get_auth_header(auth_data)}
                response = requests.request("GET", url, headers=headers, verify=self.verify_ssl)
                if response.status_code == 404:
                    if vm.state == VirtualMachine.PENDING:
                        self.log_warn("OSCAR function '%s' does not exist. Maintain it as PENDING." % vm.id)
                    else:
                        vm.state = VirtualMachine.OFF
                        self.log_warn("OSCAR function '%s' does not exist. Set as OFF." % vm.id)
                    return True, vm
                elif response.status_code != 200:
                    msg = "Error code %d: %s" % (response.status_code, response.text)
                    return False, msg
                else:
                    vm.state = VirtualMachine.RUNNING
                    self.update_system_info_from_service_info(vm.info.systems[0], response.json())
                    return True, vm
            except Exception as ex:
                self.log_exception("Error getting OSCAR function: %s." % ex)
                return False, "%s" % ex

    def alterVM(self, vm, radl, auth_data):
        try:
            service = self._get_service_json(radl.systems[0])
            url = "%s/system/services/%s" % (self.cloud.get_url(), vm.id)
            headers = {"Authorization": self._get_auth_header(auth_data)}
            response = requests.request("PUT", url, data=json.dumps(service), headers=headers, verify=self.verify_ssl)
            if response.status_code == 404:
                vm.state = VirtualMachine.OFF
                return True, vm
            elif response.status_code != 204:
                msg = "Error code %d: %s" % (response.status_code, response.text)
                return False, msg
            else:
                self.update_system_info_from_service_info(vm.info.systems[0], service)
                return True, vm
        except Exception as ex:
            self.log_exception("Error getting OSCAR function: %s." % ex)
            return False, "%s" % ex
