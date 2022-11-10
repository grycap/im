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

import os
import yaml
import tempfile
from IM.VirtualMachine import VirtualMachine
from radl.radl import Feature
from .CloudConnector import CloudConnector
from scar.providers.aws.controller import AWS
from scar.providers.aws.lambdafunction import Lambda, ClientError
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


class LambdaCloudConnector(CloudConnector):
    """
    Cloud Launcher to create Lambda functions.
    """

    type = "Lambda"
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
                (not radl_system.getValue('provider.type') or radl_system.getValue('provider.type') == "lambda") and
                ((protocol in ["docker", "lambda"] and "dkr.ecr" in src_host) or
                 protocol == '' and "dkr.ecr" in url[2])):
            res_system = radl_system.clone()
            res_system.setValue('disk.0.os.credentials.username', 'lambda')
            return res_system
        else:
            return None

    def _set_scar_env(self, system, auth_data):
        auths = auth_data.getAuthInfo(self.type, self.cloud.server)
        if not auths:
            raise Exception("No auth data has been specified to Lambda.")
        else:
            auth = auths[0]

        # Store auth to get it from TOSCA get_attribute
        if self.auth is None:
            self.auth = auth

        if 'username' in auth and 'password' in auth and 'role' in auth:
            os.environ["AWS_ACCESS_KEY_ID"] = auth['username']
            os.environ["AWS_SECRET_ACCESS_KEY"] = auth['password']
            tempf = tempfile.NamedTemporaryFile(delete=False)
            os.environ['SCAR_TMP_CFG'] = tempf.name
            func_args = self._get_function_args(system)
            tempf.write(yaml.safe_dump(func_args).encode())
            tempf.close()
            return func_args
        else:
            self.log_error("No correct auth data has been specified to Lambda: "
                           "username and password (Access Key and Secret Key)")
            raise Exception("No correct auth data has been specified to Lambda: "
                            "username and password (Access Key and Secret Key)")

    @staticmethod
    def _free_scar_env():
        del os.environ["AWS_ACCESS_KEY_ID"]
        del os.environ["AWS_SECRET_ACCESS_KEY"]
        os.unlink(os.environ['SCAR_TMP_CFG'])
        del os.environ['SCAR_TMP_CFG']

    def _get_function_args(self, radl_system):
        func = {
            "runtime": "image",
            "execution_mode": "lambda",
            "region": "us-east-1",
            "supervisor": {"version": "latest"},
            "timeout": 900,
            "description": "IM generated lambda function",
            }

        if radl_system.getValue("name"):
            func["name"] = radl_system.getValue("name")
        if radl_system.getValue("memory.size"):
            func["memory"] = radl_system.getFeature('memory.size').getValue('M')
        if radl_system.getValue("script"):
            func["script"] = radl_system.getValue("script")

        if radl_system.getValue("disk.0.image.url"):
            url_image = urlparse(radl_system.getValue("disk.0.image.url"))
            image = ""
            if url_image.scheme in ["docker", "lambda"]:
                image = "%s%s" % (url_image[1], url_image[2])
            elif url_image.scheme == "":
                image = url_image[2]
            else:
                raise Exception("Invalid image protocol: lambda, docker or empty are supported.")
            func["container"] = {"image": image, "create_image": False}
            func["ecr"] = {"delete_image": False}

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
                func[elem] = ioelems

        storage_providers = {}
        cont = {"minio": 0, "s3": 0, "onedata": 0}
        for provider_type in ["minio", "s3", "onedata"]:
            provider_pref = "%s.0" % provider_type
            while radl_system.getValue("%s.id" % provider_pref):
                sid = radl_system.getValue("%s.id" % provider_pref)
                if provider_type not in storage_providers:
                    storage_providers[provider_type] = {sid: {}}
                for elem in ['access_key', 'secret_key', 'region', 'endpoint',
                             'verify', 'oneprovider_host', 'token', 'space']:
                    value = radl_system.getValue("%s.%s" % (provider_pref, elem))
                    if value:
                        storage_providers[provider_type][sid][elem] = value

                cont[provider_type] += 1
                provider_pref = "%s.%d" % (provider_type, cont[provider_type])

        if storage_providers:
            func["storage_providers"] = storage_providers

        env_vars = {}
        for elem in radl_system.getValue("environment.variables", []):
            parts = elem.split(":")
            env_vars[parts[0]] = parts[1]
        if env_vars:
            func["environment"] = {"Variables": env_vars}

        return {"functions": {"aws": [{"iam": {"role": self.auth['role']}, "lambda": func}]}}

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

        try:
            self._set_scar_env(radl.systems[0], auth_data)
            AWS("init")
            self._free_scar_env()
            vm.destroy = False
            vm.state = VirtualMachine.RUNNING
            res.append((True, vm))
        except (Exception, SystemExit) as ex:
            self.log_exception("Error creating Lambda function: %s." % ex)
            res.append((False, "%s" % ex))

        return res

    def finalize(self, vm, last, auth_data):
        try:
            self._set_scar_env(vm.info.systems[0], auth_data)
            AWS("rm")
            self._free_scar_env()
        except (Exception, SystemExit) as ex:
            self.log_exception("Error deletting Lambda function: %s." % ex)
            return False, "%s" % ex

        return True, ""

    def update_system_info_from_function_conf(self, system, func_conf):
        if "MemorySize" in func_conf and func_conf["MemorySize"]:
            system.addFeature(Feature("memory.size", "=", func_conf["MemorySize"], "M"),
                              conflict="other", missing="other")
        if "FunctionArn" in func_conf and func_conf["FunctionArn"]:
            system.addFeature(Feature("function.arn", "=", func_conf["FunctionArn"]),
                              conflict="other", missing="other")
        if "Timeout" in func_conf and func_conf["Timeout"]:
            system.addFeature(Feature("function.timeout", "=", func_conf["Timeout"]),
                              conflict="other", missing="other")

    def updateVMInfo(self, vm, auth_data):
        try:
            aws_resources = self._set_scar_env(vm.info.systems[0], auth_data)
            # Set a version higher than 1.5.0
            aws_resources["functions"]["aws"][0]["lambda"]["supervisor"]["version"] = "1.5.4"
            func_conf = Lambda(aws_resources["functions"]["aws"][0]).get_function_configuration(vm.id)
            self.update_system_info_from_function_conf(vm.info.systems[0], func_conf)
            self._free_scar_env()
            return True, vm
        except ClientError as ce:
            # Function not found
            if ce.response['Error']['Code'] == 'ResourceNotFoundException':
                vm.state = VirtualMachine.OFF
                return True, vm
            else:
                return False, "%s" % ce
        except (Exception, SystemExit) as ex:
            self.log_exception("Error getting Lambda function: %s." % ex)
            return False, "%s" % ex
