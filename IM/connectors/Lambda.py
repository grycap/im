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

import threading
import os
import re
import yaml
import tempfile
from IM.VirtualMachine import VirtualMachine
from radl.radl import Feature
from .CloudConnector import CloudConnector
from IM.connectors.exceptions import NoAuthData, NoCorrectAuthData, CloudConnectorException
import scar.logger
from IM.connectors.OSCAR import OSCARCloudConnector
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

    _lock = threading.Lock()
    """Threading Lock to avoid concurrency problems."""
    type = "Lambda"
    """str with the name of the provider."""

    # Function to store scar error messages
    def store_error_message(self, msg):
        self.scar_errors.append(str(msg))

    def __init__(self, cloud_info, inf):
        # workaround to store scar error messages
        self.scar_errors = []
        scar.logger.exception = self.store_error_message

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

    def _set_scar_env(self, system, auth_data, supervisor_version="1.5.4"):
        # clean previous error messages
        self.scar_errors = []
        auths = auth_data.getAuthInfo(self.type, self.cloud.server)
        if not auths:
            raise NoAuthData(self.type)
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
            func_args = self._get_function_args(system, auth['role'], supervisor_version)
            tempf.write(yaml.safe_dump(func_args).encode())
            tempf.close()
            return func_args
        else:
            self.log_error("No correct auth data has been specified to Lambda: "
                           "username and password (Access Key, Secret Key and Role)")
            raise NoCorrectAuthData(self.type, "username and password (Access Key, Secret Key and Role)")

    @staticmethod
    def _free_scar_env():
        del os.environ["AWS_ACCESS_KEY_ID"]
        del os.environ["AWS_SECRET_ACCESS_KEY"]
        os.unlink(os.environ['SCAR_TMP_CFG'])
        del os.environ['SCAR_TMP_CFG']

    @staticmethod
    def _get_region_from_image(image_url):
        result = re.search(r".+dkr\.ecr\.(.+)\.amazonaws\.com.+", image_url)
        return result.group(1)

    @staticmethod
    def _get_function_args(radl_system, role_arn, supervisor_version):
        func = {
            "runtime": "image",
            "execution_mode": "lambda",
            "region": "us-east-1",
            "supervisor": {"version": supervisor_version},
            "timeout": 900,
            "description": "IM generated lambda function"
        }

        if radl_system.getValue("name"):
            func["name"] = radl_system.getValue("name")
        if radl_system.getValue("memory.size"):
            func["memory"] = radl_system.getFeature('memory.size').getValue('M')
        if radl_system.getValue("script"):
            func["init_script"] = radl_system.getValue("script")

        if radl_system.getValue("disk.0.image.url"):
            url_image = urlparse(radl_system.getValue("disk.0.image.url"))
            image = ""
            if url_image.scheme in ["docker", "lambda"]:
                image = "%s%s" % (url_image[1], url_image[2])
            elif url_image.scheme == "":
                image = url_image[2]
            else:
                raise CloudConnectorException("Invalid image protocol: lambda, docker or empty are supported.")
            func["container"] = {"image": image, "create_image": False, "timeout_threshold": 10}
            func["ecr"] = {"delete_image": False}

        if image:
            region = LambdaCloudConnector._get_region_from_image(image)
            func["region"] = region
        else:
            region = "us-east-1"

        OSCARCloudConnector._get_storage_info(radl_system, func)
        func["environment"] = {"Variables": OSCARCloudConnector._get_env_variables(radl_system)}

        res = {"functions": {"aws": [{"api_gateway": {},
                                      "iam": {"role": role_arn},
                                      "lambda": func,
                                      "batch": {"region": region},
                                      "cloudwatch": {
                                          "region": region,
                                          "log_retention_policy_in_days": 30}}]}}
        return res

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
            with LambdaCloudConnector._lock:
                self._set_scar_env(radl.systems[0], auth_data)
                AWS("init")
                self._free_scar_env()
            vm.destroy = False
            vm.state = VirtualMachine.RUNNING
            res.append((True, vm))
        except Exception as ex:
            self.log_exception("Error creating Lambda function: %s." % ex)
            res.append((False, "%s" % ex))
        except SystemExit:
            error_msgs = "\n".join(self.scar_errors)
            self.log_exception("Error creating Lambda function: %s." % error_msgs)
            res.append((False, "%s" % error_msgs))

        return res

    def finalize(self, vm, last, auth_data):
        try:
            with LambdaCloudConnector._lock:
                aws_resources = self._set_scar_env(vm.info.systems[0], auth_data)
                Lambda(aws_resources["functions"]["aws"][0]).get_function_configuration(vm.id)
                AWS("rm")
                self._free_scar_env()
        except ClientError as ce:
            # Function not found
            if ce.response['Error']['Code'] == 'ResourceNotFoundException':
                return True, ""
            return False, "%s" % ce
        except Exception as ex:
            self.log_exception("Error deletting Lambda function: %s." % ex)
            return False, "%s" % ex
        except SystemExit:
            error_msgs = "\n".join(self.scar_errors)
            self.log_exception("Error deletting Lambda function: %s." % error_msgs)
            return False, error_msgs

        return True, ""

    @staticmethod
    def update_system_info_from_function_conf(system, func_conf):
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
            with LambdaCloudConnector._lock:
                aws_resources = self._set_scar_env(vm.info.systems[0], auth_data)
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
        except Exception as ex:
            self.log_exception("Error getting Lambda function: %s." % ex)
            return False, "%s" % ex
        except SystemExit:
            error_msgs = "\n".join(self.scar_errors)
            self.log_exception("Error getting Lambda function: %s." % error_msgs)
            return False, error_msgs

    def alterVM(self, vm, radl, auth_data):
        memory = vm.info.systems[0].getFeature('memory.size').getValue('M')
        new_memory = radl.systems[0].getFeature('memory.size').getValue('M')

        if new_memory and new_memory != memory:
            try:
                with LambdaCloudConnector._lock:
                    aws_resources = self._set_scar_env(vm.info.systems[0], auth_data)
                    Lambda(aws_resources["functions"]["aws"][0]).client.update_function_configuration(
                        MemorySize=new_memory, FunctionName=vm.id)
                    self.update_system_info_from_function_conf(vm.info.systems[0], {"MemorySize": new_memory})
                    self._free_scar_env()
                return True, vm
            except ClientError as ce:
                # Function not found
                if ce.response['Error']['Code'] == 'ResourceNotFoundException':
                    vm.state = VirtualMachine.OFF
                    return True, vm
                else:
                    return False, "%s" % ce
            except Exception as ex:
                self.log_exception("Error updating Lambda function: %s." % ex)
                return False, "%s" % ex
            except SystemExit:
                error_msgs = "\n".join(self.scar_errors)
                self.log_exception("Error updating Lambda function: %s." % error_msgs)
                return False, error_msgs
