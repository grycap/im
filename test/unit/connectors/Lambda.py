#! /usr/bin/env python
#
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

import sys
import unittest

from IM.VirtualMachine import VirtualMachine

sys.path.append(".")
sys.path.append("..")
from .CloudConn import TestCloudConnectorBase
from IM.CloudInfo import CloudInfo
from IM.auth import Authentication
from radl import radl_parse
from IM.connectors.Lambda import LambdaCloudConnector
from mock import patch, MagicMock


class TestLambdaConnector(TestCloudConnectorBase):
    """
    Class to test the IM connectors
    """

    @staticmethod
    def get_lambda_cloud():
        cloud_info = CloudInfo()
        cloud_info.type = "Lambda"
        cloud_info.port = -1
        inf = MagicMock()
        inf.id = "1"
        cloud = LambdaCloudConnector(cloud_info, inf)
        return cloud

    def test_10_concrete(self):
        radl_data = """
            network net ()
            system test (
            name = 'plants' and
            script = '#!/bin/bash
                      echo "HOLA"' and
            memory.size>=512m and
            disk.0.image.url = 'lambda://000000000000.dkr.ecr.us-east-1.amazonaws.com/scar-function'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl_system = radl.systems[0]

        auth = Authentication([{'id': 'lam', 'type': 'Lambda', 'username': 'AK', 'password': 'SK'}])
        lambda_cloud = self.get_lambda_cloud()

        concrete = lambda_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)

        radl_system.setValue('disk.0.image.url', 'docker://000000000000.dkr.ecr.us-east-1.amazonaws.com/scar-function')
        concrete = lambda_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)

        radl_system.setValue('disk.0.image.url', '000000000000.dkr.ecr.us-east-1.amazonaws.com/scar-function')
        concrete = lambda_cloud.concreteSystem(radl_system, auth)
        self.assertEqual(len(concrete), 1)
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch('scar.providers.aws.controller._check_function_defined')
    @patch('scar.providers.aws.controller._add_extra_aws_properties')
    @patch('IM.connectors.Lambda.AWS._create_lambda_function')
    @patch('IM.connectors.Lambda.AWS._create_log_group')
    @patch('IM.connectors.Lambda.AWS._create_s3_buckets')
    @patch('scar.providers.aws.controller._check_preheat_function')
    @patch('scar.providers.aws.controller.SupervisorUtils')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, save_data, su, cpf, csb, clg, clf, adwp, cfd):
        radl_data = """
            system test (
                name = 'micafer-plants' and
                memory.size = 512M and
                disk.0.image.url = '000000000000.dkr.ecr.us-east-1.amazonaws.com/scar-function' and
                script = 'plants.sh' and
                environment.variables = ['some_var:some_value'] and
                input.0.provider = 's3' and
                input.0.path = 'micafer/input' and
                input.0.suffix = ['*.txt'] and
                output.0.provider = 's3' and
                output.0.path = 'micafer/output'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'lam', 'type': 'Lambda', 'username': 'AK',
                                'password': 'SK', 'role': 'arn:aws:iam::000000000000:role/lambda-role-name'}])
        lambda_cloud = self.get_lambda_cloud()

        inf = MagicMock(["id", "_lock", "add_vm"])
        inf.id = "infid"

        su.check_supervisor_version.return_value = "1.5.4"

        res = lambda_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        expected_res = {'iam': {'role': 'arn:aws:iam::000000000000:role/lambda-role-name'},
                        'api_gateway': {},
                        "cloudwatch": {"region": "us-east-1",
                                       "log_retention_policy_in_days": 30},
                        "batch": {"region": "us-east-1"},
                        'lambda': {'container': {'create_image': False,
                                                 'timeout_threshold': 10,
                                                 'image': '000000000000.dkr.ecr.us-east-1.amazonaws.com/scar-function'},
                                   'description': 'IM generated lambda function',
                                   'ecr': {'delete_image': False},
                                   'environment': {'Variables': {'some_var': 'some_value'}},
                                   'execution_mode': 'lambda',
                                   'input': [{'path': 'micafer/input',
                                              'storage_provider': 's3',
                                              'suffix': ['*.txt']}],
                                   'memory': 512,
                                   'name': 'micafer-plants',
                                   'output': [{'path': 'micafer/output',
                                               'storage_provider': 's3'}],
                                   'region': 'us-east-1',
                                   'runtime': 'image',
                                   'init_script': 'plants.sh',
                                   'supervisor': {'version': '1.5.4'},
                                   'timeout': 900}}
        self.assertEqual(clf.call_args_list[0][0][0], expected_res)

    @patch("IM.connectors.Lambda.Lambda.get_function_configuration")
    def test_30_updateVMInfo(self, gfc):
        radl_data = """
            system test (
                name = 'micafer-plants' and
                disk.0.image.url = '000000000000.dkr.ecr.us-east-1.amazonaws.com/scar-function'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'lam', 'type': 'Lambda', 'username': 'AK',
                                'password': 'SK', 'role': 'arn:aws:iam::000000000000:role/lambda-role-name'}])
        lambda_cloud = self.get_lambda_cloud()

        inf = MagicMock()
        inf.id = "infid"
        vm = VirtualMachine(inf, "micafer-plants", lambda_cloud.cloud, radl, radl, lambda_cloud, 1)

        gfc.return_value = {'FunctionArn': 'arn:aws:lambda:us-east-1:000000000000:function:micafer-plants',
                            'MemorySize': 2048, 'Timeout': 243}
        success, new_vm = lambda_cloud.updateVMInfo(vm, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.assertEqual(new_vm.info.systems[0].getFeature('memory.size').getValue('M'), 2048)
        self.assertEqual(new_vm.info.systems[0].getValue('function.timeout'), 243)

    @patch("IM.connectors.Lambda.Lambda.get_function_configuration")
    @patch('scar.providers.aws.controller._check_function_not_defined')
    @patch('scar.providers.aws.controller._add_extra_aws_properties')
    @patch('IM.connectors.Lambda.AWS._delete_resources')
    def test_40_finalize(self, dr, aeap, cfnd, gfc):
        radl_data = """
            system test (
                name = 'micafer-plants' and
                memory.size = 512M and
                disk.0.image.url = '000000000000.dkr.ecr.us-east-1.amazonaws.com/scar-function' and
                script = 'plants.sh' and
                environment.variables = ['some_var:some_value'] and
                input.0.provider = 's3' and
                input.0.path = 'micafer/input' and
                input.0.suffix = ['*.txt'] and
                output.0.provider = 's3' and
                output.0.path = 'micafer/output'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()
        auth = Authentication([{'id': 'lam', 'type': 'Lambda', 'username': 'AK',
                                'password': 'SK', 'role': 'arn:aws:iam::000000000000:role/lambda-role-name'}])
        lambda_cloud = self.get_lambda_cloud()

        inf = MagicMock(["id", "_lock", "add_vm"])
        inf.id = "infid"
        vm = VirtualMachine(inf, "fname", lambda_cloud.cloud, radl, radl, lambda_cloud, 1)

        success, _ = lambda_cloud.finalize(vm, True, auth)
        self.assertTrue(success, msg="ERROR: deleting a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())

    @patch("scar.providers.aws.clients.lambdafunction.LambdaClient.update_function_configuration")
    def test_50_alterVM(self, ufc):
        radl_data = """
            system test (
                name = 'micafer-plants' and
                memory.size = 512M and
                disk.0.image.url = '000000000000.dkr.ecr.us-east-1.amazonaws.com/scar-function' and
                script = 'plants.sh' and
                environment.variables = ['some_var:some_value'] and
                input.0.provider = 's3' and
                input.0.path = 'micafer/input' and
                input.0.suffix = ['*.txt'] and
                output.0.provider = 's3' and
                output.0.path = 'micafer/output'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        new_radl_data = """
            system test (
                memory.size = 1024m
            )"""
        new_radl = radl_parse.parse_radl(new_radl_data)
        new_radl.check()

        auth = Authentication([{'id': 'lam', 'type': 'Lambda', 'username': 'AK',
                                'password': 'SK', 'role': 'arn:aws:iam::000000000000:role/lambda-role-name'}])
        lambda_cloud = self.get_lambda_cloud()

        inf = MagicMock()
        inf.id = "infid"
        vm = VirtualMachine(inf, "micafer-plants", lambda_cloud.cloud, radl, radl, lambda_cloud, 1)

        success, new_vm = lambda_cloud.alterVM(vm, new_radl, auth)

        self.assertTrue(success, msg="ERROR: updating VM info.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())
        self.assertEqual(new_vm.info.systems[0].getFeature("memory.size").getValue("M"), 1024)
        self.assertEqual(ufc.call_args_list[0][1], {'MemorySize': 1024, 'FunctionName': 'micafer-plants'})


if __name__ == '__main__':
    unittest.main()
