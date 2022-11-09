#! /usr/bin/env python
#
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
import unittest

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

    @patch('scar.providers.aws.controller._get_owner')
    @patch('IM.connectors.Lambda.AWS.init')
    @patch('IM.InfrastructureList.InfrastructureList.save_data')
    def test_20_launch(self, get_owner, aws_init, save_data):
        radl_data = """
            system test (
                name = 'plants' and
                memory.size = 2G and
                cpu.count = 1.0 and
                disk.0.image.url = '000000000000.dkr.ecr.us-east-1.amazonaws.com/scar-function' and
                script = 'plants.sh' and
                environment.variables = ['a:b'] and
                input.0.provider = 'minio_id' and
                input.0.path = '/input' and
                input.0.suffix = ['*.txt'] and
                output.0.provider = 'minio_id' and
                output.0.path = '/output' and
                minio.0.id = 'minio_id' and
                minio.0.endpoint = 'https://minio.com' and
                minio.0.region = 'mregion' and
                minio.0.access_key = 'AK' and
                minio.0.secret_key = 'SK'
            )"""
        radl = radl_parse.parse_radl(radl_data)
        radl.check()

        auth = Authentication([{'id': 'lam', 'type': 'Lambda', 'username': 'AK', 'password': 'SK'}])
        lambda_cloud = self.get_lambda_cloud()

        inf = MagicMock(["id", "_lock", "add_vm"])
        inf.id = "infid"

        get_owner.return_value = "owner"

        res = lambda_cloud.launch(inf, radl, radl, 1, auth)
        success, _ = res[0]
        self.assertTrue(success, msg="ERROR: launching a VM.")
        self.assertNotIn("ERROR", self.log.getvalue(), msg="ERROR found in log: %s" % self.log.getvalue())


if __name__ == '__main__':
    unittest.main()
