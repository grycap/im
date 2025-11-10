import sys

sys.path.append(".")
sys.path.append("..")

import flask
import unittest
from IM.rest.awm import awm_bp
from IM.rest.awm.models.tool import ToolInfo
from mock import patch, MagicMock


class TestDeployment(unittest.TestCase):

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)

    def setUp(self):
        app = flask.Flask("test_app")
        app.register_blueprint(awm_bp, url_prefix='/awm')
        self.client = app.test_client()

    def _get_database_mock(self, selects=None):
        mock_db_instance = MagicMock()
        mock_db_instance.connect.return_value = True
        mock_db_instance.select.side_effect = selects if selects else []
        return mock_db_instance

    @staticmethod
    def _get_deployment_info():
        return ('{"id": "dep_id", '
                '"deployment": {"tool": {"kind": "ToolId", "id": "toolid", '
                '"version": "latest", "infoLink": "http://some.url"}, '
                '"allocation": {"kind": "AllocationId", "id": "aid", "infoLink": "http://some.url"}}, '
                '"status": "pending"}')

    @patch('IM.rest.awm.authorization.check_OIDC')
    @patch('IM.rest.awm.routers.deployments.DataBase')
    def test_list_deployments(self, mock_db, mock_check_oidc):
        """Test AWM deployments listing endpoint."""
        mock_check_oidc.return_value = {'sub': 'test-user'}
        selects = [
            [[self._get_deployment_info()]],
            [[1]]
        ]
        mock_db_instance = self._get_database_mock(selects)
        mock_db.return_value = mock_db_instance

        headers = {"Authorization": "Bearer you-very-secret-token"}
        response = self.client.get('/awm/deployments', headers=headers)
        self.assertEqual(response.status_code, 200)
        expected_res = {
            "from": 0,
            "limit": 100,
            "count": 1,
            "self": "http://localhost/awm/deployments",
            "elements": [
                {
                    "deployment": {
                        "allocation": {
                            "kind": "AllocationId",
                            "id": "aid",
                            "infoLink": "http://some.url/"
                        },
                        "tool": {
                            "kind": "ToolId",
                            "id": "toolid",
                            "version": "latest",
                            "infoLink": "http://some.url/"
                        },
                    },
                    "id": "dep_id",
                    "status": "pending",
                }
            ],
        }
        self.assertEqual(response.json, expected_res)
        mock_db_instance.select.assert_any_call(
            "SELECT data FROM deployments WHERE owner = %s order by created LIMIT %s OFFSET %s",
            ('test-user', 100, 0)
        )
        mock_db_instance.select.assert_any_call(
            'SELECT count(id) from deployments WHERE owner = %s',
            ('test-user',)
        )

    @patch('IM.rest.awm.authorization.check_OIDC')
    @patch('IM.rest.awm.routers.deployments.DataBase')
    @patch('IM.rest.awm.routers.deployments.InfrastructureManager')
    @patch('IM.rest.awm.routers.deployments._get_allocation')
    def test_get_deployment(self, mock_get_allocation, mock_im, mock_db, mock_check_oidc):
        """Test AWM deployments get endpoint."""
        mock_check_oidc.return_value = {'sub': 'test-user', 'token': 'astoken'}
        selects = [
            [[self._get_deployment_info()]]
        ]
        mock_db_instance = self._get_database_mock(selects)
        mock_db.return_value = mock_db_instance

        ainfo = MagicMock()
        ainfo.allocation.root = MagicMock()
        ainfo.allocation.root.kind = "KubernetesEnvironment"
        ainfo.allocation.root.host = "http://some.url/"
        mock_get_allocation.return_value = ainfo

        mock_im.GetInfrastructureState.return_value = {"state": "running"}

        headers = {"Authorization": "Bearer you-very-secret-token"}
        response = self.client.get('/awm/deployment/dep_id', headers=headers)
        self.assertEqual(response.status_code, 200)
        expected_res = {
            "deployment": {
                "allocation": {
                    "kind": "AllocationId",
                    "id": "aid",
                    "infoLink": "http://some.url/"
                },
                "tool": {
                    "kind": "ToolId",
                    "id": "toolid",
                    "version": "latest",
                    "infoLink": "http://some.url/"
                },
            },
            "id": "dep_id",
            "status": "running",
        }
        self.assertEqual(response.json, expected_res)
        mock_db_instance.select.assert_called_with(
            "SELECT data FROM deployments WHERE id = %s and owner = %s",
            ('dep_id', 'test-user')
        )

    @patch('IM.rest.awm.authorization.check_OIDC')
    @patch('IM.rest.awm.routers.deployments.DataBase')
    @patch('IM.rest.awm.routers.deployments.InfrastructureManager')
    @patch('IM.rest.awm.routers.deployments._get_allocation')
    def test_delete_deployment(self, mock_get_allocation, mock_im, mock_db, mock_check_oidc):
        """Test AWM deployments delete endpoint."""
        mock_check_oidc.return_value = {'sub': 'test-user', 'token': 'astoken'}
        selects = [
            [[self._get_deployment_info()]]
        ]
        mock_db_instance = self._get_database_mock(selects)
        mock_db.return_value = mock_db_instance

        ainfo = MagicMock()
        ainfo.allocation.root = MagicMock()
        ainfo.allocation.root.kind = "KubernetesEnvironment"
        ainfo.allocation.root.host = "http://some.url/"
        mock_get_allocation.return_value = ainfo

        mock_im.DeleteInfrastructure.return_value = True

        headers = {"Authorization": "Bearer you-very-secret-token"}
        response = self.client.delete('/awm/deployment/dep_id', headers=headers)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json, {"message": "Deleting"})
        mock_db_instance.execute.assert_called_with("DELETE FROM deployments WHERE id = %s", ('dep_id',))

    @patch('IM.rest.awm.authorization.check_OIDC')
    @patch('IM.rest.awm.routers.deployments.DataBase')
    @patch('IM.rest.awm.routers.deployments.InfrastructureManager')
    @patch('IM.rest.awm.routers.deployments.get_tool_from_repo')
    @patch('IM.rest.awm.routers.deployments.Tosca')
    @patch('IM.rest.awm.routers.deployments._get_allocation')
    def test_deploy_workload(self, mock_get_allocation, mock_tosca, mock_get_tool, mock_im, mock_db,
                             mock_check_oidc):
        """Test AWM deployments deploy endpoint."""
        mock_check_oidc.return_value = {'sub': 'test-user', 'token': 'astoken'}
        mock_db_instance = self._get_database_mock()
        mock_db.return_value = mock_db_instance
        payload = ('{"tool": {"kind": "ToolId", "id": "toolid"}, '
                   '"allocation": {"kind": "AllocationId", "id": "aid"}}')
        tool_info = ToolInfo.model_validate_json('{"kind": "ToolInfo", "id": "toolid", "type": "vm", '
                                                 '"blueprintType": "tosca", "blueprint": "bp"}')
        mock_get_tool.return_value = tool_info, 200

        mock_im.CreateInfrastructure.return_value = "new_dep_id"
        mock_tosca_instance = MagicMock()
        mock_tosca_instance.to_radl.return_value = True, "radl"
        mock_tosca.return_value = mock_tosca_instance

        ainfo = MagicMock()
        ainfo.allocation.root = MagicMock()
        ainfo.allocation.root.kind = "KubernetesEnvironment"
        ainfo.allocation.root.host = "http://some.url/"
        mock_get_allocation.return_value = ainfo

        headers = {"Authorization": "Bearer you-very-secret-token"}
        response = self.client.post('/awm/deployments', headers=headers, data=payload)
        self.assertEqual(response.status_code, 202)
        expected_res = {
            "kind": "DeploymentId",
            "infoLink": "http://localhost/awm/deployment/new_dep_id",
            "id": "new_dep_id"
        }
        self.assertEqual(response.json, expected_res)
