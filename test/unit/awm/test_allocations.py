import sys

sys.path.append(".")
sys.path.append("..")

import flask
import unittest
from IM.awm import awm_bp
from mock import patch, MagicMock


class TestAllocations(unittest.TestCase):

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

    @patch('IM.awm.authorization.check_OIDC')
    @patch('IM.awm.routers.allocations.DataBase')
    def test_list_allocations(self, mock_db, mock_check_oidc):
        """Test AWM allocations listing endpoint."""
        mock_check_oidc.return_value = {'sub': 'test-user'}
        selects = [
            [['id1', '{"kind": "CredentialsKubernetes","host": "http://k8s.io"}']],
            [[2]]
        ]
        mock_db_instance = self._get_database_mock(selects)
        mock_db.return_value = mock_db_instance

        headers = {"Authorization": "Bearer you-very-secret-token"}
        response = self.client.get('/awm/allocations', headers=headers)
        self.assertEqual(response.status_code, 200)
        expected_res = {'count': 2,
                        'elements': [{'allocation': {'host': 'http://k8s.io/',
                                                     'kind': 'CredentialsKubernetes'},
                                      'id': 'id1',
                                      'self': 'http://localhost/awm/allocation/id1'}],
                        'from': 0,
                        'limit': 100}
        self.assertEqual(response.json, expected_res)
        mock_db_instance.select.assert_any_call(
            "SELECT id, data FROM allocations WHERE owner = %s order by created LIMIT %s OFFSET %s",
            ('test-user', 100, 0)
        )
        mock_db_instance.select.assert_any_call(
            'SELECT count(id) from allocations WHERE owner = %s',
            ('test-user',)
        )

    @patch('IM.awm.authorization.check_OIDC')
    @patch('IM.awm.routers.allocations.DataBase')
    def test_get_allocation(self, mock_db, mock_check_oidc):
        """Test AWM get allocation endpoint."""
        mock_check_oidc.return_value = {'sub': 'test-user'}
        selects = [
            [['id1', '{"kind": "CredentialsKubernetes","host": "http://k8s.io"}']],
        ]
        mock_db_instance = self._get_database_mock(selects)
        mock_db.return_value = mock_db_instance
        headers = {"Authorization": "Bearer you-very-secret-token"}
        response = self.client.get('/awm/allocation/id1', headers=headers)
        self.assertEqual(response.status_code, 200)
        expected_res = {'id': 'id1',
                        'self': 'http://localhost/awm/allocation/id1',
                        'allocation': {'kind': 'CredentialsKubernetes',
                                       'host': 'http://k8s.io/'}}
        self.assertEqual(response.json, expected_res)
        mock_db_instance.select.assert_called_with(
            "SELECT id, data FROM allocations WHERE id = %s and owner = %s",
            ('id1', 'test-user')
        )

    @patch('IM.awm.authorization.check_OIDC')
    @patch('IM.awm.routers.allocations.DataBase')
    @patch('uuid.uuid4')
    @patch('time.time')
    def test_create_allocation(self, mock_time, mock_uuid, mock_db, mock_check_oidc):
        """Test AWM create allocation endpoint."""
        mock_check_oidc.return_value = {'sub': 'test-user'}
        mock_db_instance = MagicMock()
        mock_db_instance.connect.return_value = True
        mock_db.return_value = mock_db_instance
        mock_uuid.return_value = 'new-id'
        mock_time.return_value = 1000

        headers = {
            "Authorization": "Bearer you-very-secret-token",
            "Content-Type": "application/json"
        }
        payload = {
            "kind": "CredentialsKubernetes",
            "host": "http://k8s.io"
        }
        response = self.client.post('/awm/allocations', headers=headers, json=payload)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json, {'id': 'new-id'})
        mock_db_instance.execute.assert_called_with(
            "replace into allocations (id, data, owner, created) values (%s, %s, %s, %s)",
            ('new-id', '{"kind":"CredentialsKubernetes","host":"http://k8s.io/"}', 'test-user', 1000)
        )
