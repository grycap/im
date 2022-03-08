#
# IM - Infrastructure Manager Dashboard
# Copyright (C) 2020 - GRyCAP - Universitat Politecnica de Valencia
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Class to manage user credentials using a Vault backend."""
import hvac
import requests
import json


class VaultCredentials():

    def __init__(self, vault_url, vault_path=None, role=None, ssl_verify=False):
        self.vault_path = "credentials/"
        if vault_path:
            self.vault_path = vault_path
        self.role = role
        self.client = None
        self.ssl_verify = ssl_verify
        self.url = vault_url

    def _login(self, token):
        login_url = self.url + '/v1/auth/jwt/login'

        if self.role:
            data = '{ "jwt": "' + token + '", "role": "' + self.role + '" }'
        else:
            data = '{ "jwt": "' + token + '" }'

        response = requests.post(login_url, data=data, verify=self.ssl_verify, timeout=5)

        if not response.ok:
            raise Exception("Error getting Vault token: {} - {}".format(response.status_code, response.text))

        deserialized_response = response.json()

        vault_auth_token = deserialized_response["auth"]["client_token"]
        vault_entity_id = deserialized_response["auth"]["entity_id"]

        self.client = hvac.Client(url=self.url, token=vault_auth_token, verify=self.ssl_verify)
        if not self.client.is_authenticated():
            raise Exception("Error authenticating against Vault with token: {}".format(vault_auth_token))

        return vault_entity_id

    def get_creds(self, token):
        vault_entity_id = self._login(token)
        data = []

        try:
            creds = self.client.secrets.kv.v1.read_secret(path=vault_entity_id, mount_point=self.vault_path)
            for cred_json in creds["data"].values():
                new_item = json.loads(cred_json)
                if 'enabled' not in new_item or new_item['enabled']:
                    if 'enabled' in new_item:
                        del new_item['enabled']
                    if new_item['type'] == "fedcloud":
                        new_item['type'] = "OpenStack"
                        new_item['username'] = "egi.eu"
                        new_item['tenant'] = "openid"
                        new_item['auth_version'] = "3.x_oidc_access_token"
                        new_item['password'] = token
                        if 'project_id' in new_item:
                            new_item['domain'] = new_item['project_id']
                            del new_item['project_id']
                        del new_item['vo']
                    elif new_item['type'] == "EGI":
                        new_item['token'] = token
                    elif (new_item['type'] == "OpenStack" and 'auth_version' in new_item and
                            new_item['auth_version'] == '3.x_oidc_access_token'):
                        new_item['password'] = token
                    if new_item['type'] != "Vault":
                        data.append(new_item)
        except Exception:
            pass

        return data
