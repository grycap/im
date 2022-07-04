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
# GNU General Public Licenslast_updatee for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''
Class to contact with an OpenID server
'''
import requests
import json
import time
from .JWT import JWT


class OpenIDClient(object):

    ISSUER_CONFIG_CACHE = {}

    @staticmethod
    def get_openid_configuration(iss, verify_ssl=False):
        try:
            if iss in OpenIDClient.ISSUER_CONFIG_CACHE:
                return OpenIDClient.ISSUER_CONFIG_CACHE[iss]
            url = "%s/.well-known/openid-configuration" % iss
            resp = requests.request("GET", url, verify=verify_ssl)
            if resp.status_code != 200:
                return {"error": "Code: %d. Message: %s." % (resp.status_code, resp.text)}
            # Only store currently needed data
            OpenIDClient.ISSUER_CONFIG_CACHE[iss] = {"userinfo_endpoint": resp.json()["userinfo_endpoint"],
                                                     "introspection_endpoint": resp.json()["introspection_endpoint"]}
            return resp.json()
        except Exception as ex:
            return {"error": str(ex)}

    @staticmethod
    def get_user_info_request(token, verify_ssl=False):
        """
        Get a the user info from a token
        """
        try:
            decoded_token = JWT().get_info(token)
            headers = {'Authorization': 'Bearer %s' % token}
            conf = OpenIDClient.get_openid_configuration(decoded_token['iss'], verify_ssl=False)
            resp = requests.request("GET", conf["userinfo_endpoint"], verify=verify_ssl, headers=headers)
            if resp.status_code != 200:
                return False, "Code: %d. Message: %s." % (resp.status_code, resp.text)
            return True, json.loads(resp.text)
        except Exception as ex:
            return False, str(ex)

    @staticmethod
    def get_token_introspection(token, client_id, client_secret, verify_ssl=False):
        """
        Get token introspection
        """
        try:
            decoded_token = JWT().get_info(token)
            conf = OpenIDClient.get_openid_configuration(decoded_token['iss'], verify_ssl=False)
            url = "%s?token=%s&token_type_hint=access_token" % (conf["introspection_endpoint"], token)
            resp = requests.request("GET", url, verify=verify_ssl,
                                    auth=requests.auth.HTTPBasicAuth(client_id, client_secret))
            if resp.status_code != 200:
                return False, "Code: %d. Message: %s." % (resp.status_code, resp.text)
            return True, json.loads(resp.text)
        except Exception as ex:
            return False, str(ex)

    @staticmethod
    def is_access_token_expired(token):
        """
        Check if the current access token is expired
        """
        if token:
            try:
                decoded_token = JWT().get_info(token)
                now = int(time.time())
                expires = int(decoded_token['exp'])
                validity = expires - now
                if validity < 0:
                    return True, "Token expired"
                else:
                    return False, "Valid Token for %d seconds" % validity
            except Exception:
                return True, "Error getting token info"
        else:
            return True, "No token specified"
