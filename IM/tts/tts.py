'''
Created on 16 de jun. de 2016

@author: micafer
'''

import json
import requests


class TTSClient:
    """
    Class to interact with the TTS using v2 of the REST API
    https://github.com/indigo-dc/tts
    """

    def __init__(self, token, host, port=None, uri_scheme=None, ssl_verify=False):
        self.host = host
        self.port = port
        if not self.port:
            self.port = 8080
        self.token = token
        self.uri_scheme = uri_scheme
        if not self.uri_scheme:
            self.uri_scheme = "http"
        self.ssl_verify = ssl_verify

    def _perform_get(self, url, headers=None):
        """
        Perform the GET operation on the TTS with the specified URL
        """
        url = "%s://%s:%s%s" % (self.uri_scheme, self.host, self.port, url)
        resp = requests.request("GET", url, verify=self.ssl_verify, headers=headers)

        if resp.status_code >= 200 and resp.status_code <= 299:
            return True, resp.text
        else:
            return False, "Error code %d. Msg: %s" % (resp.status_code, resp.text)

    def _perform_post(self, url, headers, body):
        """
        Perform the POST operation on the TTS with the specified URL
        and using the body specified
        """
        url = "%s://%s:%s%s" % (self.uri_scheme, self.host, self.port, url)
        resp = requests.request("POST", url, verify=self.ssl_verify, headers=headers, data=body)
        if resp.status_code >= 200 and resp.status_code <= 299:
            return True, resp.text
        else:
            return False, "Error code %d. Msg: %s" % (resp.status_code, resp.text)

    def request_credential(self, sid):
        """
        Request a credential for the specified service
        """
        success, provider = self.get_provider()
        if not success:
            return False, provider

        body = '{"service_id":"%s"}' % sid
        url = "/api/v2/%s/credential" % provider["id"]
        try:
            headers = {'Authorization': 'Bearer %s' % self.token, 'Content-Type': 'application/json'}
            success, res = self._perform_post(url, headers, body)
        except Exception as ex:
            success = False
            res = str(ex)
        if success:
            return True, json.loads(res)
        else:
            return False, res

    def list_providers(self):
        """
        Get the list of providers
        """
        url = "/api/v2/oidcp"
        try:
            success, output = self._perform_get(url)
        except Exception as ex:
            success = False
            output = str(ex)
        if not success:
            return False, output
        else:
            return True, json.loads(output)

    def list_endservices(self, provider):
        """
        Get the list of services
        """
        url = "/api/v2/%s/service" % provider
        try:
            headers = {'Authorization': 'Bearer %s' % self.token}
            success, output = self._perform_get(url, headers)
        except Exception as ex:
            success = False
            output = str(ex)
        if not success:
            return False, output
        else:
            return True, json.loads(output)

    def get_provider(self):
        """
        Get the first provider available
        """
        success, providers = self.list_providers()
        if not success:
            return False, providers
        else:
            if providers['openid_provider_list']:
                return True, providers['openid_provider_list'][0]
            else:
                return False, "No provider found."

    def find_service(self, host):
        """
        Find a service for the specified host
        """
        success, provider = self.get_provider()
        if not success:
            return False, provider

        success, services = self.list_endservices(provider["id"])
        if success:
            for service in services["service_list"]:
                # we assume that if the host appears in the description it is our service
                if service["description"].find(host) != -1:
                    return True, service
        else:
            return False, services

        return False, "Cloud site %s not found in TTS" % host
