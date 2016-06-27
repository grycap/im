'''
Created on 16 de jun. de 2016

@author: micafer
'''

import json
import httplib


class TTSClient:
    """
    Class to interact with the TTS
    https://github.com/indigo-dc/tts
    """

    def __init__(self, token, iss, host, port=None, uri_scheme=None):
        self.host = host
        self.port = port
        if not self.port:
            self.port = 8080
        self.token = token
        self.iss = iss
        self.uri_scheme = uri_scheme
        if not self.uri_scheme:
            self.uri_scheme = "http"

    def _get_http_connection(self):
        """
        Get the HTTP connection to contact the TTS server
        """
        if self.uri_scheme == 'https':
            conn = httplib.HTTPSConnection(self.host, self.port)
        else:
            conn = httplib.HTTPConnection(self.host, self.port)

        return conn

    def _perform_get(self, url):
        """
        Perform the GET operation on the TTS with the specified URL
        """
        headers = {}
        headers['Authorization'] = 'Bearer %s' % self.token
        headers['Content-Type'] = 'application/json'
        headers['X-OpenId-Connect-Issuer'] = self.iss
        conn = self._get_http_connection()
        conn.request('GET', url, headers=headers)
        resp = conn.getresponse()
        output = resp.read()

        if resp.status >= 200 and resp.status <= 299:
            return True, output
        else:
            return False, "Error code %d. Msg: %s" % (resp.status, output)

    def _perform_post(self, url, body):
        """
        Perform the POR operation on the TTS with the specified URL
        and using the body specified
        """
        conn = self._get_http_connection()

        conn.putrequest('POST', url)

        conn.putheader('Authorization', 'Bearer %s' % self.token)
        conn.putheader('Content-Type', 'application/json')
        conn.putheader('X-OpenId-Connect-Issuer', self.iss)

        conn.putheader('Content-Length', len(body))
        conn.endheaders(body)

        resp = conn.getresponse()
        output = str(resp.read())

        if resp.status == 303:
            # in case of redirection get the response from the new URL
            return self._perform_get(resp.msg['location'])
        elif resp.status >= 200 and resp.status <= 299:
            return True, output
        else:
            return False, "Error code %d. Msg: %s" % (resp.status, output)

    def request_credential(self, sid):
        """
        Request a credential for the specified service
        """
        body = '{"service_id":"%s"}' % sid
        url = "/api/credential/"
        try:
            success, res = self._perform_post(url, body)
        except Exception, ex:
            success = False
            res = str(ex)
        if success:
            return True, json.loads(res)
        else:
            return False, res

    def list_endservices(self):
        """
        Get the list of services
        """
        url = "/api/service"
        try:
            success, output = self._perform_get(url)
        except Exception, ex:
            success = False
            output = str(ex)
        if not success:
            return False, output
        else:
            return True, json.loads(output)

    def find_service(self, stype, host):
        """
        Find a service with the specified type and host values
        """
        success, services = self.list_endservices()
        if success:
            for service in services["service_list"]:
                if service["type"] == stype and service["host"] == host:
                    return True, service
        else:
            return False, services

        return False, "Cloud site %s not found in TTS" % host
