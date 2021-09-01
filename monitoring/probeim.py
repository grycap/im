#! /usr/bin/python3
import time
import os
import argparse
import sys
import json
import requests
import logging
import signal
from logging.handlers import RotatingFileHandler

try:
    # To avoid annoying InsecureRequestWarning messages in some Connectors
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass

CREATE_RADL = """
network net (outbound = 'no')
system small_node (
  cpu.arch = 'x86_64' and
  cpu.count = 1 and
  memory.size >= 512M and
  net_interface.0.connection = 'net' and
  disk.0.os.name = 'linux' and
  disk.0.image.url = 'dummy://image' and
  disk.0.os.credentials.username = 'dummy'
)
deploy small_node 1
"""

ADD_RADL = """
network net
system small_node
deploy small_node 1
"""


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TimeOutExcetion(Exception):

    def __init__(self, msg="Timeout has been received."):
        Exception.__init__(self, msg)
        self.message = msg


class ResponseIM:

    def __init__(self, statuscode, info):
        self.statuscode = statuscode
        self.info = info


class IM:

    def __init__(self, url, user, password, token=None, verify=False, timeout=5):
        self.url = url
        self.verify_ssl = verify
        self.timeout = timeout
        self.token = token
        self.user = user
        self.password = password
        self.headers = self.get_imheaders()
        self.response_times = []

    def get_imheaders(self):

        authoriz = 'id = dummy; type = Dummy;\\nid = im; type = InfrastructureManager;'

        # Token has prececende over user/pass auth
        if self.token:
            authoriz += " token = %s;" % self.token
        else:
            authoriz += " username = %s; password = %s;" % (self.user, self.password)

        UPD_HEADERS = {
            "Content-Type": "text/plain",
            "Accept": "application/json",
            "Authorization": authoriz
        }

        return UPD_HEADERS

    def requestIM(self, method, url, data=None):
        try:
            logging.debug(method, self.url, data, self.headers)
            r = requests.request(method, url, data=data, headers=self.headers,
                                 verify=self.verify_ssl, timeout=self.timeout)
            self.response_times.append(r.elapsed.total_seconds())
            rq = ResponseIM(r.status_code, r.text)
        except requests.ConnectionError as e:
            logging.error("* ConnectionError exception at method " + method + ": " + str(e))
            rq = ResponseIM(111, "Failed to establish connection with %s" % self.url)
        except requests.exceptions.InvalidHeader as e:
            logging.error("* InvalidHeader exception: ---> " + str(e) + " <--")
            rq = ResponseIM(111, e)

        return rq

    def list_infrastructure(self):

        r = self.requestIM('GET', self.url + "/infrastructures")

        if r.statuscode == 200:
            ret = ResponseIM(r.statuscode, 'list method OK')
        elif r.statuscode == 111:
            ret = ResponseIM(r.statuscode, r.info)
        else:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['message'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error("list_infrastructure" + str(e))

        return ret

    def create_infrastructure(self):

        r = self.requestIM('POST', self.url + "/infrastructures", CREATE_RADL)

        if r.statuscode == 200:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['uri'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error(e)

        elif r.statuscode == 111:
            ret = ResponseIM(r.statuscode, r.info)
        else:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['message'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error("create_infrastructure" + str(e))
        return ret

    def start_infrastructure(self, uri_inf_id):

        r = self.requestIM('PUT', uri_inf_id + '/start')

        if r.statuscode == 200:
            ret = ResponseIM(r.statuscode, 'start method OK')
        elif r.statuscode == 111:
            ret = ResponseIM(r.statuscode, r.info)
        else:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['message'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error("start_infrastructure" + str(e))

        return ret

    def create_vm(self, uri_inf_id):

        r = self.requestIM('POST', uri_inf_id, ADD_RADL)

        if r.statuscode == 200:
            ret = ResponseIM(r.statuscode, 'Creation of VM is OK')
        elif r.statuscode == 111:
            ret = ResponseIM(r.statuscode, r.info)
        else:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['message'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error("create_vm" + str(e))

        return ret

    def delete_infrastructure(self, uri_inf_id):

        r = self.requestIM('DELETE', uri_inf_id)

        if r.statuscode == 200:
            ret = ResponseIM(r.statuscode, 'delete_infrastructure is OK')
        elif r.statuscode == 111:
            ret = ResponseIM(r.statuscode, r.info)
        else:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['message'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error("delete_infrastructure" + str(e))

        return ret

    def get_infrastructure_vms(self, uri_inf_id):

        r = self.requestIM('GET', uri_inf_id)

        if r.statuscode == 200:
            json_data = json.loads(r.info)
            ret = ResponseIM(r.statuscode, json_data['uri-list'])
        elif r.statuscode == 111:
            ret = ResponseIM(r.statuscode, r.info)
        else:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['message'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error("get_infrastructure_vms" + str(e))

        return ret

    def get_im_version(self):

        r = self.requestIM('GET', self.url + "/version")

        if r.statuscode == 200:
            ret = ResponseIM(r.statuscode, 'get version method OK')
        elif r.statuscode == 111:
            ret = ResponseIM(r.statuscode, r.info)
        else:
            try:
                json_data = json.loads(r.info)
                ret = ResponseIM(r.statuscode, json_data['version'])
            except ValueError as e:
                ret = ResponseIM(111, e)
                logging.error("get_infrastructure_vms" + str(e))

        return ret

    def get_mean_response_time(self):
        if self.response_times:
            return sum(self.response_times) / len(self.response_times)
        else:
            return 0


def log_setup(loglevel, log_file):
    if not log_file:
        tests_path = os.path.dirname(os.path.abspath(__file__))
        log_file = tests_path + '/probeim.log'
    log_handler = RotatingFileHandler(log_file, maxBytes=1048576, backupCount=5)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s -- %(filename)s::%(funcName)s'
                                  ' line     %(lineno)d', '%b %d %H:%M:%S')
    formatter.converter = time.gmtime
    log_handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(log_handler)

    if loglevel == 'ERROR':
        lvl = 40
    elif loglevel == 'WARNING':
        lvl = 30
    elif loglevel == 'INFO':
        lvl = 20
    elif loglevel == 'DEBUG':
        lvl = 10
    else:
        lvl = 30

    logger.setLevel(lvl)


def main(url, token, username, password, delay=0.5):

    im = IM(url, username, password, token)

    vi = im.get_im_version()

    if vi.statuscode != 200:
        logging.error("Could NOT get IM version: %s" % vi.info)
        return 2, str(vi.info), 0

    # CREATE INFRASTRUCTURE
    ci = im.create_infrastructure()
    url_infr = ci.info

    if ci.statuscode == 401:
        return 2, "Authentication Error", 0

    elif ci.statuscode == 111:
        logging.error("Could NOT start CREATION INFRASTRUCTURE process: %s" % ci.info)
        return 2, str(ci.info), 0

    elif ci.statuscode != 200:
        logging.error("Infrastructure could NOT be CREATED")
        return 1, str(ci.info), im.get_mean_response_time()

    # GET VMS
    vms = im.get_infrastructure_vms(url_infr)
    if vms.statuscode == 200:
        if len(vms.info) != 1:
            return 1, "Unexpected number of VMs: %s != 1" % vms.info, im.get_mean_response_time()
    else:
        return 1, "Error getting infrastructure VMs", im.get_mean_response_time()

    # START INFRASTRUCTURE
    time.sleep(delay)
    si = im.start_infrastructure(url_infr)

    if si.statuscode != 200:
        logging.error("Infrastructure could NOT be STARTED")
        return 1, str(si.info), im.get_mean_response_time()

    time.sleep(delay)
    # LIST INFRASTRUCTURE
    li = im.list_infrastructure()

    if li.statuscode != 200:
        logging.error("Infrastructure could NOT be LISTED")
        return 1, str(li.info), im.get_mean_response_time()

    # CREATE VM
    time.sleep(delay)
    cv = im.create_vm(url_infr)

    if cv.statuscode != 200:
        logging.error("VM could NOT be CREATED")
        return 1, str(cv.info), im.get_mean_response_time()

    # GET VMS
    vms = im.get_infrastructure_vms(url_infr)
    if vms.statuscode == 200:
        if len(vms.info) != 2:
            return 1, "Unexpected number of VMs: %s != 2" % vms.info, im.get_mean_response_time()
    else:
        return 1, "Error getting infrastructure VMs", im.get_mean_response_time()

    # DELETE INFRASTRUCTURE
    time.sleep(delay)
    di = im.delete_infrastructure(url_infr)

    if di.statuscode != 200:
        logging.error("Infrastructure could NOT be DELETED")
        return 1, str(di.info), im.get_mean_response_time()

    logging.info("All operations have been completed successfully.")
    return 0, "All operations have been completed successfully.", im.get_mean_response_time()


def handler(signum, frame):
    raise TimeOutExcetion()

# ----- RUN -----------------------------------------------------------------


if __name__ == '__main__':

    rc_status_map = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}

    try:
        # Parse input arguments
        parser = argparse.ArgumentParser(description='Monitorize IM operations.')
        parser.add_argument('-u', '--url', help='URL of the IM REST API endpoint', default="http://localhost:8800")
        parser.add_argument('-T', '--token', help='OIDC access token to autenticate with IM', default=None)
        parser.add_argument('-f', '--log_file', help='Path to the log file', default=None)
        parser.add_argument('-l', '--log_level', help='Set the log level', default='INFO')
        parser.add_argument('-p', '--password', help='Password to autenticate with IM', default='monz')
        parser.add_argument('-n', '--username', help='Username to autenticate with IM', default='mon_test_1X')
        parser.add_argument('-t', '--timeout', help='Test timeout', default=10, type=int)
        args = parser.parse_args()

        log_setup(args.log_level, args.log_file)
        logging.info("Initializing --------------")

        # Register the signal function handler
        signal.signal(signal.SIGALRM, handler)
        # Define the timeout
        signal.alarm(args.timeout)
        rc, msg, mean_time = main(args.url, args.token, args.username, args.password)
    except TimeOutExcetion as tex:
        rc = 2
        msg = str(tex)
        mean_time = 0
    except Exception as ex:
        rc = 3
        msg = str(ex)
        mean_time = 0

    msg = "%s: %s" % (rc_status_map[rc], msg)
    if mean_time > 0:
        msg += "|'mean_response_time'=%.4f" % mean_time
    print(msg)
    sys.exit(rc)
