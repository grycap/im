import time
import os
import argparse
import sys

import requests
from requests.exceptions import ConnectionError

import logging
from logging.handlers import RotatingFileHandler

import IMinfrastructureOper


def log_setup(loglevel):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    log_handler = RotatingFileHandler(tests_path + '/log/probeim.log', maxBytes=1048576, backupCount=5)

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


def main(url, token):

    if token == "None":
        token = None
    imheaders = IMinfrastructureOper.update_imheaders(token)

    # CREATE INFRASTRUCTURE
    ci = IMinfrastructureOper.create_infrastructure(url, imheaders)
    url_infr = ci.info

    if ci.statuscode == 401:
        return False, "Authentication Error"

    elif ci.statuscode == 111:
        logging.error("Could NOT start CREATION INFRASTRUCTURE process: %s" % ci.info)
        return False, str(ci.info)

    elif ci.statuscode == 200:
        # START INFRASTRUCTUREWARNING
        si = IMinfrastructureOper.start_infrastructure(imheaders, url_infr)

        if si.statuscode == 200:

            time.sleep(1)
            # LIST INFRASTRUCTURE
            li = IMinfrastructureOper.list_infrastructure(url, imheaders)

            if li.statuscode == 200:
                # CREATE VM
                cv = IMinfrastructureOper.create_vm(imheaders, url_infr)

                if cv.statuscode == 200:
                    # DELETE INFRASTRUCTURE
                    di = IMinfrastructureOper.delete_infrastructure(imheaders, url_infr)

                    if di.statuscode == 200:
                        logging.info("All operations have been completed successfully.")
                        return True, "All operations have been completed successfully."
                    else:
                        logging.error("Infrastructure could NOT be DELETED")
                        return False, str(di.info)

                else:
                    logging.error("VM could NOT be CREATED")
                    return False, str(cv.info)
            else:
                logging.error("Infrastructure could NOT be LISTED")
                return False, str(li.info)
        else:
            logging.error("Infrastructure could NOT be STARTED")
            return False, str(si.info)
    else:
        logging.error("Infrastructure could NOT be CREATED")
        return False, str(ci.info)

# ----- RUN -----------------------------------------------------------------


if __name__ == '__main__':

    log_setup(logging.DEBUG)

    logging.info("Initializing --------------")

    # Parse input arguments
    parser = argparse.ArgumentParser(description='Monitorize IM operations.')
    parser.add_argument('-t', '--token', help='STRING of access token')
    parser.add_argument('-u', '--url', help='URL of the IM REST API endpoint', default="http://localhost:8800")
    args = parser.parse_args()

    # get client credential and token
    logging.info("Initializing --------------")

    succcess, msg = main(args.url, args.token)
    if succcess:
        print("All operations have been completed successfully.")
        sys.exit(0)
    else:
        print(msg)
        sys.exit(1)
