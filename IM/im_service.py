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
import logging
import logging.handlers
import logging.config
import os
import signal
import time
import argparse
import psutil

from IM.config import Config
from IM.InfrastructureManager import InfrastructureManager
from IM.InfrastructureList import InfrastructureList
from IM.REST import RESTServer
from IM import __version__ as version


logger = logging.getLogger('InfrastructureManager')


class ExtraInfoFilter(logging.Filter):
    """
    This is a filter which injects extra attributes into the log.
      * hostname
    """
    def filter(self, record):
        import socket
        record.hostname = socket.gethostname()
        return True


rest_server = RESTServer(host=Config.REST_ADDRESS, port=Config.REST_PORT)


def launch_daemon():
    """
    Launch the IM daemon
    """
    if not InfrastructureList.init_table():
        print("Error connecting with the DB!!.")
        sys.exit(2)

    InfrastructureManager.logger.info('************ Start Infrastructure Manager daemon (v.%s) ************' % version)

    # Launch the REST API server (FastAPI)
    rest_server.run()


def config_logging():
    """
    Init the logging info
    """
    try:
        # First look at /etc/im/logging.conf file
        logging.config.fileConfig('/etc/im/logging.conf')
    except Exception as ex:
        print(ex)
        log_dir = os.path.dirname(Config.LOG_FILE)
        if not os.path.isdir(log_dir):
            os.makedirs(log_dir)

        fileh = logging.handlers.RotatingFileHandler(
            filename=Config.LOG_FILE, maxBytes=Config.LOG_FILE_MAX_SIZE, backupCount=3)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fileh.setFormatter(formatter)

        if Config.LOG_LEVEL == "DEBUG":
            log_level = logging.DEBUG
        elif Config.LOG_LEVEL == "INFO":
            log_level = logging.INFO
        elif Config.LOG_LEVEL in ["WARN", "WARNING"]:
            log_level = logging.WARN
        elif Config.LOG_LEVEL == "ERROR":
            log_level = logging.ERROR
        elif Config.LOG_LEVEL in ["FATAL", "CRITICAL"]:
            log_level = logging.FATAL
        else:
            log_level = logging.WARN

        logging.RootLogger.propagate = False
        logging.root.setLevel(logging.ERROR)

        log = logging.getLogger('ConfManager')
        log.setLevel(log_level)
        log.propagate = False
        log.addHandler(fileh)

        log = logging.getLogger('CloudConnector')
        log.setLevel(log_level)
        log.propagate = False
        log.addHandler(fileh)

        log = logging.getLogger('InfrastructureManager')
        log.setLevel(log_level)
        log.propagate = False
        log.addHandler(fileh)

    # Add the filter to add extra fields
    try:
        filt = ExtraInfoFilter()
        log = logging.getLogger('ConfManager')
        log.addFilter(filt)
        log = logging.getLogger('CloudConnector')
        log.addFilter(filt)
        log = logging.getLogger('InfrastructureManager')
        log.addFilter(filt)
    except Exception as ex:
        print(ex)


def im_stop():
    """
    Function to safely stop the service
    """
    try:
        # Stop the REST API server
        rest_server.stop()

        # Assure that the IM data are correctly saved
        InfrastructureManager.logger.info('Stopping Infrastructure Manager daemon...')
        InfrastructureManager.stop()
    except Exception:
        InfrastructureManager.logger.exception("Error stopping Infrastructure Manager daemon")

    # Assure that there are no Ansible process pending
    kill_childs()

    InfrastructureManager.logger.info('************ Infrastructure Manager daemon stopped ************')
    print("IM service stopped.")
    logging.shutdown()
    sys.exit(0)


def get_childs(parent_id=None):
    if parent_id is None:
        parent_id = os.getpid()
    childs = []
    for proc in psutil.process_iter():
        if not parent_id or parent_id == proc.ppid():
            childs.append(proc.pid)
    if childs:
        res = childs
        for child in childs:
            res.extend(get_childs(int(child)))
        return res
    else:
        return childs


def kill_childs():
    for pid_str in get_childs():
        os.kill(int(pid_str), signal.SIGTERM)
    # assure to kill all the processes using KILL signal
    time.sleep(1)
    for pid_str in get_childs():
        os.kill(int(pid_str), signal.SIGKILL)


def signal_int_handler(signal_num, frame):
    """
    Callback function to catch the system signals
    """
    print("Signal %s received. Exiting..." % signal_num)
    im_stop()


def main():
    parser = argparse.ArgumentParser(description='IM service')
    parser.add_argument('--version', help='Show IM service version.', dest="version",
                        action="store_true", default=False)
    args = parser.parse_args()

    if args.version:
        print("IM %s" % version)
        sys.exit(0)

    # Register the signal handlers
    for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
        signal.signal(sig, signal_int_handler)

    config_logging()
    launch_daemon()


if __name__ == "__main__":
    main()
