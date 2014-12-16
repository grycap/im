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

import ConfigParser
import os
import logging

class Config:

	DEFAULT_VM_MEMORY = 512
	DEFAULT_VM_MEMORY_UNIT = 'M'
	DEFAULT_VM_CPUS = 1
	DEFAULT_VM_CPU_ARCH = 'x86_64'
	DEFAULT_VM_NAME = 'vnode-#N#'
	DEFAULT_DOMAIN = 'localdomain'
	MAX_VM_FAILS = 3
	WAIT_RUNNING_VM_TIMEOUT = 1800
	XMLRCP_PORT = 8899
	XMLRCP_ADDRESS = "0.0.0.0"
	ACTIVATE_REST = False
	REST_PORT = 8800
	REST_ADDRESS =  "0.0.0.0"
	USER_DB = ""
	IM_PATH = os.path.dirname(os.path.realpath(__file__))
	LOG_FILE = '/var/log/im/inf.log'
	LOG_FILE_MAX_SIZE = 10485760
	LOG_LEVEL = "DEBUG"
	CONTEXTUALIZATION_DIR = '/usr/share/im/contextualization'
	RECIPES_DIR = CONTEXTUALIZATION_DIR + '/AnsibleRecipes'
	RECIPES_DB_FILE = CONTEXTUALIZATION_DIR + '/recipes_ansible.db'
	MAX_CONTEXTUALIZATION_TIME = 7200
	MAX_SIMULTANEOUS_LAUNCHES = 1
	DATA_FILE = '/etc/im/inf.dat'
	MAX_INF_STORED = 20
	XMLRCP_SSL = False
	XMLRCP_SSL_KEYFILE =  "/etc/im/pki/server-key.pem"
	XMLRCP_SSL_CERTFILE = "/etc/im/pki/server-cert.pem"
	XMLRCP_SSL_CA_CERTS = "/etc/im/pki/ca-chain.pem"
	REST_SSL = False
	REST_SSL_KEYFILE =  "/etc/im/pki/server-key.pem"
	REST_SSL_CERTFILE = "/etc/im/pki/server-cert.pem"
	REST_SSL_CA_CERTS = "/etc/im/pki/ca-chain.pem"
	GET_GANGLIA_INFO = False
	GANGLIA_INFO_UPDATE_FREQUENCY = 30
	PLAYBOOK_RETRIES = 1
	VM_INFO_UPDATE_FREQUENCY = 10
	REMOTE_CONF_DIR = "/tmp/conf"
	MAX_SSH_ERRORS = 5

config = ConfigParser.ConfigParser()
config.read([Config.IM_PATH + '/../im.cfg', Config.IM_PATH + '/../etc/im.cfg', '/etc/im/im.cfg'])

section_name = "im"
options = config.options(section_name)
for option in options:
	option = option.upper()
	if option in Config.__dict__ and not option.startswith("__"):
		if isinstance(Config.__dict__[option], bool):
			Config.__dict__[option] = config.getboolean(section_name, option)
		elif isinstance(Config.__dict__[option], int):
			Config.__dict__[option] = config.getint(section_name, option)
		else:
			Config.__dict__[option] = config.get(section_name, option)
	else:
		logger = logging.getLogger('InfrastructureManager')
		logger.warn("Unknown option in the IM config file. Ignoring it: " + option)