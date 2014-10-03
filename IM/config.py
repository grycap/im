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
	ACTIVATE_REST = False
	REST_PORT = 8800
	USER_DB = ""
	IM_PATH = os.path.dirname(os.path.realpath(__file__))
	LOG_FILE = '/var/log/im/inf.log'
	LOG_FILE_MAX_SIZE = 10485760
	LOG_LEVEL = logging.DEBUG
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

config = ConfigParser.ConfigParser()
config.read([Config.IM_PATH + '/../im.cfg', Config.IM_PATH + '/../etc/im.cfg', '/etc/im/im.cfg'])

if config.has_option('im', "DEFAULT_VM_MEMORY"):
	Config.DEFAULT_VM_MEMORY = config.getint('im', "DEFAULT_VM_MEMORY")

if config.has_option('im', "DEFAULT_VM_MEMORY_UNIT"):
	Config.DEFAULT_VM_MEMORY_UNIT = config.get('im', "DEFAULT_VM_MEMORY_UNIT")

if config.has_option('im', "DEFAULT_VM_CPUS"):
	Config.DEFAULT_VM_CPUS = config.getint('im', "DEFAULT_VM_CPUS")

if config.has_option('im', "DEFAULT_VM_CPU_ARCH"):
	Config.DEFAULT_VM_CPU_ARCH = config.get('im', "DEFAULT_VM_CPU_ARCH")
	
if config.has_option('im', "DEFAULT_VM_NAME"):
	Config.DEFAULT_VM_NAME = config.get('im', "DEFAULT_VM_NAME")

if config.has_option('im', "DEFAULT_DOMAIN"):
	Config.DEFAULT_DOMAIN = config.get('im', "DEFAULT_DOMAIN")

if config.has_option('im', "MAX_VM_FAILS"):
	Config.MAX_VM_FAILS = config.getint('im', "MAX_VM_FAILS")

if config.has_option('im', "WAIT_RUNNING_VM_TIMEOUT"):
	Config.WAIT_RUNNING_VM_TIMEOUT = config.getint('im', "WAIT_RUNNING_VM_TIMEOUT")

if config.has_option('im', "XMLRCP_PORT"):
	Config.XMLRCP_PORT = config.getint('im', "XMLRCP_PORT")

if config.has_option('im', "ACTIVATE_REST"):
	Config.ACTIVATE_REST = config.getboolean('im', "ACTIVATE_REST")

if config.has_option('im', "REST_PORT"):
	Config.REST_PORT = config.getint('im', "REST_PORT")

if config.has_option('im', "IM_PATH"):
	Config.IM_PATH = config.get('im', "IM_PATH")
	
if config.has_option('im', "USER_DB"):
	Config.USER_DB = config.get('im', "USER_DB")

if config.has_option('im', "LOG_LEVEL"):
	Config.LOG_LEVEL = eval(config.get('im', "LOG_LEVEL"))

if config.has_option('im', "LOG_FILE"):
	Config.LOG_FILE = config.get('im', "LOG_FILE")

if config.has_option('im', "LOG_FILE_MAX_SIZE"):
	Config.LOG_FILE_MAX_SIZE = config.getint('im', "LOG_FILE_MAX_SIZE")

# Valores para usar ansible
if config.has_option('im', "CONTEXTUALIZATION_DIR"):
	Config.CONTEXTUALIZATION_DIR = config.get('im', "CONTEXTUALIZATION_DIR")

if config.has_option('im', "RECIPES_DIR"):
	Config.RECIPES_DIR = config.get('im', "RECIPES_DIR")

if config.has_option('im', "RECIPES_DB_FILE"):
	Config.RECIPES_DB_FILE = config.get('im', "RECIPES_DB_FILE")

if config.has_option('im', "MAX_CONTEXTUALIZATION_TIME"):
	Config.MAX_CONTEXTUALIZATION_TIME = config.getint('im', "MAX_CONTEXTUALIZATION_TIME")

# Fichero para la persistencia
if config.has_option('im', "DATA_FILE"):
	Config.DATA_FILE = config.get('im', "DATA_FILE")

if config.has_option('im', "MAX_INF_STORED"):
	Config.MAX_INF_STORED = config.getint('im', "MAX_INF_STORED")

if config.has_option('im', "XMLRCP_SSL"):
	Config.XMLRCP_SSL = config.getboolean('im', "XMLRCP_SSL")

if config.has_option('im', "XMLRCP_SSL_KEYFILE"):
	Config.XMLRCP_SSL_KEYFILE = config.get('im', "XMLRCP_SSL_KEYFILE")

if config.has_option('im', "XMLRCP_SSL_CERTFILE"):
	Config.XMLRCP_SSL_CERTFILE = config.get('im', "XMLRCP_SSL_CERTFILE")

if config.has_option('im', "XMLRCP_SSL_CA_CERTS"):
	Config.XMLRCP_SSL_CA_CERTS = config.get('im', "XMLRCP_SSL_CA_CERTS")


if config.has_option('im', "REST_SSL"):
	Config.REST_SSL = config.getboolean('im', "REST_SSL")

if config.has_option('im', "REST_SSL_KEYFILE"):
	Config.REST_SSL_KEYFILE = config.get('im', "REST_SSL_KEYFILE")

if config.has_option('im', "REST_SSL_CERTFILE"):
	Config.REST_SSL_CERTFILE = config.get('im', "REST_SSL_CERTFILE")

if config.has_option('im', "REST_SSL_CA_CERTS"):
	Config.REST_SSL_CA_CERTS = config.get('im', "REST_SSL_CA_CERTS")
	
if config.has_option('im', "GET_GANGLIA_INFO"):
	Config.GET_GANGLIA_INFO = config.getboolean('im', "GET_GANGLIA_INFO")

