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

try:
    from ConfigParser import ConfigParser
except ImportError:
    from configparser import ConfigParser
import os
import logging
import json


def parse_options(config, section_name, config_class):
    options = config.options(section_name)
    for option in options:
        option = option.upper()
        if option in config_class.__dict__ and not option.startswith("__"):
            if isinstance(config_class.__dict__[option], bool):
                setattr(config_class, option, config.getboolean(section_name, option))
            elif isinstance(config_class.__dict__[option], int):
                setattr(config_class, option, config.getint(section_name, option))
            elif isinstance(config_class.__dict__[option], list):
                str_value = config.get(section_name, option)
                setattr(config_class, option, str_value.split(','))
            elif isinstance(config_class.__dict__[option], dict):
                str_value = config.get(section_name, option)
                setattr(config_class, option, json.loads(str_value))
            else:
                setattr(config_class, option, config.get(section_name, option))
        else:
            logger = logging.getLogger('InfrastructureManager')
            logger.warning("Unknown option in the IM config file. Ignoring it: " + option)


class Config:

    DEFAULT_VM_MEMORY = 512
    DEFAULT_VM_MEMORY_UNIT = 'M'
    DEFAULT_VM_CPUS = 1
    DEFAULT_VM_CPU_ARCH = 'x86_64'
    DEFAULT_VM_NAME = 'vnode-#N#'
    DEFAULT_DOMAIN = 'localdomain'
    MAX_VM_FAILS = 3
    WAIT_RUNNING_VM_TIMEOUT = 1800
    WAIT_SSH_ACCCESS_TIMEOUT = 300
    WAIT_PUBLIC_IP_TIMEOUT = 90
    XMLRCP_PORT = 8899
    XMLRCP_ADDRESS = "0.0.0.0"  # nosec
    ACTIVATE_REST = True
    REST_PORT = 8800
    REST_ADDRESS = "0.0.0.0"  # nosec
    USER_DB = ""
    IM_PATH = os.path.dirname(os.path.realpath(__file__))
    LOG_FILE = '/var/log/im/inf.log'
    LOG_FILE_MAX_SIZE = 10485760
    LOG_LEVEL = "INFO"
    CONTEXTUALIZATION_DIR = IM_PATH + '/../contextualization'
    RECIPES_DIR = CONTEXTUALIZATION_DIR + '/AnsibleRecipes'
    RECIPES_DB_FILE = CONTEXTUALIZATION_DIR + '/recipes_ansible.db'
    MAX_CONTEXTUALIZATION_TIME = 7200
    MAX_SIMULTANEOUS_LAUNCHES = 1
    DATA_DB = '/etc/im/inf.dat'
    XMLRCP_SSL = False
    XMLRCP_SSL_KEYFILE = "/etc/im/pki/server-key.pem"
    XMLRCP_SSL_CERTFILE = "/etc/im/pki/server-cert.pem"
    XMLRCP_SSL_CA_CERTS = "/etc/im/pki/ca-chain.pem"
    REST_SSL = False
    REST_SSL_KEYFILE = "/etc/im/pki/server-key.pem"
    REST_SSL_CERTFILE = "/etc/im/pki/server-cert.pem"
    REST_SSL_CA_CERTS = "/etc/im/pki/ca-chain.pem"
    PLAYBOOK_RETRIES = 1
    VM_INFO_UPDATE_FREQUENCY = 10
    # This value must be always higher than VM_INFO_UPDATE_FREQUENCY
    VM_INFO_UPDATE_ERROR_GRACE_PERIOD = 120
    REMOTE_CONF_DIR = "/var/tmp/.im"  # nosec
    MAX_SSH_ERRORS = 5
    PRIVATE_NET_MASKS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                         "169.254.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15"]
    CHECK_CTXT_PROCESS_INTERVAL = 10
    CONFMAMAGER_CHECK_STATE_INTERVAL = 5
    UPDATE_CTXT_LOG_INTERVAL = 20
    ANSIBLE_INSTALL_TIMEOUT = 500
    SINGLE_SITE = False
    SINGLE_SITE_TYPE = ''
    SINGLE_SITE_AUTH_HOST = ''
    SINGLE_SITE_IMAGE_URL_PREFIX = ''
    OIDC_ISSUERS = []
    OIDC_AUDIENCE = None
    INF_CACHE_TIME = 0
    VMINFO_JSON = False
    OIDC_CLIENT_ID = None
    OIDC_CLIENT_SECRET = None
    OIDC_SCOPES = []
    OIDC_USER_INFO_PATH = "/userinfo"
    OIDC_INSTROSPECT_PATH = "/introspect"
    OIDC_GROUPS = []
    OIDC_GROUPS_CLAIM = "groups"
    VM_NUM_USE_CTXT_DIST = 30
    DELAY_BETWEEN_VM_RETRIES = 5
    VERIFI_SSL = False
    SSH_REVERSE_TUNNELS = True
    ACTIVATE_XMLRPC = True
    FORCE_OIDC_AUTH = False
    BOOT_MODE = 0  # It can be 0-Normal, 1-ReadOnly, 2-ReadDelete
    ENABLE_CORS = False
    CORS_ORIGIN = '*'
    VAULT_URL = None
    VAULT_MOUNT_POINT = None
    VAULT_PATH = None
    VAULT_ROLE = None
    VM_TAG_USERNAME = None
    VM_TAG_INF_ID = None
    VM_TAG_IM_URL = None
    VM_TAG_IM = None
    ADMIN_USER = {}
    STATIC_FILES_DIR = None
    OAIPMH_REPO_ADMIN_EMAIL = None
    OAIPMH_REPO_NAME = None
    OAIPMH_REPO_DESCRIPTION = None
    OAIPMH_REPO_BASE_IDENTIFIER_URL = None


config = ConfigParser()
config.read([Config.IM_PATH + '/../im.cfg', Config.IM_PATH +
             '/../etc/im.cfg', '/etc/im/im.cfg'])

section_name = "im"
if config.has_section(section_name):
    parse_options(config, section_name, Config)

# Get some vars from environment variables to make easy docker container configuration
if 'IM_DATA_DB' in os.environ:
    Config.DATA_DB = os.environ['IM_DATA_DB']

if 'IM_SINGLE_SITE_ONE_HOST' in os.environ:
    Config.SINGLE_SITE = True
    Config.SINGLE_SITE_TYPE = 'OpenNebula'
    Config.SINGLE_SITE_AUTH_HOST = 'http://%s:2633' % os.environ['IM_SINGLE_SITE_ONE_HOST']
    Config.SINGLE_SITE_IMAGE_URL_PREFIX = 'one://%s/' % os.environ['IM_SINGLE_SITE_ONE_HOST']


class ConfigOpenNebula:
    TEMPLATE_CONTEXT = ''
    TEMPLATE_OTHER = 'GRAPHICS = [type="vnc",listen="0.0.0.0"]'
    IMAGE_UNAME = ''
    TTS_URL = 'https://localhost:8443'


if config.has_section("OpenNebula"):
    parse_options(config, 'OpenNebula', ConfigOpenNebula)


# In this case set assume that the TTS server is in the same server
if 'IM_SINGLE_SITE_ONE_HOST' in os.environ:
    ConfigOpenNebula.TTS_URL = 'https://%s:8443' % os.environ['IM_SINGLE_SITE_ONE_HOST']
