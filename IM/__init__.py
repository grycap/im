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


__all__ = ['auth', 'CloudInfo', 'config', 'ConfManager', 'db',
           'InfrastructureInfo', 'InfrastructureManager', 'recipe', 'request', 'REST', 'retry',
           'ServiceRequests', 'SSH', 'SSHRetry', 'timedcall', 'UnixHTTPAdapter',
           'VirtualMachine', 'VMRC', 'xmlobject']
__version__ = '1.9.0'
__author__ = 'Miguel Caballer'


def get_ex_error(ex):
    """
    Return a secure string with the error of the exception in Py2 and Py3
    """
    try:
        return "%s" % ex
    except Exception:
        error = getattr(ex, 'message', None)
        if not error:
            error = ex.args[0] if len(ex.args) else repr(ex)
        return error
