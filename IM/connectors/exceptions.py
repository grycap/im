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


class CloudConnectorException(Exception):
    def __init__(self, message):
        super().__init__(message)


class NoCompatibleAuthData(CloudConnectorException):
    def __init__(self, cloud_type):
        super().__init__("No compatible auth data has been specified to %s." % cloud_type)


class NoAuthData(CloudConnectorException):
    def __init__(self, cloud_type):
        super().__init__("No auth data has been specified to %s." % cloud_type)


class NoCorrectAuthData(CloudConnectorException):
    def __init__(self, cloud_type, args=""):
        msg = "No correct auth data has been specified to %s." % cloud_type
        if args:
            msg += ": %s" % args
        super().__init__(msg)
