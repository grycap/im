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

import logging


class LoggerMixin(object):
    """
    Class add Inf ID in all log messages
    """

    def log_msg(self, level, msg, exc_info=0):
        msg = "Inf ID: %s: %s" % (self.inf.id, msg)
        self.logger.log(level, msg, exc_info=exc_info)

    def log_error(self, msg):
        self.log_msg(logging.ERROR, msg)

    def log_debug(self, msg):
        self.log_msg(logging.DEBUG, msg)

    def log_warn(self, msg):
        self.log_msg(logging.WARNING, msg)

    def log_exception(self, msg):
        self.log_msg(logging.ERROR, msg, exc_info=1)

    def log_info(self, msg):
        self.log_msg(logging.INFO, msg)
