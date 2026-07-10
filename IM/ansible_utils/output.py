# IM - Infrastructure Manager
# Copyright (C) 2026 - GRyCAP - Universitat Politecnica de Valencia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import logging
import sys


class AnsibleOutput:
    """
    Serializable output target for Ansible callbacks running in a child process.
    """

    def __init__(self, output=None):
        self.stream = None
        self.log_name = None
        self.log_level = None
        self.log_file = None

        if isinstance(output, AnsibleOutput):
            self.stream = output.stream
            self.log_name = output.log_name
            self.log_level = output.log_level
            self.log_file = output.log_file
        elif output is not None:
            self.stream = output

    @classmethod
    def from_value(cls, output=None):
        if isinstance(output, cls):
            return output
        elif isinstance(output, logging.Logger):
            return cls.from_logger(output)
        return cls.from_stream(output)

    @classmethod
    def from_logger(cls, logger):
        output = cls()
        output.log_name = logger.name
        output.log_level = logger.getEffectiveLevel()
        output.log_file = cls._find_log_file(logger)
        return output

    @classmethod
    def from_stream(cls, stream):
        return cls(stream)

    @property
    def is_logger(self):
        return self.log_name is not None

    @staticmethod
    def _find_log_file(logger):
        current = logger
        while current:
            for handler in current.handlers:
                if isinstance(handler, logging.FileHandler) and getattr(handler, 'baseFilename', None):
                    return handler.baseFilename
            if not current.propagate:
                break
            current = current.parent

        for handler in logging.root.handlers:
            if isinstance(handler, logging.FileHandler) and getattr(handler, 'baseFilename', None):
                return handler.baseFilename
        return None

    def _get_logger(self):
        logger = logging.getLogger(self.log_name)
        level = self.log_level if self.log_level is not None else logging.INFO
        logger.setLevel(level)

        if logger.hasHandlers():
            return logger

        if not self.log_file:
            logging.basicConfig(level=level, format='%(message)s', datefmt='%m-%d-%Y %H:%M:%S')
            return logger

        try:
            handler = logging.FileHandler(self.log_file)
            handler.setFormatter(logging.Formatter('%(message)s', datefmt='%m-%d-%Y %H:%M:%S'))
            logger.addHandler(handler)
            logger.propagate = False
        except Exception:
            logging.basicConfig(level=level, format='%(message)s', datefmt='%m-%d-%Y %H:%M:%S')

        return logger

    def write(self, msg):
        if self.is_logger:
            self._get_logger().info(msg)
        elif self.stream:
            self.stream.write("%s\n" % msg)
            if hasattr(self.stream, 'flush'):
                self.stream.flush()
        else:
            sys.stdout.write(msg)
            sys.stdout.flush()

    def queue_output(self):
        if self.is_logger:
            return None
        return self.stream
