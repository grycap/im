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

import unittest
import time

from IM.timedcall import TimedCall, Timer


class TestTimed(unittest.TestCase):
    """
    Class to test the Timer and TimedCall classes
    """

    CONT = 0

    @staticmethod
    def callback():
        TestTimed.CONT += 1

    def test_timed_call(self):
        call = TimedCall(TestTimed.callback, time_between_calls=0.5)
        cont = 0
        while cont < 10:
            call.call()
            time.sleep(0.1)
            cont += 1
            if cont == 1:
                self.assertGreaterEqual(0.4, call.time_to_next_call)
                self.assertGreaterEqual(call.time_to_next_call, 0.3)
        self.assertEqual(TestTimed.CONT, 2)

    def test_timer(self):
        t = Timer(0.5)
        t.start()
        cont = 0
        res = 0
        while cont < 10:
            if t.can_call():
                res += 1
            cont += 1
            time.sleep(0.1)
        self.assertEqual(res, 4)

if __name__ == '__main__':
    unittest.main()
