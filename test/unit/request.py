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

from IM.request import Request, RequestQueue, AsyncRequest


class DummyRequest(AsyncRequest):
    def _execute(self):
        TestRequest.REQ_CONT += 1
        self.set(TestRequest.REQ_CONT)
        return True


class SleepRequest(AsyncRequest):
    def _execute(self):
        self.set("OK")
        self.wake_up()
        time.sleep(2)
        return True


class TestRequest(unittest.TestCase):
    """
    Class to test the Requests classes
    """
    REQ_CONT = 0

    def test_request_queue(self):
        queue = RequestQueue()
        queue.put((0, Request()))
        dr1 = DummyRequest()
        dr2 = DummyRequest()
        queue.put((1, dr1))
        queue.put((1, dr2))
        cont = queue.process_requests(-1)
        dr2.wait()
        self.assertEqual(dr2.status(), Request.STATUS_PROCESSED)
        self.assertEqual(dr2.get(), 2)
        self.assertEqual(cont, 3)
        self.assertEqual(TestRequest.REQ_CONT, 2)

    def test_wake_up(self):
        before = time.time()
        queue = RequestQueue()
        sr = SleepRequest()
        queue.put((1, sr))
        cont = queue.process_requests(-1)
        sr.wait()
        after = time.time()
        self.assertEqual(sr.status(), Request.STATUS_PROCESSING)
        self.assertEqual(sr.get(), "OK")
        self.assertLess(after - before, 2)
        self.assertEqual(cont, 1)
        time.sleep(2.5)
        self.assertEqual(sr.status(), Request.STATUS_PROCESSED)


if __name__ == '__main__':
    unittest.main()
