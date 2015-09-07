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

TESTS_PATH = '/home/micafer/codigo/git_im/im/test'


from IM.radl.radl_parse import parse_radl
from IM.radl.radl import RADL, Features, Feature, RADLParseException, system
import unittest

class TestRADL(unittest.TestCase):
	def __init__(self, *args):
		unittest.TestCase.__init__(self, *args)

	def radl_check(self, radl, expected_lengths=None, check_output=True):
		self.assertIsInstance(radl, RADL)
		radl.check()
		if expected_lengths:
			lengths = [len(l) for l in [radl.networks, radl.systems, radl.deploys,
			                            radl.configures, radl.contextualize]]
			self.assertEqual(lengths, expected_lengths)
		if check_output:
			self.radl_check(parse_radl(str(radl)), expected_lengths, check_output=False)
	
	def test_basic(self):
		r = parse_radl(TESTS_PATH + "/test_radl_0.radl")
		self.radl_check(r, [1, 1, 1, 1, 0])
		s = r.get_system_by_name("cursoaws")
		self.assertIsInstance(s, system)
		self.assertEqual(len(s.features), 17)
		self.assertEqual(s.getValue("disk.0.os.name"), "linux")

	def test_basic0(self):

		r = parse_radl(TESTS_PATH + "/test_radl_1.radl")
		self.radl_check(r, [2, 2, 0, 0, 0])
		s = r.get_system_by_name("main")
		self.assertEqual(s.getValue("cpu.arch"), "x86_64")
		self.assertEqual(s.getValue("net_interface.0.connection"), "publica")

	def test_references(self):

		r = parse_radl(TESTS_PATH + "/test_radl_ref.radl")
		self.radl_check(r, [2, 2, 0, 2, 2])

	def test_logic0(self):

		f0 = Feature("prop", ">=", 0)
		f1 = Feature("prop", "<=", 5)
		self.assertEqual(Features._applyInter((None, None), (f0, None)), (f0, None))
		self.assertEqual(Features._applyInter((None, None), (None, f1)), (None, f1))

	def test_dup_features(self):

		radl = """
system main (
cpu.count>=1 and
cpu.count<=0
)		"""

		with self.assertRaises(RADLParseException) as ex:
			parse_radl(radl)
		self.assertEqual(ex.exception.line, 4)

		radl = """
system main (
cpu.count=1 and
cpu.count=2
)		"""

		with self.assertRaises(RADLParseException) as ex:
			parse_radl(radl)
		self.assertEqual(ex.exception.line, 4)

		radl = """
system main (
cpu.count>=1 and
cpu.count>=5 and
cpu.count>=0
)		"""

		parse_radl(radl)

		radl = """
system main (
cpu.count=1 and
cpu.count>=0
)		"""

		parse_radl(radl)

		radl = """
system main (
cpu.count>=1 and
cpu.count<=5
)		"""

		parse_radl(radl)

		radl = """
system main (
cpu.count>=5 and
cpu.count<=5
)		"""

		parse_radl(radl)

	def test_concrete(self):

		r = parse_radl(TESTS_PATH + "/test_radl_conc.radl")
		self.radl_check(r)
		s = r.get_system_by_name("main")
		self.assertIsInstance(s, system)
		concrete_s, score = s.concrete()
		self.assertIsInstance(concrete_s, system)
		self.assertEqual(score, 201)
		
		
	def test_outports(self):

		radl = """
network publica (outbound = 'yes' and outports='8899a-8899,22-22')

system main (
net_interface.0.connection = 'publica'
)		"""
		r = parse_radl(radl)
		with self.assertRaises(RADLParseException):
			self.radl_check(r)

	def test_check_password(self):

		radl = """
network publica ()

system main (
disk.0.os.credentials.new.password = 'verysimple'
)		"""
		r = parse_radl(radl)
		with self.assertRaises(RADLParseException):
			r.check()
			
		radl = """
network publica ()

system main (
disk.0.os.credentials.new.password = 'NotS0simple+'
)		"""
		r = parse_radl(radl)
		r.check()
		
	def test_check_newline(self):
		radl = """
system test (
auth = 'asd asd asd asd asd asd asd as dasd asd as das dasd as das d                            asd \n' and
otra = 1
)
		"""
		r = parse_radl(radl)
		r.check()

if __name__ == "__main__":
	unittest.main()




