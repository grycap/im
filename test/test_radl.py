
from radl_parse import parse_radl
from radl import RADL
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

		radl = """
network publica (outbound = 'yes')
system cursoaws (
cpu.arch='x86_64' and
cpu.count>=1 and
memory.size>=512m and
net_interface.0.connection = 'publica' and
net_interface.0.dns_name = 'cursoaws' and
disk.0.os.name='linux' and
disk.0.os.flavour='ubuntu' and
disk.0.os.version='12.04' and
disk.0.applications contains (name='org.grycap.cursoaws') and
disk.0.os.credentials.public_key = 'alucloud00-keypair' and
disk.0.os.credentials.private_key = '-----BEGIN RSA PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END RSA PRIVATE KEY-----'
)

configure cursoaws (
@begin
---
  - vars:
    ak_00: BBBBBBBBBBBBBBB0AA
    sk_00: ffffffffffff23202m/Sfasf/Ahaspe70efsa

    tasks:
    - name: Create user
      user: name=alucloud00 password=1234
@end
)

deploy cursoaws 1
		"""	
		r = parse_radl(radl)
		self.radl_check(r, [1, 1, 1, 1, 0])

	def test_basic0(self):

		radl = """
network publica ( outbound = 'yes')
system main (
cpu.arch='x86_64' and
cpu.count>=1 and
memory.size>=512 and
net_interfaces.count = 1 and
net_interface.0.connection='publica' and
disk.0.os.name='linux' and
disk.0.os.flavour='ubuntu'
)
system wn (
cpu.arch='x86_64' and
cpu.count>=1 and
memory.size>=512 and
disk.0.os.name='linux'
)		"""

		r = parse_radl(radl)
		self.radl_check(r, [1, 2, 0, 0, 0])

	def test_references(self):

		radl = """
network publica ( outbound = 'yes')
network ref_publica

system main (
net_interface.0.connection='publica' and
net_interface.1.connection='ref_publica'
)
system wn
contextualize (
system main configure recipe
system wn configure ref_recipe
) 

configure recipe (
@begin
---
  test: True
@end
)
configure ref_recipe
		"""

		r = parse_radl(radl)
		self.radl_check(r, [2, 2, 0, 2, 2])

if __name__ == "__main__":
	unittest.main()
