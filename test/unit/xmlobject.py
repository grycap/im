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

from IM.xmlobject import XMLObject


class NIC(XMLObject):
    values = ['BRIDGE', 'IP', 'MAC', 'NETWORK', 'VNID']


class OS(XMLObject):
    values = ['ARCH']


class DISK(XMLObject):
    values = ['SIZE', 'SOURCE']
    numeric = ['SIZE']


class TEMPLATE(XMLObject):
    values = ['CPU', 'MEMORY']
    values_lists = ['TIME']
    tuples = {'OS': OS}
    tuples_lists = {'DISK': DISK}
    numeric = ['CPU', 'MEMORY']
    noneval = 0


class TestXMLObject(unittest.TestCase):
    """
    Class to test the XMLObject class
    """

    def test_timed_call(self):
        xml_data = """
            <TEMPLATE>
                <TIME>1</TIME>
                <TIME>2</TIME>
                <CPU><![CDATA[1]]></CPU>
                <MEMORY><![CDATA[512]]></MEMORY>
                <DISK>
                    <SIZE><![CDATA[20000]]></SIZE>
                    <SOURCE><![CDATA[ubuntu-14-04-v5]]></SOURCE>
                </DISK>
                <DISK>
                    <SIZE><![CDATA[40000]]></SIZE>
                    <SOURCE><![CDATA[data]]></SOURCE>
                </DISK>
                <OS>
                    <ARCH><![CDATA[x86_64]]></ARCH>
                </OS>
            </TEMPLATE>"""
        parsed_data = TEMPLATE(xml_data)
        self.assertEqual(len(parsed_data.DISK), 2)
        self.assertEqual(parsed_data.MEMORY, 512)

        res = parsed_data.to_xml()
        expected = ('<TEMPLATE>\n<OS>\n<ARCH>x86_64</ARCH>\n</OS>\n<DISK>\n<SIZE>20000</SIZE>\n'
                    '<SOURCE>ubuntu-14-04-v5</SOURCE>\n</DISK>\n<DISK>\n<SIZE>40000</SIZE>\n'
                    '<SOURCE>data</SOURCE>\n</DISK>\n<TIME>1</TIME>\n<TIME>2</TIME>\n<CPU>1</CPU>\n'
                    '<MEMORY>512</MEMORY>\n</TEMPLATE>\n')
        self.assertEqual(res, expected)

if __name__ == '__main__':
    unittest.main()
