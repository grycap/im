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

import xml.dom.minidom
import logging
import os


class XMLObject:
    """
    Class to easily parse XML documents
    """
    tuples = {}
    tuples_lists = {}
    attributes = []
    values = []
    values_lists = []
    numeric = []
    noneval = None

    def to_xml(self, node_name=None):
        if node_name is None:
            node_name = self.__class__.__name__
        res = "<" + node_name

        for tag in self.__class__.attributes:
            if self.__dict__[tag] is not None and len(str(self.__dict__[tag])) > 0:
                res += ' ' + tag + ' = "' + self.__dict__[tag] + '"'

        res += ">\n"

        for tag, _ in self.__class__.tuples.items():
            if self.__dict__[tag] is not None:
                res += self.__dict__[tag].to_xml(tag)

        for tag, _ in self.__class__.tuples_lists.items():
            if self.__dict__[tag] is not None:
                obj_list = self.__dict__[tag]
                for obj in obj_list:
                    res += obj.to_xml(tag)

        for tag in self.__class__.values_lists:
            if self.__dict__[tag] is not None:
                obj_list = self.__dict__[tag]
                for value in obj_list:
                    if value is not None and len(str(value)) > 0:
                        res += "<" + tag + ">" + value + "</" + tag + ">\n"

        for tag in self.__class__.values:
            if self.__dict__[tag] is not None and len(str(self.__dict__[tag])) > 0:
                res += "<" + tag + ">" + \
                    self.__dict__[tag] + "</" + tag + ">\n"

        res += "</" + node_name + ">\n"

        return res

    @staticmethod
    def getChildByTagName(node, tagname):
        objs = []
        for e in node.childNodes:
            if e.nodeType == e.ELEMENT_NODE and e.tagName == tagname:
                objs.append(e)
        return objs

    @staticmethod
    def getText(nodelist):
        rc = []
        for node in nodelist:
            if node.nodeType == node.TEXT_NODE or node.nodeType == node.CDATA_SECTION_NODE:
                rc.append(node.data)
        return ''.join(rc)

    @staticmethod
    def handleField(fieldName, VM):
        try:
            fieldElements = VM.getElementsByTagName(fieldName)[0]
            return XMLObject.getText(fieldElements.childNodes)
        except:
            return None

    @staticmethod
    def handleFieldAsList(fieldName, VM):
        try:
            fieldElements = VM.getElementsByTagName(fieldName)
            local_list = []
            for fieldElement in fieldElements:
                local_list.append(XMLObject.getText(fieldElement.childNodes))
            return local_list
        except:
            return []

    def __setattr__(self, name, value):
        self.__dict__[name] = value

    def __init__(self, input_str):
        if isinstance(input_str, xml.dom.minidom.Element):
            dom = input_str
        else:
            if os.path.isfile(input_str):
                f = open(input_str)
                xml_str = ""
                for line in f.readlines():
                    xml_str += line
            else:
                xml_str = input_str

            dom = xml.dom.minidom.parseString(xml_str).documentElement

        for tag, className in self.__class__.tuples.items():
            objs = self.getChildByTagName(dom, tag)
            if (len(objs) > 0):
                newObj = className(objs[0])
                try:
                    dom.removeChild(objs[0])
                except:
                    pass
            else:
                newObj = None
            self.__setattr__(tag, newObj)

        for tag, className in self.__class__.tuples_lists.items():
            objs = self.getChildByTagName(dom, tag)
            obj_list = []
            for obj in objs:
                newObj = className(obj)
                dom.removeChild(obj)
                obj_list.append(newObj)
            self.__setattr__(tag, obj_list)

        for tag in self.__class__.values_lists:
            self.__setattr__(tag, XMLObject.handleFieldAsList(tag, dom))

        for tag in self.__class__.values:
            value = XMLObject.handleField(tag, dom)
            if (value is None):
                value = self.noneval
            if (tag in self.__class__.numeric and value is not None):
                try:
                    value = float(value)
                    if (value == int(value)):
                        value = int(value)
                except:
                    logging.error(
                        "Incorrect type for %s i must be numeric but it is %s" % (tag, value))
            self.__setattr__(tag, value)

        for tag in self.__class__.attributes:
            self.__setattr__(tag, dom.getAttribute(tag))
