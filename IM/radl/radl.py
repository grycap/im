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

import copy
from distutils.version import LooseVersion

def UnitToValue(unit):
	"""Return the value of an unit."""

	if not unit:
		return 1
	unit = unit[0].upper()
	if unit == "K":
		return 1024
	if unit == "M":
		return 1024 * 1024
	if unit == "G":
		return 1024 * 1024 * 1024
	return 1

def is_version(version, _):
	if version.getValue() == "":
		return True
	else:
		return all([num.isdigit() for num in version.getValue().split(".")])

def check_password(password, _):
	passwd = password.value
	# Al least 6 chars
	if len(passwd) <= 6:
		return False 
	# At least one Upper leter
	if passwd.lower() == passwd:
		return False
	# At least one digit
	if len([x for x in passwd if x.isdigit()]) == 0:
		return False
	# At least one special char
	if len([x for x in passwd if not x.isalnum()]) == 0:
		return False
	return True

def check_outports_format(outports, _):
	"""
	Check the format of the outports string.
	Valid formats:
	8899/tcp-8899/tcp,22/tcp-22/tcp
	8899/tcp-8899,22/tcp-22
	8899-8899,22-22
	8899/tcp,22/udp
	8899,22
	"""
	try:
		network.parseOutPorts(outports.getValue())
	except:
		return False
	else:
		return True

class RADLParseException(Exception):
	"""Error parsing RADL document."""

	def __init__(self, msg="", line=None):
		if line:
			msg = "Line %d: %s" % (line, msg)
		self.line = line
		Exception.__init__(self, msg)

class Feature:
	"""
	Every property that can appear in the definitions of a ``network`` and ``system``.

	Args:
	- prop: feature name.
	- operator: ``<=``, ``=``, ``=>`` or ``contains``.
	- value: value associated to the feature.
	- unit: like ``K``, ``M`` and ``G``.
	- line: line number in the RADL document.
	"""

	def __init__(self, prop = None, operator = None, value = None, unit = '', line=None):
		self.prop = prop
		self.operator = operator
		self.value = value
		self.unit = unit
		self.line = line

	def __str__(self):
		if isinstance(self.value, list):
			return "{0} {1} ['{2}']".format(self.prop, self.operator, "','".join(self.value)) 
		else:
			return ("{0} {1} ({2})" if self.operator == "contains" else
		        	"{0} {1} '{2}'" if isinstance(self.value, str) or isinstance(self.value, unicode) else
		        	"{0} {1} {2}{3}").format(self.prop, self.operator, self.value,
		                                 self.unit if self.unit else "") 

	def clone(self):
		"""Return a copy of this Feature."""

		return copy.deepcopy(self)
	
	def getLogOperator(self):
		"""Return the operator of this Feature in python style."""
		if self.operator == "=":
			return "=="
		else:
			return self.operator

	def getValue(self, unit=None):
		"""
		Return the value of the feature.

		If the unit is specified and the feature has a unit, the value is converted

		Args:
		- unit(str,optional): A unit to convert the current feature value ('B','K','M','G') 
		"""

		if unit or self.unit:
			r = float(self.value * UnitToValue(self.unit)) / UnitToValue(unit)
			return int(round(r)) if isinstance(self.value, int) else r
		return self.value

	def _check(self, check, radl):
		"""
		Check type, operator and unit in a feature.

		Args:
		- check(tuple):
		   - v[0]: expected type of the feature value.
		   - v[1]: can be a list of possible values or a function to test the value or None.
		   - v[2] (optional): can be a list of possible units; if None or not set the
			 unit valid is none.
		- radl: second argument passed when calling v[1].
		"""

		# Check type
		# If the value must be float, int is also valid
		if check[0] == float:
			if not isinstance(self.value, int) and not isinstance(self.value, float):
				raise RADLParseException("Invalid type; expected %s" % check[0],
									 line=self.line)
		elif check[0] == str:
			if not isinstance(self.value, str) and not isinstance(self.value, unicode):
				raise RADLParseException("Invalid type; expected %s" % check[0],
									 line=self.line)
		else:
			if not isinstance(self.value, check[0]):
				raise RADLParseException("Invalid type; expected %s" % check[0],
									 line=self.line)
		# Check operator
		if (isinstance(self.value, str) or isinstance(self.value, unicode)) and self.prop.find('version') == -1:
			if self.operator != "=":
				raise RADLParseException("Invalid operator; expected '='",
										 line=self.line)
		elif isinstance(self.value, int) or isinstance(self.value, float) or self.prop.find('version') >= 0:
			if self.operator not in ["=", "<=", ">=", ">", "<"]:
				raise RADLParseException("Invalid operator; expected '=', '<=', " +
					 "'>=', '>' or '<'", line=self.line)
		elif isinstance(self.value, Features):
			if self.operator != "contains":
				raise RADLParseException(
					"Invalid operator; expected 'contains'", line=self.line)
		# Check value
		if isinstance(check[1], list):
			if self.value.upper() not in check[1]:
				raise RADLParseException("Invalid value; expected one of %s" % check[1],
										 line=self.line)
		elif callable(check[1]):
			if not check[1](self, radl):
				raise RADLParseException("Invalid value in property '%s'" % self.prop, line=self.line)
		# Check unit
		if len(check) < 3 or check[2] == None:
			if self.unit:
				raise RADLParseException("Invalid unit; expected none", line=self.line)
		elif len(check) > 2 and check[2]:
			if self.unit.upper() not in check[2]:
				raise RADLParseException(
					"Invalid unit; expected one of %s" % check[2], line=self.line)
		return True

class Features(object):
	"""
	Collects a group of features.
	"""

	def __init__(self, features=None):
		self.props = {}
		if features:
			for f in features:
				self.addFeature(f)

	@property
	def features(self):
		"""List of features."""

		r = []
		for _, inter in self.props.items():
			if isinstance(inter, tuple):
				if (inter[0] and inter[1] and inter[0].getValue() == inter[1].getValue() and
					inter[0].operator == "=" and inter[1].operator == "="):
					r.append(inter[0])
				else:
					r.extend([f for f in inter if f])
			elif isinstance(inter, dict):
				r.extend(inter.values())
			elif isinstance(inter, list):
				r.extend(inter)
			else:
				r.append(inter)
		return r
	
	def __str__(self):
		return " and\n".join([str(f) for f in self.features])

	def __eq__(self, other):
		if other is None:
			return self is None
		return self.props == other.props

	def clone(self):
		"""Return a copy of this aspect."""

		return copy.deepcopy(self)

	def addFeature(self, f, conflict="error", missing="other"):
		"""
		Add a feature.

		Args:

		- f(Feature): feature to add.
		- conflict(str): if a property hasn't compatible values/constrains, do:
		   - ``"error"``: raise exception.
		   - ``"ignore"``: go on.
		   - ``"me"``: keep the old value.
		   - ``"other"``: set the passed value.
		- missing(str): if a property has not been set yet, do:
		   - ``"error"``: raise exception.
		   - ``"ignore"``: do nothning.
		   - ``"me"``: do nothing.
		   - ``"other"``: set the passed value.
		"""

		OPTIONS = ["error", "ignore", "me", "other"]
		assert missing in OPTIONS, "Invalid value in `missing`."
		assert conflict in OPTIONS, "Invalid value in `missing`."

		if f.prop not in self.props and missing == "error":
			raise Exception("Property has not set.")
		elif f.prop not in self.props and missing in ["ignore", "first"]:
			return
		
		if isinstance(f.value, int) or isinstance(f.value, float):
			if f.operator == "=":
				inter1 = (f, f)
			elif f.operator[0] == "<":
				inter1 = (None, f)
			elif f.operator[0] == ">":
				inter1 = (f, None)
			inter0 = self.props.get(f.prop, (None, None))
			try:
				self.props[f.prop] = Features._applyInter(inter0, inter1, conflict)
			except Exception, e:
				raise RADLParseException("%s. Involved features: %s" % (e, [str(f0) for f0 in inter0]),
										 line=f.line)
		elif isinstance(f, SoftFeatures):
			self.props.setdefault(f.prop, []).append(f)
		elif f.operator == "contains":
			if f.prop in self.props and f.value.getValue("name") in self.props[f.prop]:
				feature = self.props[f.prop][f.value.getValue("name")].clone()
				for f0 in f.value.features:
					feature.value.addFeature(f0, conflict, missing)
				self.props[f.prop][f.value.getValue("name")] = feature
			else:
				self.props.setdefault(f.prop, {})[f.value.getValue("name")] = f
		else:
			value0 = self.props.get(f.prop, None)
			if not value0 or (conflict == "other"):
				self.props[f.prop] = f
			elif value0.value != f.value and conflict == "error":
				raise RADLParseException("Conflict adding `%s` because `%s` is already set and conflict is %s" % (f, value0, conflict), line=f.line)

	def hasFeature(self, prop, check_softs=False):
		"""Return if there is a property with that name."""

		return prop in self.props or (check_softs and
			any([ fs.hasFeature(prop) for fs in self.props.get(SoftFeatures.SOFT, []) ]))

	def getValue(self, prop, default=None):
		"""Return the value of feature with that name or ``default``."""

		f = self.props.get(prop, None)
		if not f:
			return default
		if isinstance(f, Feature):
			return f.getValue()
		if isinstance(f, tuple):
			#if f[0].getValue() == f[1].getValue():
			#	return f[0].getValue()
			# Miguel: para poder probar
			if f[0]:
				return f[0].getValue()
			elif f[1]:
				return f[1].getValue()
			raise Exception("Getting value from a property with a constrain")
		if isinstance(f, list):
			return f
		raise Exception("Getting value from a not simple property.")

	def getFeature(self, prop):
		"""Return the feature with that name."""

		f = self.props.get(prop, None)
		if not f:
			return None
		if isinstance(f, Feature):
			return f
		if isinstance(f, tuple):
			if f[0]:
				return f[0]
			elif f[1]:
				return f[1]
			raise Exception("Getting value from a property with a constrain")
		if isinstance(f, list):
			return f
		raise Exception("Getting value from a not simple property.")

	def setValue(self, prop, value, unit=None):
		"""Set the value of feature with that name."""

		if isinstance(value, int) or isinstance(value, float):
			if prop in self.props:
				for i, j in [(0, 1), (1, 0)]:
					if self.props[prop][i] == None:
						self.props[prop] = (self.props[prop][j], self.props[prop][j])
				for v in self.props[prop]:
					v.value, v.unit = value, unit
			else:
				f = Feature(prop, "=", value, unit=unit)
				self.props[prop] = (f, f)
		elif prop in self.props:
			self.props[prop].value, self.props[prop].unit = value, unit
		else:
			self.props[prop] = Feature(prop, "=", value, unit=unit)

	def delValue(self, prop):
		"""Remove the feature with that name."""

		try:
			del self.props[prop]
		except:
			pass

	@staticmethod
	def _applyInter(finter0, finter1, conflict="ignore"):
		"""
		Return the restriction of first interval by the second.

		Args:

		- inter0, inter1 (tuple of Feature): intervals

		Return(tuple of Feature): the resulting interval
		- conflict(str): if a property hasn't compatible values/constrains, do:
		   - ``"error"``: raise exception.
		   - ``"ignore"``: return None.
		   - ``"me"``: return finter0.
		   - ``"other"``: return finter1.
		"""
		
		OPTIONS = ["error", "ignore", "me", "other"]
		assert conflict in OPTIONS, "Invalid value in `conflict`."

		# Compute the comparison of the interval extremes
		# Remember, None <= number and None <= None are True, but number <= None is False.
		inter0 = tuple([f.getValue() if f else None for f in finter0])
		inter1 = tuple([f.getValue() if f else None for f in finter1])
		le00 = inter0[0] <= inter1[0]						 # finter0[0] <= finter1[0]
		le01 = inter1[1] == None or inter0[0] <= inter1[1]	# finter0[0] <= finter1[1]
		le11 = inter1[1] == None or (inter0[1] != None and inter0[1] <= inter1[1])
															# finter0[1] <= finter1[1]
		ge00 = not le00 or inter0[0] == inter1[0]			 # finter0[0] >= finter1[0]
		ge10 = inter0[1] == None or inter0[1] >= inter1[0]	# finter0[1] >= finter1[0]

		#print "\n".join("%s: %s" % (s, v) for v, s in [
		#	(le00, "finter0[0] <= finter1[0]"),
		#	(le01, "finter0[0] <= finter1[1]"),
		#	(le11, "finter0[1] <= finter1[1]"),
		#	(ge00, "finter0[0] >= finter1[0]"),
		#	(ge10, "finter0[1] >= finter1[0]") ])

		# First interval is (  ), second interval is [  ]
		if le00 and ge10 and le11:					   # ( [ ) ] chain first-second
			return finter1[0], finter0[1]
		elif le00 and ge10 and not le11:				 # ( [ ] )  second is inside first
			return finter1
		elif ge00 and le01 and le11:					 # [ ( ) ] first is inside second
			return finter0
		elif ge00 and le01 and not le11:				 # [ ( ] ) chain second-first
			return finter0[0], finter1[1]
		elif conflict == "me":
			return finter0
		elif conflict == "other":
			return finter1
		elif conflict == "error":
			raise Exception("Disjoint intervals!")
		return None
		
	def applyFeatures(self, new_features, conflict="error", missing="error"):
		"""
		Apply the constrain of the features passed to this instance.

		.. warning::
		   Feature instances are only considered, that is, SoftFeatures will be
		   not considered.

		Args:

		- new_features(Features): features to apply
		- conflict(str): if a property hasn't compatible values/constrains, do:
		   - ``"error"``: raise exception.
		   - ``"ignore"``: nothing.
		   - ``"me"``: preserve the original value.
		   - ``"other"``: set like the passed feature.
		- missing(str): if a property is missing in some side, do:
		   - ``"error"``: raise exception.
		   - ``"ignore"``: nothing.
		   - ``"me"``: preserve the original value.
		   - ``"other"``: set like the passed feature.
		"""

		OPTIONS = ["error", "ignore", "me", "other"]
		assert missing in OPTIONS, "Invalid value in `missing`."
		assert conflict in OPTIONS, "Invalid value in `missing`."

		self0 = self.clone()
		if isinstance(new_features, Features):
			new_features = new_features.features
		for f in new_features:
			self0.addFeature(f, conflict=conflict, missing=missing)
		self.props = self0.props
		return self

	def check_simple(self, checks, radl):
		"""Check types, operators and units in simple features."""

		for f in self.features:
			if not isinstance(f, Feature) or f.prop not in checks: continue
			f._check(checks[f.prop], radl)

	def check_num(self, checks, radl):
		"""
		Check types, operators and units in features with numbers.
		
		Args:

		- checks(dict of dict of str:tuples): keys are property name prefixes, and the
		  values are dict with keys are property name suffixes and values are iterable
		  as in ``_check_feature``.
		- radl: passed to ``_check_feature``.
		"""
	
		prefixes = {}
		for f in self.features:
			if not isinstance(f, Feature): continue
			(prefix, sep, tail) = f.prop.partition(".")
			if not sep or prefix not in checks: continue
			checks0 = checks[prefix]
			(num, sep, suffix) = tail.partition(".")
			try:
				num = int(num)
			except:
				raise RADLParseException(
					"Invalid property name; expected an index.", line=f.line)
			if not sep or suffix not in checks0: continue
			f._check(checks0[suffix], radl)
			if prefix not in prefixes: prefixes[prefix] = set()
			prefixes[prefix].add(num)

		# Check consecutive indices for num properties.
		for prefix, nums in prefixes.items():
			if min(nums) != 0 or max(nums) != len(nums)-1:
				raise RADLParseException(
					"Invalid indices values in properties '%s'" % prefix)

		return prefixes

class Aspect:
	"""A network, ansible_host, system, deploy, configure or contextualize element in a RADL."""

	def getId(self):
		"""Return the id of the aspect."""

		return id(self)

	def clone(self):
		"""Return a copy of this aspect."""

		return copy.deepcopy(self)

class contextualize_item:
	"""Store a line under ``contextualize`` RADL keyword."""
	def __init__(self, system_id, configure_id, num=0, ctxt_tool=None ,line=None):
		self.system = system_id
		"""System id."""
		self.configure = configure_id
		"""Configure id."""
		self.num = num
		"""Num of steps (optional)."""
		self.ctxt_tool = ctxt_tool
		"""Name of the Ctxt. tool (optional). Currently supported: 'Ansible' and 'cloud-init'. Default 'Ansible'."""
		self.line = line
		
	def __str__(self):
		return "system %s configure %s %s %s" % (self.system, self.configure,
															  "step " + str(self.num) if self.num else "",
															  "with " + self.ctxt_tool if self.ctxt_tool else "")

	def getId(self):
		"""Return an unique key for this element."""

		return (self.system, self.configure)
	
	def get_ctxt_tool(self):
		"""Return the name of the Ctxt. tool."""

		return self.ctxt_tool if self.ctxt_tool else "Ansible"

	def check(self, radl):
		"""Check a line under a contextualize."""

		if not radl.get_system_by_name(self.system):
			raise RADLParseException("Invalid system id '%s'" % self.system, line=self.line)
		if not radl.get_configure_by_name(self.configure):
			raise RADLParseException("Invalid configure id '%s'" % self.configure, line=self.line)


class contextualize(Aspect, object):
	"""Store a ``contextualize`` RADL keyword."""
	def __init__(self, items=None, max_time=0, line=None):
		self.max_time = max_time
		"""Maximum time."""
		self.items = None
		"""List of contextualize_item."""
		if isinstance(items, list):
			self.items = dict([(c.getId(), c) for c in items])
		elif isinstance(items, dict):
			self.items = items
		elif items is not None:
			raise ValueError("Unexpected type for 'items'.")
		self.line = line
		
	def __str__(self):
		if self.items is None:
			return ""
		elif not self.items:
			return "contextualize ()"
		else:
			return "contextualize %s (\n%s\n)" % (self.max_time if self.max_time else "",
											  "\n".join([str(i) for i in self.items.values()]))

	def __len__(self):
		if self.items is None:
			return 0
		else:
			return len(self.items)

	def update(self, cont):
		"""Update this instance with the contextualize passed."""

		self.max_time = max(self.max_time, cont.max_time)
		if cont.items is not None:
			if self.items is None:
				self.items = cont.items
			else:
				self.items.update(cont.items)

	def check(self, radl):
		"""Check a contextualize."""

		if not isinstance(self.max_time, int) or self.max_time < 0:
			raise RADLParseException("Invalid 'max time' in 'contextualize'",
									 line=self.line)
		if self.items is not None:
			for i in self.items.values():
				i.check(radl)
			
	def get_contextualize_items_by_step(self, default=None):
		"""Get a dictionary of the contextualize_items grouped by the step or the default value"""
		if self.items:
			res = {}
			for elem in self.items.values():
				if elem.num in res:
					res[elem.num].append(elem)
				else:
					res[elem.num] = [elem]
			return res
		else:
			return default

		
class configure(Aspect):
	"""Store a RADL ``configure``."""

	def __init__(self, name, recipe="", reference=False, line=None):
		# encode the recipe to enable to set special chars in the recipes
		self.recipes = str(recipe.encode('utf-8', 'ignore'))
		"""Recipe content."""
		self.name = str(name.encode('utf-8', 'ignore'))
		"""Configure id."""
		self.reference = reference
		"""True if it is only a reference and it isn't a definition."""
		self.line = line

	def getId(self):
		return self.name

	def __str__(self):
		if self.reference or not self.recipes:
			return "configure %s" % self.name
		return "configure %s (\n@begin\n%s\n@end\n)" % (self.name, self.recipes)

	def check(self, _):
		"""Check this configure."""

		try:
			import yaml
		except:
			return True
		try:
			yaml.load(self.recipes)
		except Exception, e:
			raise RADLParseException("Invalid YAML code: %s." % e, line=self.line)
		return True

class deploy(Aspect):
	"""Store a RADL ``deploy``."""

	def __init__(self, deploy_id, vm_number, cloud_id=None, line=None):
		self.id = deploy_id
		"""System id."""
		self.vm_number = vm_number
		"""Number of virtual machines to deploy."""
		self.cloud_id = cloud_id
		"""Cloud provider id."""
		self.line = line
		
	def __str__(self):
		res = "deploy " + self.id + (" %s" % self.vm_number)
		if self.cloud_id:
			res += " " + self.cloud_id
		return res

	def check(self, radl):
		"""Check this deploy."""

		if not radl.get_system_by_name(self.id):
			raise RADLParseException("Invalid system id in the deploy.", line=self.line)

		if self.vm_number < 0:
			raise RADLParseException("Invalid number of virtual machines to deploy.",
									 line=self.line)

class network(Features, Aspect):
	"""Store a RADL ``network``."""

	def __init__(self, name, features=None, reference=False, line=None):
		self.id = name
		"""Network id."""
		self.reference = reference
		"""True if it is only a reference and it isn't a definition."""
		Features.__init__(self, features)
		self.line = line 

	def getId(self):
		return self.id

	def __str__(self):
		return "network %s %s" % (self.id, "" if self.reference else "( %s )" % Features.__str__(self))

	def check(self, radl):
		"""Check the features in this network."""

		SIMPLE_FEATURES = {
			"outbound": (str, ["YES", "NO"]),
			"outports": (str, check_outports_format),
			"provider_id": (str, None)
		}
		self.check_simple(SIMPLE_FEATURES, radl)

	def isPublic(self):
		"""Return true if outbound = yes."""
		return self.getValue("outbound") == "yes"

	@staticmethod
	def createNetwork(name, public=False):
		"""Return a network with id being ``name`` and with outbound=yes if ``public``."""

		return network(name, [Feature("outbound", "=", "yes" if public else "no")])

	@staticmethod
	def parseOutPorts(outports):
		"""
		Parse the outports string
		Valid formats:
		8899/tcp-8899/tcp,22/tcp-22/tcp
		8899/tcp-8899,22/tcp-22
		8899-8899,22-22
		8899/tcp,22/udp
		8899,22
		Returns a list of tuple with the format: (remote_port,remote_protocol,local_port,local_protocol)
		"""
		res = []
		ports = outports.split(',')
		for port in ports:
			parts = port.split('-')
			remote_port = parts[0]
			if len(parts) > 1:
				local_port = parts[1]
			else:
				local_port = remote_port

			local_port_parts = local_port.split("/")
			if len(local_port_parts) > 1:
				local_protocol = local_port_parts[1]
				local_port = local_port_parts[0]
			else:
				local_protocol = "tcp"
		
			remote_port_parts = remote_port.split("/")	
			if len(remote_port_parts) > 1:
				remote_protocol = remote_port_parts[1]
				remote_port = remote_port_parts[0]
			else:
				remote_protocol = "tcp"
			res.append((int(remote_port),remote_protocol,int(local_port),local_protocol))
		return res

	def getOutPorts(self):
		"""
		Get the outports of this network.
		outports format: 22/tcp-22/tcp,8899/tcp,8800
		Returns a list of tuples with the format: (remote_port,remote_protocol,local_port,local_protocol)
		"""
		outports = self.getValue("outports")
		if outports:
			return self.parseOutPorts(outports)
		else:
			return None

class FeaturesApp(Features):
	"""Store an RADL application."""

	def __init__(self, features):
		Features.__init__(self, features)

	@staticmethod
	def from_str(app_name, app_version = None):
		if app_name != None:
			res = FeaturesApp([])
			res.addFeature(Feature(prop = "name", operator = "=", value = app_name))			
			if app_version:
				res.addFeature(Feature(prop = "version", operator = "=", value = app_version))
			return res
		else:
			return None

	def isNewerThan(self, other):
		""" Compare if the version of this app is newer that the other """
		if self.getValue("name") == other.getValue("name"):
			if other.getValue("version"):
				if not other.getValue("version"):
					return False
				else:
					return LooseVersion(self.getValue("version")) > LooseVersion(other.getValue("version"))
			else:
				return True
		else:
			return False

	def check(self, radl):
		"""Check the features in this application."""
		SIMPLE_FEATURES = {
			"name": (str, lambda x,_: bool(x.value)),
			"path": (str, lambda x,_: bool(x.value)),
			"version": (str, is_version),
			"preinstalled": (str, ["YES", "NO"])
		}
		self.check_simple(SIMPLE_FEATURES, radl)

class Credentials:
	pass

class UserPassCredential(Credentials):
	def __init__(self, user, passwd):
		self.username = user
		self.password = passwd
		
class UserKeyCredential(Credentials):
	def __init__(self, user, public, private=None):
		self.username = user
		self.public_key = public
		self.private_key = private
		
class system(Features, Aspect):
	"""Store a RADL ``system``."""

	def __init__(self, name, features=None, reference=False, line=None):
		self.name = name
		"""System id."""
		self.reference = reference
		"""True if it is only a reference and it isn't a definition."""
		Features.__init__(self, features)
		self.line = line

	def getId(self):
		return self.name

	def __str__(self):
		return "system %s %s" % (self.name, "" if self.reference else "(\n%s\n)\n" % Features.__str__(self))

	def hasIP(self, ip):
		"""Return True if some system has this IP."""

		for f in self.features:
			if (f.prop.startswith("net_interface.") and
			    f.prop.endswith(".ip") and f.value == ip):
				return True
		return False

	def getIfaceIP(self, iface_num):
		"""Return IP in the interface with that number."""

		ip = self.getValue("net_interface.%d.ip" % iface_num)
		if ip:
			return ip
		return None

	def getNumNetworkIfaces(self):
		"""Return the number of network interfaces defined."""

		i = 0
		while self.hasFeature("net_interface.%d.connection" % i):
			i += 1
		return i

	def getNumNetworkWithConnection(self, connection):
		"""Return the number of network interfaces with id ``connection``."""

		i = 0
		while True:
			value = self.getValue("net_interface.%d.connection" % i, None)
			if not value:
				return None
			if value == connection:
				return i
			i += 1 

	def getRequestedNameIface(self, iface_num=0, num = None, default_hostname = None, default_domain = None):
		"""Return the dns name associated to the net interface."""
		
		full_name = self.getValue("net_interface.%d.dns_name" % iface_num)

		if full_name:
			replaced_full_name = system.replaceTemplateName(full_name, num)
			(hostname, domain) = replaced_full_name
			if not domain:
				domain = default_domain
			return (hostname, domain)
		else:
			if default_hostname:
				(hostname, _) = system.replaceTemplateName(default_hostname, num)
				return (hostname, default_domain)
			else:
				return None
	
	@staticmethod
	def replaceTemplateName(full_name, num = None):
		if full_name:
			if num is not None:
				full_name = full_name.replace("#N#", str(num))
			dot_pos = full_name.find('.')
			if dot_pos != -1:
				domain = full_name[dot_pos+1:]
				name = full_name[:dot_pos]
				return (name, domain)
			else:
				return (full_name, None)
		else:
			return full_name
	
	def getNetworkIDs(self):
		"""Return a list of network id of this system."""

		res = []
		i = 0
		while True:
			netid = self.getValue("net_interface.%d.connection" % i)
			if not netid:
				return res
			res.append(netid)
			i += 1
	
	def getCredentialValues(self, new = False):
		"""Return the values in disk.0.os.credentials.*."""

		credentials_base = "disk.0.os.credentials."
		if new:
			credentials_base = "disk.0.os.credentials.new."
		return tuple([ self.getValue(credentials_base + p) for p in [
						 "username", "password", "public_key",
						 "private_key"]
					 ])
		
	def updateNewCredentialValues(self):
		"""
		Set the new credential values to the credentials to use, and delete the new ones
		"""

		credentials_base = "disk.0.os.credentials."
		new_credentials_base = "disk.0.os.credentials.new."
		
		for elem in ['password','public_key','private_key']:
			if self.getValue(new_credentials_base + elem):
				self.setValue(credentials_base + elem, self.getValue(new_credentials_base + elem))
				self.delValue(new_credentials_base + elem)
		
	def setCredentialValues(self, username=None, password=None, public_key=None, private_key=None, new = False):
		"""Set the values in disk.0.os.credentials.*."""

		credentials_base = "disk.0.os.credentials."
		if new:
			credentials_base = "disk.0.os.credentials.new."
			
		if username:
			self.setValue(credentials_base + "username", username)
		if password:
			self.setValue(credentials_base + "password", password)
		if public_key:
			self.setValue(credentials_base + "public_key", public_key)
		if private_key:
			self.setValue(credentials_base + "private_key", private_key)

		
	def getCredentials(self):
		"""Return UserKeyCredential or UserPassCredential.""" 

		(username, password, public_key, private_key) = self.getCredentialValues()
		
		if public_key or private_key:
			return UserKeyCredential(username, public_key, private_key)

		if username or password:
			return UserPassCredential(username, password)

		return None

	def setCredentials(self, creds):
		"""Set values in UserKeyCredential or UserPassCredential."""

		if isinstance(creds, UserKeyCredential):
			self.setUserKeyCredentials(creds.username, creds.public_key, creds.private_key)
		elif isinstance(creds, UserPassCredential):
			self.setUserPasswdCredentials(creds.username, creds.password)

	def setUserPasswdCredentials(self, username, password):
		"""Set username and password in ``disk.0.os.credentials``."""

		self.setCredentialValues(username=username,password=password)

	def setUserKeyCredentials(self, username, public_key=None, private_key=None):
		"""Set these properties in ``disk.0.os.credentials``."""
		
		self.setCredentialValues(username=username,public_key=public_key,private_key=private_key)

	def getApplications(self):
		"""Return a list of Application with the specified apps in this system."""

		res = []
		for f in self.features:
			if isinstance(f, Feature) and f.prop == "disk.0.applications":
				res.append(FeaturesApp(f.value.features))

		return res

	def addApplication(self, name, version=None, path=None, disk_num=0, soft=-1):
		"""Add a new application in some disk."""

		fapp = Features()
		fapp.features.append(Feature("name", "=", name))
		if version:
			fapp.features.append(Feature("version", "=", version))
		if path:
			fapp.features.append(Feature("path", "=", path))
		self.features.append(
			   Feature("disk.%d.applications" % disk_num, "contains", fapp, soft > 0))

	def check(self, radl):
		"""Check the features in this system."""

		def positive(f, _):
			return f.value >= 0

		def check_ansible_host(f, radl0):
			if radl0.get_ansible_by_id(f.value) == None:
				return False
			return True

		mem_units = ["", "B", "K", "M", "G", "KB", "MB", "GB"]
		SIMPLE_FEATURES = {
			"spot": (str, ["YES", "NO"]),
			"image_type": (str, ["VMDK", "QCOW", "QCOW2", "RAW"]),
			"virtual_system_type": (str, system._check_virtual_system_type),
			"price": ((int,float), positive, None),
			"cpu.count": (int, positive, None),
			"cpu.arch": (str, ['I386', 'X86_64']),
			"cpu.performance": ((int,float), positive, ["ECU", "GCEU", "HRZ"]),
			"memory.size": (int, positive, mem_units),
			"disk.0.os.credentials.new.password": (str, check_password),
			"ansible_host": (str, check_ansible_host),
			SoftFeatures.SOFT: (SoftFeatures, lambda x, r: x.check(r))
		}
		self.check_simple(SIMPLE_FEATURES, radl)

		net_connections = set()
		def check_net_interface_connection(f, radl0):
			if radl0.get_network_by_id(f.value) == None:
				return False
			net_connections.add(f.prop)
			return True

		def check_app(f, x):
			FeaturesApp(f.value.features).check(x)
			return True
	
		NUM_FEATURES = {
			"net_interface": {
				"connection": (str, check_net_interface_connection),
				"ip": (str, None),
				"dns_name": (str, None) },
			"disk": {
				"image.url": ((str,list), system._check_disk_image_url),
				"image.name": (str, None),
				"type": (str, ["SWAP", "ISO", "FILESYSTEM"]),
				"device": (str, None),
				"mount_path": (str, None),
				"fstype": (str, None),
				"size": (float, positive, mem_units),
				"free_size": (float, positive, mem_units),
				"os.name": (str, ["LINUX", "WINDOWS", "MAC OS X"]),
				"os.flavour": (str, None),
				"os.version": (str, is_version),
				"os.credentials.username": (str, None),
				"os.credentials.password": (str, None),
				"os.credentials.private_key": (str, None),
				"os.credentials.public_key": (str, None),
				"applications": (Features, check_app)
			}
		}
		prefixes = self.check_num(NUM_FEATURES, radl)

		# Check all interfaces
		if len(net_connections) != len(prefixes.get("net_interface", set())):
			raise RADLParseException( "Some net_interface does not have a connection")

		return True

	@staticmethod
	def _check_disk_image_url(f, radl):
		return True

	@staticmethod
	def _check_virtual_system_type(f, radl):
		return True

	def concrete(self, other=None):
		"""
		Return copy and score after being applied other system and soft features.

		Args:

		- other(system, optional): system to apply just before soft features.

		Return(tuple): tuple of the resulting system and its score.
		"""

		new_system = self.clone()
		if other:
			new_system.applyFeatures(other, missing="other")
		soft_features = self.getValue(SoftFeatures.SOFT, [])
		score = 0
		for f in sorted(soft_features, key=lambda f: f.soft, reverse=True):
			try:
				new_system.applyFeatures(f, missing="other")
				score += f.soft
			except:
				pass
		new_system.delValue(SoftFeatures.SOFT)
		return new_system, score


class SoftFeatures(system, Feature):
	"""
	Assign a weight to a group of features.

	Args:
	- soft: weight of matching the containing features.
	"""

	SOFT = "__soft__"
	"""Fake property name."""

	def __init__(self, soft, features, line=None):
		self.soft = soft
		system.__init__(self, None, features, line=line)
		Feature.__init__(self, SoftFeatures.SOFT, "contains", self)

	def __str__(self):
		return "soft %s ( %s )" % (self.soft, Features.__str__(self))


class RADL:
	"""Parsed RADL document."""
	
	def __init__(self):
		self.networks = []
		"""List of network."""
		self.ansible_hosts = []
		"""List of ansible_hosts."""
		self.systems = []
		"""List of system."""
		self.deploys = []
		"""List of deploy."""
		self.configures = []
		"""List of configure."""
		self.contextualize =  contextualize()
		"""List of contextualize."""

	def __str__(self):
		return "\n".join([ str(f) for fs in [self.ansible_hosts, self.networks, self.systems, self.configures,
									  [self.contextualize], self.deploys] for f in fs ])

	def add(self, aspect, ifpresent="error"):
		"""
		Add a network, ansible_host, system, deploy, configure or contextualize.

		Args:
		- aspect(network, system, deploy, configure or contextualize): thing to add.
		- ifpresent(str): if it has been defined, do:

		   - ``"ignore"``: not add the aspect.
		   - ``"replace"``: replace by the old defined.
		   - ``"error"``: raise an error.

		Return(bool): True if aspect was added.
		"""

		# If aspect is a contextualization, it is trated separately
		if isinstance(aspect, contextualize):
			self.contextualize.update(aspect)
			return True

		classification = [(network, self.networks), (system, self.systems), (ansible, self.ansible_hosts),
						  (deploy, self.deploys), (configure, self.configures)]
		aspect_list = [l for t, l in classification if isinstance(aspect, t)]
		assert len(aspect_list) == 1, "Unexpected aspect for RADL."
		aspect_list = aspect_list[0] 

		old_aspect = [a for a in aspect_list if a.getId() == aspect.getId()]
		if old_aspect:
			# If some aspect with the same id is found
			if ifpresent == "error":
				raise Exception("Aspect with the same id was found.")
			elif ifpresent == "replace":
				aspect_list.remove(old_aspect[0])
				aspect_list.append(aspect)
				return True
			elif ifpresent == "ignore":
				return False
			else:
				raise ValueError
		else:
			# Otherwise add aspect
			aspect_list.append(aspect)
			return True

	def get(self, aspect):
		"""Get a network, system or configure or contextualize with the same id as aspect passed."""

		classification = [(network, self.networks), (system, self.systems),
						  (configure, self.configures)]
		aspect_list = [l for t, l in classification if isinstance(aspect, t)]
		assert len(aspect_list) == 1, "Unexpected aspect for RADL."
		aspect_list = aspect_list[0] 

		old_aspect = [a for a in aspect_list if a.getId() == aspect.getId()]
		return old_aspect[0] if old_aspect else None

	def clone(self):
		return copy.deepcopy(self)
	
	def __getIP(self, public):
		"""Return the first net_interface.%d.ip for a system in a public/private network."""

		maybeNot = (lambda x: x) if public else (lambda x: not x)
		nets_id = [net.id for net in self.networks if maybeNot(net.isPublic())]
		for s in self.systems:
			i = 0
			while True:
				value = s.getValue("net_interface.%d.connection" % i)
				if not value:
					break
				if value in nets_id:
					ip = s.getValue("net_interface.%d.ip" % i)
					if ip:
						return ip
					else:
						break
				i += 1
		return None

	def getPublicIP(self):
		"""Return the first net_interface.%d.ip for a system in a public network."""

		return self.__getIP(True)
	
	def getPrivateIP(self):
		"""Return the first net_interface.%d.ip for a system in a private network."""

		return self.__getIP(False)


	def hasPublicNet(self, system_name):
		""" Return true if some system has a public network."""

		nets_id = [net.id for net in self.networks if net.isPublic()]
		system = self.get_system_by_name(system_name)
		if system:
			i = 0
			while True:
				f = system.getFeature("net_interface.%d.connection" % i)
				if not f:
					break
				if f.value in nets_id:
					return True
				i += 1
		
		return False

	def check(self):
		"""Check if it is a valid RADL document."""

		for i in [ f for fs in [self.networks, self.ansible_hosts, self.systems, self.deploys,
									self.configures, [self.contextualize]] for f in fs ]:
			i.check(self)
		return True

	def get_system_by_name(self, name):
		"""Return a system with that name or None."""

		for elem in self.systems:
			if elem.name == name:
				return elem
		return None
	
	def get_deploy_by_id(self, dep_id):
		"""Return a deploy with that system id or None."""

		for elem in self.deploys:
			if elem.id == dep_id:
				return elem
		return None
	
	def get_configure_by_name(self, name):
		"""Return a configure with that id or None."""

		for elem in self.configures:
			if elem.name == name:
				return elem
		return None
	
	def get_network_by_id(self, net_id):
		"""Return a network with that id or None."""

		for elem in self.networks:
			if elem.id == net_id:
				return elem
		return None

	def get_ansible_by_id(self, ansible_id):
		"""Return a ansible with that id or None."""

		for elem in self.ansible_hosts:
			if elem.id == ansible_id:
				return elem
		return None

class ansible(Features, Aspect):
	"""Store a RADL ``ansible``."""

	def __init__(self, name, features, line=None):
		self.id = name
		"""Ansible host id."""
		Features.__init__(self, features)
		self.line = line
		self.reference = False

	def __str__(self):
		return "ansible %s (%s)" % (self.id, Features.__str__(self))

	def getId(self):
		"""Return the id of the aspect."""

		return self.id

	def check(self, radl):
		"""Check the features in this network."""

		SIMPLE_FEATURES = {
			"host": (str, None),
			"credentials.username": (str, None),
			"credentials.password": (str, None),
			"credentials.private_key": (str, None)
		}
		self.check_simple(SIMPLE_FEATURES, radl)
		
		if not self.getHost():
			raise RADLParseException("Ansible host must have a host", line=self.line)
		(username, password, private_key) = self.getCredentialValues()
		if not username:
			raise RADLParseException("Ansible host must have a credentials.username", line=self.line)
		if not password and not private_key:
			raise RADLParseException("Ansible host must have a credentials.password or credentials.private_key", line=self.line)
	
	def getHost(self):
		return self.getValue("host")
		
	def getCredentials(self):
		"""Return UserKeyCredential or UserPassCredential.""" 

		(username, password, private_key) = self.getCredentialValues()
		
		if private_key:
			return UserKeyCredential(username, None, private_key)

		if username or password:
			return UserPassCredential(username, password)

		return None
	
	def getCredentialValues(self, new = False):
		"""Return the values in credentials.*."""

		credentials_base = "credentials."
		return tuple([ self.getValue(credentials_base + p) for p in [
						 "username", "password", "private_key"]
					 ])