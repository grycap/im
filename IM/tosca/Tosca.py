import os
import logging
import yaml
import copy
import tempfile

from toscaparser.tosca_template import ToscaTemplate
from toscaparser.elements.interfaces import InterfacesDef
from toscaparser.elements.entity_type import EntityType
from toscaparser.functions import Function, is_function, get_function, GetAttribute
from IM.radl.radl import system, deploy, network, Feature, configure, contextualize_item, RADL, contextualize
from  toscaparser.utils.yamlparser import load_yaml

class Tosca:
	"""
	Class to translate a TOSCA document to an RADL object.
	
	TODO: What about CSAR files?
	
	"""
	
	ARTIFACTS_PATH = os.path.dirname(os.path.realpath(__file__)) + "/artifacts"
	CUSTOM_TYPES_FILE = os.path.dirname(os.path.realpath(__file__)) + "/custom_types.yaml"
	
	logger = logging.getLogger('InfrastructureManager')
	
	def __init__(self, yaml_str):
		# Load custom data
		custom_def = load_yaml(Tosca.CUSTOM_TYPES_FILE)
		# and update tosca_def with the data
		EntityType.TOSCA_DEF.update(custom_def)
		
		self.tosca = None
		# write the contents to a file as ToscaTemplate needs 
		with tempfile.NamedTemporaryFile(suffix=".yaml") as f:
			f.write(yaml_str)
			f.flush()
			self.tosca = ToscaTemplate(f.name)

	@staticmethod
	def is_tosca(yaml_string):
		"""
		Check if a string seems to be a tosca document
		Check if it is a correct YAML document and has the item 'tosca_definitions_version'
		"""
		try:
			yamlo = yaml.load(yaml_string)
			if isinstance(yamlo, dict) and 'tosca_definitions_version' in yamlo.keys():
				return True 
			else:
				return False
		except:
			return False

	def to_radl(self):
		"""
		Converts the current ToscaTemplate object in a RADL object 
		"""
		
		relationships = []
		for node in self.tosca.nodetemplates:
			# Store relationships to check later
			for relationship, target in node.relationships.iteritems():
				source = node
				relationships.append((source, target, relationship))
		
		radl = RADL()
		interfaces = {}
		cont_intems = []
		
		for node in self.tosca.nodetemplates:
			root_type = Tosca._get_root_parent_type(node).type
			
			if root_type == "tosca.nodes.BlockStorage":
				# The BlockStorage disks are processed later
				pass
			elif root_type == "tosca.nodes.network.Port":	
				pass
			elif root_type == "tosca.nodes.network.Network":
				# TODO: check IM to support more network properties
				# At this moment we only support the network_type with values, private and public
				net = Tosca._gen_network(node)
				radl.networks.append(net)
			else:
				if root_type == "tosca.nodes.Compute":
					# Add the system RADL element
					sys = Tosca._gen_system(node, self.tosca.nodetemplates)
					radl.systems.append(sys)
					# Add the deploy element for this system
					dep = deploy(sys.name, 1)
					radl.deploys.append(dep)
					compute = node
				else:
					# Select the host to host this element
					compute = Tosca._find_host_compute(node, self.tosca.nodetemplates)
					if not compute:
						Tosca.logger.warn("Node %s has not compute node to host in." % node.name)

				interfaces = Tosca._get_interfaces(node)
				interfaces.update(Tosca._get_relationships_interfaces(relationships, node))
				
				conf = self._gen_configure_from_interfaces(radl, node, interfaces, compute)
				if conf:
					level = Tosca._get_dependency_level(node)
					radl.configures.append(conf)
					cont_intems.append(contextualize_item(compute.name, conf.name, level))

		if cont_intems:
			radl.contextualize = contextualize(cont_intems)
	
		return self._complete_radl_networks(radl)

	@staticmethod
	def _get_relationship_template(rel, src, trgt):
		rel_tpls = src.get_relationship_template()
		rel_tpls.extend(trgt.get_relationship_template())
		for rel_tpl in rel_tpls:
			if rel.type == rel_tpl.type:
				return rel_tpl

	@staticmethod
	def _get_relationships_interfaces(relationships, node):
		res = {}
		for src, trgt, rel in relationships:
			rel_tpl = Tosca._get_relationship_template(rel, src, trgt)			
			if src.name == node.name:
				for name in ['pre_configure_source', 'post_configure_source', 'add_source']:
					for iface in rel_tpl.interfaces:
						if iface.name == name:
							res[name] = iface
			elif trgt.name == node.name:
				for name in ['pre_configure_target', 'post_configure_target', 'add_target','target_changed','remove_target']:
					for iface in rel_tpl.interfaces:
						if iface.name == name:
							res[name] = iface
		return res

	def _gen_configure_from_interfaces(self, radl, node, interfaces, compute):
		if not interfaces:
			return None

		variables = ""
		tasks = ""
		recipe_list = []
		remote_artifacts_path = "/tmp"
		# Take the interfaces in correct order
		for name in ['create', 'pre_configure_source','pre_configure_target','configure', 'post_configure_source','post_configure_target', 'start', 'add_target','add_source','target_changed','remove_target']:
			interface = interfaces.get(name, None)
			if interface:
				artifacts = []
				# Get the inputs
				env = {}
				if interface.inputs:
					for param_name, param_value in interface.inputs.iteritems():
						val = None
						
						if self._is_artifact(param_value):
							artifact_uri = self._get_artifact_uri(param_value, node)
							val = remote_artifacts_path + "/" + os.path.basename(artifact_uri)
							artifacts.append(artifact_uri)
						else:
							val = self._final_function_result(param_value, node)
							
						if val:
							env[param_name] = val
						else:
							raise Exception("input value for %s in interface %s of node %s not valid" % (param_name, name, node.name))

				name = node.name + "_" + interface.name
				script_path = os.path.join(Tosca.ARTIFACTS_PATH, interface.implementation)
				
				# if there are artifacts to download
				if artifacts:
					for artifact in artifacts:
						tasks += "  - name: Download artifact " + artifact + "\n"
						tasks += "    get_url: dest=" + remote_artifacts_path + "/" + os.path.basename(artifact) + " url='" + artifact + "'\n"
				
				if interface.implementation.endswith(".yaml") or interface.implementation.endswith(".yml"):
					if os.path.isfile(script_path):
						f = open(script_path)
						script_content = f.read()
						f.close()

						if env:
							for var_name, var_value in env.iteritems():
								variables += "    %s: %s " % (var_name, var_value) + "\n"
							variables += "\n"

						recipe_list.append(script_content)
					else:
						raise Exception(script_path + " is not located in the artifacts folder.")
				else:
					if os.path.isfile(script_path):
						f = open(script_path)
						script_content = f.read().replace("\n","\\n")
						f.close()
						
						recipe = "- tasks:\n"
						recipe += "  - name: Copy contents of script of interface " + name + "\n"
						recipe += "    copy: dest=/tmp/" +  os.path.basename(script_path) + " content='" + script_content + "' mode=0755\n"
						
						recipe += "  - name: " + name + "\n"
						recipe += "    shell: /tmp/" +  os.path.basename(script_path) + "\n"
						if env:
							recipe += "    environment:\n"
							for var_name, var_value in env.iteritems():
								recipe += "      %s: %s\n" % (var_name, var_value)
						
						recipe_list.append(recipe)
					else:
						raise Exception(script_path + " is not located in the artifacts folder.")							

		if tasks or recipe_list:
			name = node.name + "_conf"
			if variables:
				recipes = "---\n- vars:\n" + variables + "\n"
				recipes += "  "
			else:
				recipes = "- "

			if tasks:
				recipes += "tasks:\n" + tasks + "\n" 
			
			# Merge the main recipe with the other yaml files
			for recipe in recipe_list:
				recipes = Tosca._merge_yaml(recipes, recipe)
			
			return configure(name, recipes)
		else:
			return None

	@staticmethod
	def _is_artifact(function):
		"""Returns True if the provided function is a Tosca get_artifact function.
	
		Examples:
	
		* "{ get_artifact: { SELF, uri } }"
	
		:param function: Function as string.
		:return: True if function is a Tosca get_artifact function, otherwise False.
		"""
		if isinstance(function, dict) and len(function) == 1:
			func_name = list(function.keys())[0]
			return func_name == "get_artifact"
		return False 
	
	@staticmethod
	def _get_artifact_uri(function, node):
		if isinstance(function, dict) and len(function) == 1:
			name = function["get_artifact"][1]
			artifacts = node.entity_tpl.get("artifacts")
			if isinstance(artifacts, dict):
				for artifact_name, value in artifacts.iteritems():
					if artifact_name == name:
						return value['implementation']

		return None 

	@staticmethod
	def _complete_radl_networks(radl):
		if not radl.networks:
			radl.networks.append(network.createNetwork("public", True))
			
		public_net = None
		for net in radl.networks:
			if net.isPublic():
				public_net = net
				break
		
		if not public_net:
			for net in radl.networks:
				public_net = net
			
		for sys in radl.systems:
			if not sys.hasFeature("net_interface.0.connection"):
				sys.setValue("net_interface.0.connection", public_net.id)
		
		return radl

	@staticmethod
	def _is_intrinsic(function):
		"""Returns True if the provided function is a Tosca get_artifact function.
	
		Examples:
	
		* "{ concat: ['str1', 'str2'] }"
		* "{ token: [ <string_with_tokens>, <string_of_token_chars>, <substring_index> ] }"
	
		:param function: Function as string.
		:return: True if function is a Tosca get_artifact function, otherwise False.
		"""
		if isinstance(function, dict) and len(function) == 1:
			func_name = list(function.keys())[0]
			return func_name in ["concat", "token"]
		return False 

	def _get_intrinsic_value(self, func, node):
		if isinstance(func, dict) and len(func) == 1:
			func_name = list(func.keys())[0]
			if func_name == "concat":
				items = func["concat"]
				res = ""
				for item in items:
					if is_function(item):
						res += str(self._final_function_result(item, node))
					else:
						res += str(item)
				return res
			elif func_name == "token":
				if len(items) == 3:
					string_with_tokens = items[0]
					string_of_token_chars = items[1]
					substring_index = int(items[2])
					
					parts = string_with_tokens.split(string_of_token_chars)
					if len(parts) >= substring_index:
						return parts[substring_index]
					else:
						Tosca.logger.error("Incorrect substring_index in function token.")
						return None
				else:
					Tosca.logger.warn("Intrinsic function token must receive 3 parameters.")
					return None
			else:
				Tosca.logger.warn("Intrinsic function %s not supported." % func_name)
				return None

	def _get_attribute_result(self, func, node):
		"""Get an attribute value of an entity defined in the service template
	
		Node template attributes values are set in runtime and therefore its the
		responsibility of the Tosca engine to implement the evaluation of
		get_attribute functions.
	
		Arguments:
	
		* Node template name | HOST.
		* Attribute name.
	
		If the HOST keyword is passed as the node template name argument the
		function will search each node template along the HostedOn relationship
		chain until a node which contains the attribute is found.
	
		Examples:
	
		* { get_attribute: [ server, private_address ] }
		* { get_attribute: [ HOST, private_address ] }
		* { get_attribute: [ SELF, private_address ] }
		"""
		node_name = func.args[0]
		attribute_name = func.args[1]

		if node_name == "HOST":
			node = self._find_host_compute(node, self.tosca.nodetemplates)
		else:
			for n in self.tosca.nodetemplates:
				if n.name == node_name:
					node = n
					break

		if attribute_name == "tosca_id":
			if node_name in ["HOST", "SELF"]: 
				return "{{ IM_NODE_VMID }}"
			else:
				return "{{ hostvars[groups['%s'][0]]['IM_NODE_VMID'] }}" % node.name
		elif attribute_name == "tosca_name":
			return node.name
		elif attribute_name == "private_address":
			# TODO: we suppose that iface 1 is the private one 
			if node_name in ["HOST", "SELF"]: 
				return "{{ IM_NODE_NET_1_IP }}"
			else:
				return "{{ hostvars[groups['%s'][0]]['IM_NODE_NET_1_IP'] }}" % node.name
		elif attribute_name == "public_address":
			if node_name in ["HOST", "SELF"]: 
				return "{{ IM_NODE_ANSIBLE_IP }}"
			else:
				return "{{ hostvars[groups['%s'][0]]['IM_NODE_ANSIBLE_IP'] }}" % node.name
		elif attribute_name == "ip_address": 
			root_type = Tosca._get_root_parent_type(node).type
			if root_type == "tosca.nodes.network.Port":
				order = node.get_property_value('order')
				return "{{ hostvars[groups['%s'][0]]['IM_NODE_NET_%s_IP'] }}" % (node.name, order)
			elif root_type == "tosca.capabilities.Endpoint":
				# TODO: check this
				if node_name in ["HOST", "SELF"]: 
					return "{{ IM_NODE_ANSIBLE_IP }}"
				else:
					return "{{ hostvars[groups['%s'][0]]['IM_NODE_ANSIBLE_IP'] }}" % node.name
			else:
				Tosca.logger.warn("Attribute ip_address only supported in tosca.nodes.network.Port and tosca.capabilities.Endpoint nodes.")
				return None
		else:
			Tosca.logger.warn("Attribute %s not supported." % attribute_name)
			return None
		
	def _final_function_result(self, func, node):
		"""
		Take a translator.toscalib.functions.Function and return the final result
		(in some cases the result of a function is another function)
		"""
		if isinstance(func, dict):
			if is_function(func):
				func = get_function(self.tosca, node, func)

		if isinstance(func, Function):
			if isinstance(func, GetAttribute):
				func = self._get_attribute_result(func, node)
			while isinstance(func, Function):
				func = func.result()

		if isinstance(func, dict):
			if self._is_intrinsic(func):
				func = self._get_intrinsic_value(func, node)				
		
		if func is None:
			# TODO: resolve function values related with run-time values as IM or ansible variables 
			pass
		return func
	
	@staticmethod
	def _find_host_compute(node, nodetemplates):
		"""
		Select the node to host each node, using the node requirements
		In most of the cases the are directly specified, otherwise "node_filter" is used
		"""

		# check for a HosteOn relation
		root_type = Tosca._get_root_parent_type(node).type
		if root_type == "tosca.nodes.Compute":
			return node

		if node.requirements:
			for r, n in node.relationships.iteritems():
				if Tosca._is_derived_from(r, r.HOSTEDON) or Tosca._is_derived_from(r, r.BINDSTO):
					root_type = Tosca._get_root_parent_type(n).type
					if root_type == "tosca.nodes.Compute":
						return n
					else:
						return Tosca._find_host_compute(n, nodetemplates)

		# There are no direct HostedOn node
		# check node_filter requirements
		if node.requirements:
			for requires in node.requirements:
				if 'host' in requires:
					value = requires.get('host')
					if isinstance(value, dict):
						if 'node_filter' in value:
							node_filter = value.get('node_filter')
							return Tosca._get_compute_from_node_filter(node_filter, nodetemplates)
		
		return None
	
	@staticmethod
	def _node_fulfill_filter(node, node_filter):
		"""
		Check if a node fulfills the features of a node filter
		"""
		
		# Get node properties
		node_props = {}
		for cap_type in ['os', 'host']:
			if node.get_capability(cap_type):
				for prop in node.get_capability(cap_type).get_properties_objects():
					if prop.value:
						unit = None
						value = prop.value
						if prop.name in ['disk_size', 'mem_size']:
							value, unit = Tosca._get_size_and_unit(prop.value)
						node_props[prop.name] = (value, unit) 
					
		filter_props = {}
		# Get node_filter properties
		for elem in node_filter:
			if isinstance(elem, dict):
				for cap_type in ['os', 'host']:
					if cap_type in elem:
						for p in elem.get(cap_type).get('properties'):
							p_name = p.keys()[0]
							p_value = p.values()[0]
							if isinstance(p_value, dict):
								filter_props[p_name] = (p_value.keys()[0], p_value.values()[0])
							else:
								filter_props[p_name] = ("equal", p_value)
	
		operator_map = {
			'equal':'==',
			'greater_than':'>',
			'greater_or_equal':'>=',
			'less_than': '<',
			'less_or_equal': '<='
		}
		
		# Compare the properties
		for name, value in filter_props.iteritems():
			operator, filter_value = value
			if name in ['disk_size', 'mem_size']:
				filter_value, _ = Tosca._get_size_and_unit(filter_value)
				
			if name in node_props:
				node_value, _ = node_props[name] 
				
				if isinstance(node_value, str) or isinstance(node_value, unicode):
					str_node_value = "'" + node_value + "'"
				else:
					str_node_value = str(node_value)
	
				conv_operator = operator_map.get(operator, None)
				if conv_operator:
					if isinstance(filter_value, str) or isinstance(filter_value, unicode):
						str_filter_value = "'" + filter_value + "'"
					else:
						str_filter_value = str(filter_value)					
	
					comparation = str_node_value  + conv_operator + str_filter_value
				else:
					if operator == "in_range":
						minv = filter_value[0]
						maxv = filter_value[1]
						comparation = str_node_value + ">=" +str(minv) + " and " + str_node_value + "<=" + str(maxv)
					elif operator == "valid_values":
						comparation = str_node_value + " in " + str(filter_value)
					else: 
						Tosca.logger.warn("Logical operator %s not supported." % operator)
				
				if not eval(comparation):
					return False
			else:
				# if this property is not specified in the node, return False
				# TODO: we must think about default values
				return False
	
		return True
	
	@staticmethod
	def _get_compute_from_node_filter(node_filter, nodetemplates):
		"""
		Select the first node that fulfills the specified "node_filter"
		"""
		#{'capabilities': [{'host': {'properties': [{'num_cpus': {'in_range': [1, 4]}}, {'mem_size': {'greater_or_equal': '2 GB'}}]}}, {'os': {'properties': [{'architecture': {'equal': 'x86_64'}}, {'type': 'linux'}, {'distribution': 'ubuntu'}]}}]}
	
		for node in nodetemplates:
			root_type = Tosca._get_root_parent_type(node).type
			
			if root_type == "tosca.nodes.Compute":
				if Tosca._node_fulfill_filter(node, node_filter.get('capabilities')):
					return node
	
		return None
	
	@staticmethod
	def _get_dependency_level(node):
		"""
		Check the relations to get the contextualization level
		"""
		if node.related_nodes:
			maxl = 0
			for node_depend in node.related_nodes:
				level = Tosca._get_dependency_level(node_depend)
				if level > maxl:
					maxl = level
			return maxl + 1
		else:
			return 1
	
	@staticmethod
	def _unit_to_bytes(unit):
		"""Return the value of an unit."""
		if not unit:
			return 1
		unit = unit.upper()
		
		if unit.startswith("KI"):
			return 1024
		elif unit.startswith("K"):
			return 1000
		elif unit.startswith("MI"):
			return 1048576
		elif unit.startswith("M"):
			return 1000000
		elif unit.startswith("GI"):
			return 1073741824
		elif unit.startswith("G"):
			return 1000000000
		elif unit.startswith("TI"):
			return 1099511627776
		elif unit.startswith("T"):
			return 1000000000000
		else:
			return 1
	
	@staticmethod
	def _get_size_and_unit(str_value):
		"""
		Normalize the size and units to bytes
		"""
		parts = str_value.split(" ")
		value = float(parts[0])
		unit = 'M'
		if len(parts) > 1:
			unit = parts[1]
		
		value = int(value * Tosca._unit_to_bytes(unit))
		
		return value, 'B'
	
	@staticmethod
	def _gen_network(node):
		"""
		Take a node of type "Network" and get the RADL.network to represent it
		"""
		res = network(node.name)
		
		nework_type = node.get_property_value("network_type")
		network_name = node.get_property_value("network_name")
		
		# TODO: get more properties -> must be implemented in the RADL
		if nework_type == "public":
			res.setValue("outbound", "yes")
		
		if network_name:
			res.setValue("provider_id", network_name)
		
		return res		
		
		
	@staticmethod
	def _gen_system(node, nodetemplates):
		"""
		Take a node of type "Compute" and get the RADL.system to represent it
		"""
		res = system(node.name)
	
		property_map = {
			'architecture':'cpu.arch',
			'type':'disk.0.os.name',
			'distribution':'disk.0.os.flavour',
			'version': 'disk.0.os.version',
			'num_cpus': 'cpu.count',
			'disk_size': 'disk.0.size',
			'mem_size': 'memory.size',
			'cpu_frequency': 'cpu.performance'
		}
	
		for cap_type in ['os', 'host']:
			if node.get_capability(cap_type):
				for prop in node.get_capability(cap_type).get_properties_objects():
					name = property_map.get(prop.name, None)
					if name and prop.value:
						unit = None
						value = prop.value
						if prop.name in ['disk_size', 'mem_size']:
							value, unit = Tosca._get_size_and_unit(prop.value)
						
						if prop.name == "version":
							value= str(value)
	
						if isinstance(value, float) or isinstance(value, int):
							operator = ">="
						else:
							operator = "="
						
						feature = Feature(name, operator, value, unit)
						res.addFeature(feature)
			
		# Find associated BlockStorages
		disks = Tosca._get_attached_disks(node, nodetemplates)
		
		for size, unit, location, device, num in disks:
			res.setValue('disk.%d.size' % num, size, unit)
			if device:
				res.setValue('disk.%d.device' % num, device)
			if location:
				res.setValue('disk.%d.mount_path' % num, location)
				res.setValue('disk.%d.fstype' % num, "ext4")
		
		# Find associated Networks		
		nets = Tosca._get_bind_networks(node, nodetemplates)
		for net_name, ip, dns_name, num in nets:
			res.setValue('net_interface.%d.connection' % num, net_name)
			if dns_name:
				res.setValue('net_interface.%d.dns_name' % num, dns_name)
			if ip:
				res.setValue('net_interface.%d.ip' % num, ip)
		
		return res
	
	@staticmethod
	def _get_bind_networks(node, nodetemplates):
		nets = []
		count = 0
		for requires in node.requirements:
			for value in requires.values():
				name = None
				ip = None
				dns_name = None
				if isinstance(value, dict):
					if 'relationship' in value:
						rel = value.get('relationship')
						
						rel_type = None
						if isinstance(rel, dict) and 'type' in rel:
							rel_type = rel.get('type')
						else:
							rel_type = rel
						
						if rel_type and rel_type.endswith("BindsTo"):
							if isinstance(rel, dict) and 'properties' in rel:
								prop = rel.get('properties')
								if isinstance(prop, dict):
									ip = prop.get('ip', None)
									dns_name = prop.get('dns_name', None)
							
							name = value.values()[0]
							nets.append((name, ip, dns_name, count))
							count += 1
				else:
					Tosca.logger.error("ERROR: expected dict in requires values.")
			
		for port in nodetemplates:
			root_type = Tosca._get_root_parent_type(port).type
			if root_type == "tosca.nodes.network.Port":
				binding = None
				link = None
				for requires in port.requirements:
					binding = requires.get('binding', binding)
					link = requires.get('link', link)
				
				if binding == node.name:
					ip = port.get_property_value('ip_address')
					order = port.get_property_value('order')
					dns_name = None
					nets.append((link, ip, dns_name, order))
		
		return nets
		
		
	@staticmethod
	def _get_attached_disks(node, nodetemplates):
		"""
		Get the disks attached to a node
		"""
		disks = []
		count = 1
		for requires in node.requirements:
			for value in requires.values():
				size = None
				location = None
				device = None
				if isinstance(value, dict):
					if 'relationship' in value:
						rel = value.get('relationship')
						
						rel_type = None
						if isinstance(rel, dict) and 'type' in rel:
							rel_type = rel.get('type')
						else:
							rel_type = rel
						
						if rel_type and rel_type.endswith("AttachesTo"):
							if isinstance(rel, dict) and 'properties' in rel:
								prop = rel.get('properties')
								if isinstance(prop, dict):
									location = prop.get('location', None)
									device = prop.get('device', None)

							# seet a default device	
							if not device:
								device = "hdb"

							for node_name in value.values():
								for n in nodetemplates:
									if n.name == node_name:
										size, unit = Tosca._get_size_and_unit(n.get_property_value('size'))						
										break
									
							disks.append((size, unit, location, device, count))
							count += 1
				else:
					Tosca.logger.error("ERROR: expected dict in requires values.")
			
		return disks
	
	@staticmethod
	def _is_derived_from(rel, parent_type):	
		"""
		Check if a node is a descendant from a specified parent type
		"""
		while True:		
			if rel.type == parent_type:
				return True
			else:
				if rel.parent_type:
					rel = rel.parent_type
				else:
					return False
	@staticmethod
	def _get_root_parent_type(node):
		"""
		Get the root parent type of a node (just before the tosca.nodes.Root)
		"""
		node_type = node.type_definition
		
		while True:
			if node_type.parent_type != None:
				if node_type.parent_type.type.endswith(".Root"):
					return node_type
				else:
					node_type = node_type.parent_type
			else:
				return node_type
	
	@staticmethod
	def _get_interfaces(node):
		"""
		Get a dict of InterfacesDef of the specified node
		"""
		interfaces = {}
		for interface in node.interfaces:
			interfaces[interface.name] = interface
		
		node_type = node.type_definition
		
		while True:
			if node_type.interfaces and 'Standard' in node_type.interfaces:
				for name, elems in node_type.interfaces['Standard'].iteritems():
					if name in  ['create', 'configure', 'start', 'stop', 'delete']:
						if name not in interfaces:
							interfaces[name] = InterfacesDef(node_type, 'Standard', name=name, value=elems)

			if node_type.parent_type != None:
					node_type = node_type.parent_type
			else:
				return interfaces

	@staticmethod
	def _merge_yaml(yaml1, yaml2):
		"""
		Merge two ansible yaml docs 
	
		Arguments:
		   - yaml1(str): string with the first YAML
		   - yaml1(str): string with the second YAML
		Returns: The merged YAML. In case of errors, it concatenates both strings
		"""
		yamlo1o = {}
		try:
			yamlo1o = yaml.load(yaml1)[0]
			if not isinstance(yamlo1o, dict):
				yamlo1o = {}
		except Exception:
			Tosca.logger.exception("Error parsing YAML: " + yaml1 + "\n Ignore it")
		
		try:
			yamlo2s = yaml.load(yaml2)
			if not isinstance(yamlo2s, list) or any([ not isinstance(d, dict) for d in yamlo2s ]):
				yamlo2s = {}
		except Exception:
			Tosca.logger.exception("Error parsing YAML: " + yaml2 + "\n Ignore it")
			yamlo2s = {}

		if not yamlo2s and not yamlo1o:
			return ""

		result = []
		for yamlo2 in yamlo2s:
			yamlo1 = copy.deepcopy(yamlo1o)
			all_keys = []
			all_keys.extend(yamlo1.keys())
			all_keys.extend(yamlo2.keys())
			all_keys = set(all_keys)

			for key in all_keys:
				if key in yamlo1 and yamlo1[key]:
					if key in yamlo2 and yamlo2[key]:
						if isinstance(yamlo1[key], dict):
							yamlo1[key].update(yamlo2[key])
						elif isinstance(yamlo1[key], list):
							yamlo1[key].extend(yamlo2[key])
						else:
							# Both use have the same key with merge in a lists
							v1 = yamlo1[key]
							v2 = yamlo2[key]
							yamlo1[key] = [v1, v2]
				elif key in yamlo2 and yamlo2[key]:
					yamlo1[key] = yamlo2[key]
			result.append(yamlo1)

		return yaml.dump(result, default_flow_style=False, explicit_start=True, width=256)