import os
import logging
import yaml
import copy
import tempfile
import urllib

from IM.uriparse import uriparse
from toscaparser.tosca_template import ToscaTemplate
from toscaparser.elements.interfaces import InterfacesDef
from toscaparser.functions import Function, is_function, get_function, GetAttribute, Concat, Token
from radl.radl import system, deploy, network, Feature, Features, configure, contextualize_item, RADL, contextualize


class Tosca:
    """
    Class to translate a TOSCA document to an RADL object.

    TODO: What about CSAR files?

    """

    ARTIFACTS_PATH = os.path.dirname(
        os.path.realpath(__file__)) + "/tosca-types/artifacts"
    ARTIFACTS_REMOTE_REPO = "https://raw.githubusercontent.com/indigo-dc/tosca-types/master/artifacts/"

    logger = logging.getLogger('InfrastructureManager')

    def __init__(self, yaml_str):
        self.tosca = None
        # write the contents to a file as ToscaTemplate needs
        with tempfile.NamedTemporaryFile(suffix=".yaml") as f:
            f.write(yaml_str)
            f.flush()
            self.tosca = ToscaTemplate(f.name)

    def to_radl(self, inf_info=None):
        """
        Converts the current ToscaTemplate object in a RADL object
        If the inf_info parameter is not None, it is an AddResource and
        we must check the number of resources to correctly compute the
        number of nodes to deploy
        """

        all_removal_list = []
        relationships = []
        for node in self.tosca.nodetemplates:
            # Store relationships to check later
            for relationship, trgt in node.relationships.iteritems():
                src = node
                relationships.append((src, trgt, relationship))

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
                # At this moment we only support the network_type with values,
                # private and public
                net = Tosca._gen_network(node)
                radl.networks.append(net)
            else:
                if root_type == "tosca.nodes.Compute":
                    # Add the system RADL element
                    sys = Tosca._gen_system(node, self.tosca.nodetemplates)
                    # add networks using the simple method with the public_ip
                    # property
                    Tosca._add_node_nets(
                        node, radl, sys, self.tosca.nodetemplates)
                    radl.systems.append(sys)
                    # Add the deploy element for this system
                    min_instances, _, default_instances, count, removal_list = Tosca._get_scalable_properties(
                        node)
                    if count is not None:
                        # we must check the correct number of instances to
                        # deploy
                        num_instances = count
                    elif default_instances is not None:
                        num_instances = default_instances
                    elif min_instances is not None:
                        num_instances = min_instances
                    else:
                        num_instances = 1

                    num_instances = num_instances - \
                        self._get_num_instances(sys.name, inf_info)

                    # TODO: Think about to check the IDs of the VMs
                    if num_instances < 0:
                        all_removal_list.extend(removal_list[0:-num_instances])

                    if num_instances > 0:
                        dep = deploy(sys.name, num_instances)
                        radl.deploys.append(dep)
                    compute = node
                else:
                    # Select the host to host this element
                    compute = Tosca._find_host_compute(
                        node, self.tosca.nodetemplates)
                    if not compute:
                        Tosca.logger.warn(
                            "Node %s has not compute node to host in." % node.name)

                interfaces = Tosca._get_interfaces(node)
                interfaces.update(Tosca._get_relationships_interfaces(relationships, node))

                conf = self._gen_configure_from_interfaces(
                    radl, node, interfaces, compute)
                if conf:
                    level = Tosca._get_dependency_level(node)
                    radl.configures.append(conf)
                    if compute:
                        cont_intems.append(contextualize_item(
                            compute.name, conf.name, level))

        if cont_intems:
            radl.contextualize = contextualize(cont_intems)
        else:
            # If there are no configures, disable contextualization
            radl.contextualize = contextualize({})

        return all_removal_list, self._complete_radl_networks(radl)

    def _get_num_instances(self, sys_name, inf_info):
        """
        Get the current number of instances of system type name sys_name
        """
        current_num = 0

        if inf_info:
            vm_list = inf_info.get_vm_list_by_system_name()
            if sys_name in vm_list:
                current_num = len(vm_list[sys_name])

        return current_num

    @staticmethod
    def _format_outports(ports_dict):
        res = ""
        for port in ports_dict.values():
            # TODO: format ranges
            protocol = "tcp"
            if "protocol" in port:
                protocol = port["protocol"]
            if "source" in port:
                remote_port = port["source"]
            if "target" in port:
                local_port = port["target"]
            else:
                local_port = remote_port

            if res:
                res += ","
            res += "%s/%s-%s/%s" % (remote_port, protocol, local_port, protocol)

        return res

    @staticmethod
    def _add_node_nets(node, radl, system, nodetemplates):

        # Find associated Networks
        nets = Tosca._get_bind_networks(node, nodetemplates)
        if nets:
            # If there are network nodes, use it to define system network
            # properties
            for net_name, ip, dns_name, num in nets:
                system.setValue('net_interface.%d.connection' % num, net_name)
                # This is not a normative property
                if dns_name:
                    system.setValue('net_interface.%d.dns_name' %
                                    num, dns_name)
                if ip:
                    system.setValue('net_interface.%d.ip' % num, ip)
        else:
            public_ip = False

            # This is the solution using the public_ip property
            node_props = node.get_properties()
            if node_props and "public_ip" in node_props:
                public_ip = node_props["public_ip"].value

            # This is the solution using endpoints
            dns_name = None
            ports = {}
            node_caps = node.get_capabilities()
            if node_caps:
                if "endpoint" in node_caps:
                    cap_props = node_caps["endpoint"].get_properties()
                    if cap_props and "network_name" in cap_props:
                        if cap_props["network_name"].value == "PUBLIC":
                            public_ip = True
                    if cap_props and "dns_name" in cap_props:
                        dns_name = cap_props["dns_name"].value
                    if cap_props and "ports" in cap_props:
                        ports = cap_props["ports"].value

            # If the node needs a public IP
            if public_ip:
                public_nets = []
                for net in radl.networks:
                    if net.isPublic():
                        public_nets.append(net)

                if public_nets:
                    public_net = None
                    for net in public_nets:
                        num_net = system.getNumNetworkWithConnection(net.id)
                        if num_net is not None:
                            public_net = net
                            break

                    if not public_net:
                        # There are a public net but it has not been used in
                        # this VM
                        public_net = public_nets[0]
                        num_net = system.getNumNetworkIfaces()
                else:
                    # There no public net, create one
                    public_net = network.createNetwork("public_net", True)
                    radl.networks.append(public_net)
                    num_net = system.getNumNetworkIfaces()

                if ports:
                    public_net.setValue("outports", Tosca._format_outports(ports))

                system.setValue('net_interface.%d.connection' % num_net, public_net.id)

            # The private net is always added
            private_nets = []
            for net in radl.networks:
                if not net.isPublic():
                    private_nets.append(net)

            if private_nets:
                private_net = None
                for net in private_nets:
                    num_net = system.getNumNetworkWithConnection(net.id)
                    if num_net is not None:
                        private_net = net
                        break

                if not private_net:
                    # There are a public net but it has not been used in this
                    # VM
                    private_net = private_nets[0]
                    num_net = system.getNumNetworkIfaces()
            else:
                # There no public net, create one
                private_net = network.createNetwork("private_net", False)
                radl.networks.append(private_net)
                num_net = system.getNumNetworkIfaces()

            system.setValue('net_interface.' + str(num_net) +
                            '.connection', private_net.id)

            if dns_name:
                system.setValue('net_interface.0.dns_name', dns_name)

    @staticmethod
    def _get_scalable_properties(node):
        count = min_instances = max_instances = default_instances = None
        removal_list = []
        scalable = node.get_capability("scalable")
        if scalable:
            for prop in scalable.get_properties_objects():
                if prop.value is not None:
                    if prop.name == "count":
                        count = prop.value
                    elif prop.name == "max_instances":
                        max_instances = prop.value
                    elif prop.name == "min_instances":
                        min_instances = prop.value
                    elif prop.name == "default_instances":
                        default_instances = prop.value
                    elif prop.name == "removal_list":
                        removal_list = prop.value

        return min_instances, max_instances, default_instances, count, removal_list

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
            if rel_tpl.interfaces:
                if src.name == node.name:
                    for name in ['pre_configure_source', 'post_configure_source', 'add_source']:
                        for iface in rel_tpl.interfaces:
                            if iface.name == name:
                                res[name] = iface
                elif trgt.name == node.name:
                    for name in ['pre_configure_target', 'post_configure_target', 'add_target',
                                 'target_changed', 'remove_target']:
                        for iface in rel_tpl.interfaces:
                            if iface.name == name:
                                res[name] = iface
        return res

    def _get_artifact_full_uri(self, node, artifact_name):
        res = None
        artifacts = node.type_definition.get_value(
            'artifacts', node.entity_tpl, True)
        if artifacts:
            for name, artifact in artifacts.items():
                if name == artifact_name:
                    if isinstance(artifact, dict):
                        res = artifact['file']
                        if 'repository' in artifact:
                            repo = artifact['repository']
                            repositories = self.tosca.tpl.get('repositories')

                            if repositories:
                                for repo_name, repo_def in repositories.items():
                                    if repo_name == repo:
                                        repo_url = (
                                            (repo_def['url']).strip()).rstrip("//")
                                        res = repo_url + "/" + artifact['file']
                    else:
                        res = artifact

        return res

    def _get_implementation_url(self, node, implementation):
        res = implementation
        if implementation:
            artifact_url = self._get_artifact_full_uri(node, implementation)
            if artifact_url:
                res = artifact_url

        return res

    def _gen_configure_from_interfaces(self, radl, node, interfaces, compute):
        if not interfaces:
            return None

        variables = ""
        tasks = ""
        recipe_list = []
        remote_artifacts_path = "/tmp"
        # Take the interfaces in correct order
        for name in ['create', 'pre_configure_source', 'pre_configure_target', 'configure',
                     'post_configure_source', 'post_configure_target', 'start', 'add_target',
                     'add_source', 'target_changed', 'remove_target']:
            interface = interfaces.get(name, None)
            if interface:
                artifacts = []
                # Get the inputs
                env = {}
                if interface.inputs:
                    for param_name, param_value in interface.inputs.iteritems():
                        val = None

                        if self._is_artifact(param_value):
                            artifact_uri = self._get_artifact_uri(
                                param_value, node)
                            if artifact_uri:
                                val = remote_artifacts_path + "/" + \
                                    os.path.basename(artifact_uri)
                                artifacts.append(artifact_uri)
                        else:
                            val = self._final_function_result(
                                param_value, node)

                        if val:
                            env[param_name] = str(val)
                        else:
                            raise Exception("input value for %s in interface %s of node %s not valid" % (
                                param_name, name, node.name))

                name = node.name + "_" + interface.name

                # if there are artifacts to download
                if artifacts:
                    for artifact in artifacts:
                        tasks += "  - name: Download artifact " + artifact + "\n"
                        tasks += "    get_url: dest=" + remote_artifacts_path + "/" + \
                            os.path.basename(artifact) + \
                            " url='" + artifact + "'\n"

                implementation_url = uriparse(
                    self._get_implementation_url(node, interface.implementation))

                if implementation_url[0] in ['http', 'https', 'ftp']:
                    script_path = implementation_url[2]
                    try:
                        response = urllib.urlopen(interface.implementation)
                        script_content = response.read()
                        if response.code != 200:
                            raise Exception("")
                    except Exception, ex:
                        raise Exception("Error downloading the implementation script '%s': %s" % (
                            interface.implementation, str(ex)))
                else:
                    script_path = os.path.join(
                        Tosca.ARTIFACTS_PATH, interface.implementation)
                    if os.path.isfile(script_path):
                        f = open(script_path)
                        script_content = f.read()
                        f.close()
                    else:
                        try:
                            response = urllib.urlopen(
                                Tosca.ARTIFACTS_REMOTE_REPO + interface.implementation)
                            script_content = response.read()
                            if response.code != 200:
                                raise Exception("")
                        except Exception, ex:
                            raise Exception("Implementation file: '%s' is not located in the artifacts folder '%s' "
                                            "or in the artifacts remote url '%s'." % (interface.implementation,
                                                                                      Tosca.ARTIFACTS_PATH,
                                                                                      Tosca.ARTIFACTS_REMOTE_REPO))

                if script_path.endswith(".yaml") or script_path.endswith(".yml"):
                    if env:
                        for var_name, var_value in env.iteritems():
                            if var_value.startswith("|"):
                                variables += '    %s: %s ' % (
                                    var_name, var_value) + "\n"
                            else:
                                variables += '    %s: "%s" ' % (
                                    var_name, var_value) + "\n"
                        variables += "\n"

                    script_content = self._remove_recipe_header(script_content)
                    recipe_list.append(script_content)
                else:
                    recipe = "- tasks:\n"
                    recipe += "  - name: Copy contents of script of interface " + name + "\n"
                    recipe += "    copy: dest=/tmp/" + \
                        os.path.basename(script_path) + " content='" + \
                        script_content + "' mode=0755\n"

                    recipe += "  - name: " + name + "\n"
                    recipe += "    shell: /tmp/" + \
                        os.path.basename(script_path) + "\n"
                    if env:
                        recipe += "    environment:\n"
                        for var_name, var_value in env.iteritems():
                            recipe += "      %s: %s\n" % (var_name, var_value)

                    recipe_list.append(recipe)

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

    def _remove_recipe_header(self, script_content):
        """
        Removes the "hosts" and "connection" elements from the recipe
        to make it "RADL" compatible
        """

        try:
            yamlo = yaml.load(script_content)
            if not isinstance(yamlo, list):
                Tosca.logger.warn("Error parsing YAML: " +
                                  script_content + "\n.Do not remove header.")
                return script_content
        except Exception:
            Tosca.logger.exception(
                "Error parsing YAML: " + script_content + "\n.Do not remove header.")
            return script_content

        for elem in yamlo:
            if 'hosts' in elem:
                del elem['hosts']
            if 'connection' in elem:
                del elem['connection']

        return yaml.dump(yamlo, default_flow_style=False, explicit_start=True, width=256)

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

    def _get_artifact_uri(self, function, node):
        if isinstance(function, dict) and len(function) == 1:
            name = function["get_artifact"][1]
            return self._get_artifact_full_uri(node, name)

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

    def _get_intrinsic_value(self, func, node, inf_info):
        if isinstance(func, dict) and len(func) == 1:
            func_name = list(func.keys())[0]
            if func_name == "concat":
                items = func["concat"]
                res = ""
                for item in items:
                    if is_function(item):
                        res += str(self._final_function_result(item, node, inf_info))
                    else:
                        res += str(item)
                return res
            elif func_name == "token":
                items = func["token"]
                if len(items) == 3:
                    string_with_tokens = items[0]
                    string_of_token_chars = items[1]
                    substring_index = int(items[2])

                    if is_function(string_with_tokens):
                        string_with_tokens = str(self._final_function_result(string_with_tokens, node, inf_info))

                    parts = string_with_tokens.split(string_of_token_chars)
                    if len(parts) > substring_index:
                        return parts[substring_index]
                    else:
                        Tosca.logger.error(
                            "Incorrect substring_index in function token.")
                        return None
                else:
                    Tosca.logger.warn(
                        "Intrinsic function token must receive 3 parameters.")
                    return None
            else:
                Tosca.logger.warn(
                    "Intrinsic function %s not supported." % func_name)
                return None

    def _get_attribute_result(self, func, node, inf_info):
        """Get an attribute value of an entity defined in the service template

        Node template attributes values are set in runtime and therefore its the
        responsibility of the Tosca engine to implement the evaluation of
        get_attribute functions.

        Arguments:

        * Node template name | HOST.
        * Attribute name.
        * Index (optional)

        If the HOST keyword is passed as the node template name argument the
        function will search each node template along the HostedOn relationship
        chain until a node which contains the attribute is found.

        Examples:

        * { get_attribute: [ server, private_address ] }
        * { get_attribute: [ HOST, private_address ] }
        * { get_attribute: [ SELF, private_address ] }
        * { get_attribute: [ HOST, private_address, 0 ] }
        * { get_attribute: [ server, endpoint, credential, 0 ] }
        """
        node_name = func.args[0]
        capability_name = None
        attribute_name = func.args[1]

        index = None
        # Currently only support 2,3 or 4 parameters
        if len(func.args) == 3:
            try:
                index = int(func.args[2])
            except:
                Tosca.logger.exception("Error getting get_attribute index.")
                pass
        elif len(func.args) == 4:
            capability_name = func.args[1]
            attribute_name = func.args[2]
            try:
                index = int(func.args[3])
            except:
                Tosca.logger.exception("Error getting get_attribute index.")
                pass

        if node_name == "HOST":
            node = self._find_host_compute(node, self.tosca.nodetemplates)
        elif node_name != "SELF":
            node = None
            for n in self.tosca.nodetemplates:
                if n.name == node_name:
                    node = n
                    break
            if not node:
                Tosca.logger.error(
                    "Calling get_attribute function for non existing node: %s" % node_name)
                return None

        root_type = Tosca._get_root_parent_type(node).type

        if inf_info:
            vm_list = inf_info.get_vm_list_by_system_name()

            if node.name not in vm_list:
                Tosca.logger.warn(
                    "There are no VM associated with the name %s." % node.name)
                return None
            else:
                # As default assume that there will be only one VM per group
                vm = vm_list[node.name][0]
                if len(vm_list[node.name]) < index:
                    index = len(vm_list[node.name]) - 1

            if attribute_name == "tosca_id":
                return vm.id
            elif attribute_name == "tosca_name":
                return node.name
            elif attribute_name == "credential" and capability_name == "endpoint":
                if node.type == "tosca.nodes.indigo.Compute":
                    res = []
                    for vm in vm_list[node.name]:
                        user, password, _, private_key = vm.getCredentialValues()
                        val = {"user": user}
                        if password:
                            val["token"] = password
                            val["token_type"] = "password"
                        if private_key:
                            val["token_type"] = "private_key"
                            val["token"] = private_key
                        res.append(val)
                    if index is not None:
                        res = res[index]
                    return res
                else:
                    return vm.getPrivateIP()
            elif attribute_name == "private_address":
                if node.type == "tosca.nodes.indigo.Compute":
                    res = [vm.getPrivateIP() for vm in vm_list[node.name]]
                    if index is not None:
                        res = res[index]
                    return res
                else:
                    return vm.getPrivateIP()
            elif attribute_name == "public_address":
                if node.type == "tosca.nodes.indigo.Compute":
                    res = [vm.getPublicIP() for vm in vm_list[node.name]]
                    if index is not None:
                        res = res[index]
                    return res
                else:
                    return vm.getPublicIP()
            elif attribute_name == "ip_address":
                if root_type == "tosca.nodes.network.Port":
                    order = node.get_property_value('order')
                    return vm.getNumNetworkWithConnection(order)
                elif root_type == "tosca.capabilities.Endpoint":
                    if vm.getPublicIP():
                        return vm.getPublicIP()
                    else:
                        return vm.getPrivateIP()
                else:
                    Tosca.logger.warn("Attribute ip_address only supported in tosca.nodes.network.Port "
                                      "and tosca.capabilities.Endpoint nodes.")
                    return None
            else:
                Tosca.logger.warn("Attribute %s not supported." %
                                  attribute_name)
                return None
        else:
            if attribute_name == "tosca_id":
                if node_name in ["HOST", "SELF"]:
                    return "{{ IM_NODE_VMID }}"
                else:
                    return "{{ hostvars[groups['%s'][0]]['IM_NODE_VMID'] }}" % node.name
            elif attribute_name == "tosca_name":
                return node.name
            elif attribute_name == "private_address":
                if node.type == "tosca.nodes.indigo.Compute":
                    # This only works with Ansible 2.1, wait for it to be released
                    # return "{{ groups['%s']|map('extract', hostvars,'IM_NODE_PRIVATE_IP')|list }}" % node.name
                    if index is not None:
                        return "{{ hostvars[groups['%s'][%d]]['IM_NODE_PRIVATE_IP'] }}" % (node.name, index)
                    else:
                        return ("""|\n"""
                                """     {%% if '%s' in groups %%}"""
                                """{%% set comma = joiner(",") %%}"""
                                """[{%% for host in groups['%s'] %%}"""
                                """{{ comma() }}"{{ hostvars[host]['IM_NODE_PRIVATE_IP'] }}" """
                                """{%% endfor %%} ]"""
                                """{%% else %%}[]{%% endif %%}""" % (node.name, node.name))
                else:
                    if node_name in ["HOST", "SELF"]:
                        return "{{ IM_NODE_PRIVATE_IP }}"
                    else:
                        return "{{ hostvars[groups['%s'][0]]['IM_NODE_PRIVATE_IP'] }}" % node.name
            elif attribute_name == "public_address":
                if node.type == "tosca.nodes.indigo.Compute":
                    # This only works with Ansible 2.1, wait for it to be released
                    # return "{{ groups['%s']|map('extract', hostvars,'IM_NODE_PUBLIC_IP')|list }}" % node.name
                    if index is not None:
                        return "{{ hostvars[groups['%s'][%d]]['IM_NODE_PUBLIC_IP'] }}" % (node.name, index)
                    else:
                        return ("""|\n"""
                                """     {%% if '%s' in groups %%}"""
                                """{%% set comma = joiner(",") %%}"""
                                """[{%% for host in groups['%s'] %%}"""
                                """{{ comma() }}"{{ hostvars[host]['IM_NODE_PUBLIC_IP'] }}" """
                                """{%% endfor %%} ]"""
                                """{%% else %%}[]{%% endif %%}""" % (node.name, node.name))
                else:
                    if node_name in ["HOST", "SELF"]:
                        return "{{ IM_NODE_PUBLIC_IP }}"
                    else:
                        return "{{ hostvars[groups['%s'][0]]['IM_NODE_PUBLIC_IP'] }}" % node.name
            elif attribute_name == "ip_address":
                if root_type == "tosca.nodes.network.Port":
                    order = node.get_property_value('order')
                    return "{{ hostvars[groups['%s'][0]]['IM_NODE_NET_%s_IP'] }}" % (node.name, order)
                elif root_type == "tosca.capabilities.Endpoint":
                    # TODO: check this
                    if node_name in ["HOST", "SELF"]:
                        return "{{ IM_NODE_PUBLIC_IP }}"
                    else:
                        return "{{ hostvars[groups['%s'][0]]['IM_NODE_PUBLIC_IP'] }}" % node.name
                else:
                    Tosca.logger.warn("Attribute ip_address only supported in tosca.nodes.network.Port and "
                                      "tosca.capabilities.Endpoint nodes.")
                    return None
            else:
                Tosca.logger.warn("Attribute %s not supported." %
                                  attribute_name)
                return None

    def _final_function_result(self, func, node, inf_info=None):
        """
        Take a translator.toscalib.functions.Function and return the final result
        (in some cases the result of a function is another function)
        """
        if isinstance(func, dict):
            if is_function(func):
                func = get_function(self.tosca, node, func)

        while isinstance(func, Function):
            if isinstance(func, GetAttribute):
                func = self._get_attribute_result(func, node, inf_info)
            elif isinstance(func, Concat):
                func = self._get_intrinsic_value(
                    {"concat": func.args}, node, inf_info)
            elif isinstance(func, Token):
                func = self._get_intrinsic_value(
                    {"token": func.args}, node, inf_info)
            else:
                func = func.result()

        if isinstance(func, dict):
            if self._is_intrinsic(func):
                func = self._get_intrinsic_value(func, node, inf_info)

        if func is None:
            # TODO: resolve function values related with run-time values as IM
            # or ansible variables
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
                    if prop.value is not None:
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
                                filter_props[p_name] = (
                                    p_value.keys()[0], p_value.values()[0])
                            else:
                                filter_props[p_name] = ("equal", p_value)

        operator_map = {
            'equal': '==',
            'greater_than': '>',
            'greater_or_equal': '>=',
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

                    comparation = str_node_value + conv_operator + str_filter_value
                else:
                    if operator == "in_range":
                        minv = filter_value[0]
                        maxv = filter_value[1]
                        comparation = str_node_value + ">=" + \
                            str(minv) + " and " + \
                            str_node_value + "<=" + str(maxv)
                    elif operator == "valid_values":
                        comparation = str_node_value + \
                            " in " + str(filter_value)
                    else:
                        Tosca.logger.warn(
                            "Logical operator %s not supported." % operator)

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
    def _add_ansible_roles(node, nodetemplates, system):
        """
        Find all the roles to be applied to this node and
        add them to the system as ansible.modules.* in 'disk.0.applications'
        """
        roles = []
        for other_node in nodetemplates:
            root_type = Tosca._get_root_parent_type(other_node).type
            if root_type == "tosca.nodes.Compute":
                compute = other_node
            else:
                # Select the host to host this element
                compute = Tosca._find_host_compute(other_node, nodetemplates)

            if compute and compute.name == node.name:
                # Get the artifacts to see if there is a ansible galaxy role
                # and add it as an "ansible.modules" app requirement in RADL
                artifacts = other_node.type_definition.get_value(
                    'artifacts', other_node.entity_tpl, True)
                if artifacts:
                    for name, artifact in artifacts.items():
                        name
                        if ('type' in artifact and artifact['type'] == 'tosca.artifacts.AnsibleGalaxy.role' and
                                'file' in artifact and artifact['file']):
                            if artifact['file'] not in roles:
                                roles.append(artifact['file'])

        for role in roles:
            app_features = Features()
            app_features.addFeature(
                Feature('name', '=', 'ansible.modules.' + role))
            feature = Feature(
                'disk.0.applications', 'contains', app_features)
            system.addFeature(feature)

    @staticmethod
    def _gen_system(node, nodetemplates):
        """
        Take a node of type "Compute" and get the RADL.system to represent it
        """
        res = system(node.name)

        property_map = {
            'architecture': 'cpu.arch',
            'type': 'disk.0.os.name',
            'distribution': 'disk.0.os.flavour',
            'version': 'disk.0.os.version',
            'image': 'disk.0.image.url',
            'credential': 'disk.0.os.credentials',
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
                        elif prop.name == "version":
                            value = str(value)
                        elif prop.name == "image":
                            if value.find("://") == -1:
                                value = "docker://%s" % value
                        elif prop.name == "credential":
                            # Currently oly supports user/pass credentials
                            if 'token' in value and value['token']:
                                feature = Feature(
                                    "disk.0.os.credentials.password", "=", value['token'])
                                res.addFeature(feature)
                            if 'user' not in value or not value['user']:
                                raise Exception(
                                    "User must be specified in the image credentials.")
                            name = "disk.0.os.credentials.username"
                            value = value['user']

                        if isinstance(value, float) or isinstance(value, int):
                            operator = ">="
                        else:
                            operator = "="

                        feature = Feature(name, operator, value, unit)
                        res.addFeature(feature)

        # Find associated BlockStorages
        disks = Tosca._get_attached_disks(node, nodetemplates)

        for size, unit, location, device, num, fstype in disks:
            if size:
                res.setValue('disk.%d.size' % num, size, unit)
            if device:
                res.setValue('disk.%d.device' % num, device)
            if location:
                res.setValue('disk.%d.mount_path' % num, location)
                res.setValue('disk.%d.fstype' % num, fstype)

        Tosca._add_ansible_roles(node, nodetemplates, res)

        return res

    @staticmethod
    def _get_bind_networks(node, nodetemplates):
        nets = []

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
                    dns_name = port.get_property_value('dns_name')
                    nets.append((link, ip, dns_name, order))

        return nets

    @staticmethod
    def _get_attached_disks(node, nodetemplates):
        """
        Get the disks attached to a node
        """
        disks = []
        count = 1

        for rel, trgt in node.relationships.iteritems():
            src = node
            rel_tpl = Tosca._get_relationship_template(rel, src, trgt)
            # TODO: ver root_type
            if rel.type.endswith("AttachesTo"):
                rel_tpl.entity_tpl
                props = rel_tpl.get_properties_objects()

                size = None
                location = None
                # set a default device
                device = "hdb"

                for prop in props:
                    if prop.name == "location":
                        location = prop.value
                    elif prop.name == "device":
                        device = prop.value

                if trgt.type_definition.type == "tosca.nodes.BlockStorage":
                    size, unit = Tosca._get_size_and_unit(
                        trgt.get_property_value('size'))
                    disks.append((size, unit, location, device, count, "ext4"))
                    count += 1
                else:
                    Tosca.logger.debug(
                        "Attached item of type %s ignored." % trgt.type_definition.type)

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
            if node_type.parent_type is not None:
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
                    if name in ['create', 'configure', 'start', 'stop', 'delete']:
                        if name not in interfaces:
                            interfaces[name] = InterfacesDef(
                                node_type, 'Standard', name=name, value=elems)

            if node_type.parent_type is not None:
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
            Tosca.logger.exception(
                "Error parsing YAML: " + yaml1 + "\n Ignore it")

        yamlo2s = {}
        try:
            yamlo2s = yaml.load(yaml2)
            if not isinstance(yamlo2s, list) or any([not isinstance(d, dict) for d in yamlo2s]):
                yamlo2s = {}
        except Exception:
            Tosca.logger.exception(
                "Error parsing YAML: " + yaml2 + "\n Ignore it")

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

    def get_outputs(self, inf_info):
        """
        Get the outputs of the TOSCA document using the InfrastructureInfo
        object 'inf_info' to get the data of the VMs
        """
        res = {}

        for output in self.tosca.outputs:
            val = self._final_function_result(
                output.attrs.get(output.VALUE), None, inf_info)
            res[output.name] = val

        return res
