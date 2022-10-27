import os
import logging
import yaml
import copy
import operator
import requests
import json
import re
from toscaparser.nodetemplate import NodeTemplate

try:
    unicode("hola")
except NameError:
    unicode = str

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from toscaparser.tosca_template import ToscaTemplate
from toscaparser.elements.interfaces import InterfacesDef
from toscaparser.functions import Function, is_function, get_function, GetAttribute, Concat, Token
from toscaparser.elements.scalarunit import ScalarUnit_Size
from IM.ansible_utils import merge_recipes
from radl.radl import (system, deploy, network, Feature, Features, configure,
                       contextualize_item, RADL, contextualize, ansible)


class Tosca:
    """
    Class to translate a TOSCA document to an RADL object.

    TODO: What about CSAR files?

    """

    ARTIFACTS_PATH = os.path.dirname(os.path.realpath(__file__)) + "/tosca-types/artifacts"
    ARTIFACTS_REMOTE_REPO = "https://raw.githubusercontent.com/indigo-dc/tosca-types/master/artifacts/"

    logger = logging.getLogger('InfrastructureManager')

    def __init__(self, yaml_str, verify=True):
        Tosca.logger.debug("TOSCA: %s" % yaml_str)
        self.yaml = yaml.safe_load(yaml_str)
        if not verify:
            def verify_fake(tpl):
                return True
            ToscaTemplate.verify_template = verify_fake
        self.tosca = ToscaTemplate(yaml_dict_tpl=copy.deepcopy(self.yaml))

    def serialize(self):
        return yaml.safe_dump(self.yaml)

    @staticmethod
    def deserialize(str_data):
        # avoid validation in this case
        return Tosca(str_data, False)

    def _get_placement_property(self, sys_name, prop):
        """
        Get the specified property of the deployment based on policies
        """
        for policy in self.tosca.policies:
            if policy.type_definition.type in ["tosca.policies.Placement", "tosca.policies.indigo.Placement"]:
                node_list = []
                if policy.targets_type == "node_templates":
                    node_list = policy.targets_list
                elif policy.targets_type == "groups":
                    for group in policy.targets_list:
                        node_list.extend(group.member_nodes)

                for node in node_list:
                    if node.name == sys_name:
                        if policy.properties and prop in policy.properties:
                            Tosca.logger.debug("Set %s: %s to system: %s." % (prop,
                                                                              policy.properties[prop],
                                                                              sys_name))
                            return policy.properties[prop]
            else:
                Tosca.logger.warn("Policy %s not supported. Ignoring it." % policy.type_definition.type)

        return None

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
            for relationship, trgt in node.relationships.items():
                src = node
                relationships.append((src, trgt, relationship))

        radl = RADL()
        interfaces = {}
        cont_items = []

        # first process the networks as they are referred later
        for node in self.tosca.nodetemplates:
            root_type = Tosca._get_root_parent_type(node).type
            if root_type == "tosca.nodes.network.Network":
                net = self._gen_network(node)
                radl.networks.append(net)

        for node in self.tosca.nodetemplates:
            root_type = Tosca._get_root_parent_type(node).type

            if root_type in ["tosca.nodes.BlockStorage", "tosca.nodes.network.Port", "tosca.nodes.network.Network"]:
                # These elements are processed in other parts
                pass
            elif root_type == "tosca.nodes.im.AnsibleHost":
                # Only allow 1 ansible_host per document
                ansible_host = ansible("ansible_host", None)
                node_props = node.get_properties()
                if node_props and "host" in node_props:
                    host = self._final_function_result(node_props["host"].value, node)
                    if host:
                        ansible_host.setValue("host", host)
                if node_props and "credential" in node_props:
                    credentials = self._final_function_result(node_props["credential"].value, node)
                    if 'user' in credentials:
                        ansible_host.setValue("credentials.username", credentials['user'])
                    token_type, token = self._get_credential_values(credentials)
                    if token:
                        if token_type == "password":
                            ansible_host.setValue("credentials.password", token)
                        elif token_type == "private_key":
                            ansible_host.setValue("credentials.private_key", token)
                        else:
                            Tosca.logger.warn("Unknown tyoe of token %s. Ignoring." % token_type)
                radl.ansible_hosts = [ansible_host]
            elif root_type == "tosca.nodes.aisprint.FaaS.Function":
                oscar_host = self._find_host_compute(node, self.tosca.nodetemplates,
                                                     "tosca.nodes.SoftwareComponent")
                oscar_compute = self._find_host_compute(node, self.tosca.nodetemplates)
                # If the function has a host create a recipe
                if oscar_compute and oscar_host:
                    service_json = self._get_oscar_service_json(node)
                    dns_host = self._final_function_result(oscar_host.get_property_value('dns_host'), oscar_host)
                    if dns_host and dns_host.strip("'\""):
                        service_endpoint = "https://%s" % dns_host
                    else:
                        service_endpoint = "http://{{ IM_NODE_PUBLIC_IP }}"
                    service_password = self._final_function_result(oscar_host.get_property_value('password'),
                                                                   oscar_host)

                    recipe = '  - tasks:\n'
                    recipe += '    - include_tasks: utils/tasks/oscar_function.yml\n'
                    recipe += '      vars:\n'
                    recipe += '        oscar_endpoint: "%s"\n' % service_endpoint
                    recipe += '        oscar_username: "oscar"\n'
                    recipe += '        oscar_password: "%s"\n' % service_password
                    recipe += "        oscar_service_json: '%s'\n" % service_json

                    conf = configure("oscar_%s" % node.name, recipe)
                    radl.configures.append(conf)
                    level = Tosca._get_dependency_level(node)
                    cont_items.append(contextualize_item(oscar_compute.name, conf.name, level))
                else:
                    # if not create a system
                    oscar_sys = self._gen_oscar_system(node)
                    radl.systems.append(oscar_sys)
                    conf = configure(node.name, None)
                    radl.configures.append(conf)
                    level = Tosca._get_dependency_level(node)
                    cont_items.append(contextualize_item(node.name, conf.name, level))
                    cloud_id = self._get_placement_property(oscar_sys.name, "cloud_id")
                    dep = deploy(oscar_sys.name, 1, cloud_id)
                    radl.deploys.append(dep)
            else:
                if root_type == "tosca.nodes.Compute":
                    # Add the system RADL element
                    sys = self._gen_system(node, self.tosca.nodetemplates)
                    # add networks using the simple method with the public_ip
                    # property
                    self._add_node_nets(node, radl, sys, self.tosca.nodetemplates)
                    radl.systems.append(sys)
                    # Add the deploy element for this system
                    min_instances, _, default_instances, count, removal_list = self._get_scalable_properties(
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

                    current_num_instances = self._get_num_instances(sys.name, inf_info)
                    num_instances = num_instances - current_num_instances
                    Tosca.logger.debug("User requested %d instances of type %s and there"
                                       " are %s" % (num_instances, sys.name, current_num_instances))

                    if num_instances < 0:
                        if removal_list:
                            # TODO: Think about to check the IDs of the VMs
                            all_removal_list.extend([int(vm_id) for vm_id in removal_list[0:-num_instances]])
                        # if no removal list is set, delete the oldest VMs of this type
                        elif inf_info:
                            vm_list = inf_info.get_vm_list_by_system_name()
                            if sys.name in vm_list:
                                vms = sorted(vm_list[sys.name], key=lambda vm: vm.creation_date)
                                all_removal_list.extend([vm.im_id for vm in vms[0:-num_instances]])
                        Tosca.logger.debug("List of VMs to delete: %s" % all_removal_list)

                    if num_instances > 0:
                        cloud_id = self._get_placement_property(sys.name, "cloud_id")
                        dep = deploy(sys.name, num_instances, cloud_id)
                        radl.deploys.append(dep)
                    compute = node
                else:
                    # Select the host to host this element
                    compute = self._find_host_compute(node, self.tosca.nodetemplates)
                    if not compute:
                        Tosca.logger.warn(
                            "Node %s has not compute node to host in." % node.name)

                interfaces = Tosca._get_interfaces(node)
                interfaces.update(Tosca._get_relationships_interfaces(relationships, node))

                conf = self._gen_configure_from_interfaces(node, compute, interfaces)
                if conf:
                    level = Tosca._get_dependency_level(node)
                    radl.configures.append(conf)
                    if compute:
                        cont_items.append(contextualize_item(compute.name, conf.name, level))

        if cont_items:
            radl.contextualize = contextualize(cont_items)
        else:
            # If there are no configures, disable contextualization
            radl.contextualize = contextualize({})

        self._order_deploys(radl)

        self._check_private_networks(radl, inf_info)

        return all_removal_list, self._complete_radl_networks(radl)

    @staticmethod
    def _check_private_networks(radl, inf_info):
        """
        Check private networks to assure to create different nets
        for different cloud providers
        """
        if not radl.networks:
            return

        priv_net_cloud_map = {}

        # in case of an AddResource
        # first process already deployed VMs
        systems = [(None, []), (radl, [])]
        if inf_info:
            systems[0] = (inf_info.radl, [])
            for elem in inf_info.get_vm_list_by_system_name().items():
                systems[0][1].append(elem[1][-1].info.systems[0])

        # make that deployed nodes are checked first
        to_deploy = [d.id for d in radl.deploys]
        systems[1][1].extend([s for s in radl.systems if s.name in to_deploy])

        for r1, s1 in systems:
            for s in s1:
                image = s.getValue("disk.0.image.url")

                if image:
                    url = urlparse(image)
                    protocol = url[0]
                    src_host = url[1].split(':')[0]
                    for net_id in s.getNetworkIDs():
                        net = r1.get_network_by_id(net_id)
                        if not net.isPublic():
                            if net_id in priv_net_cloud_map:
                                if priv_net_cloud_map[net_id] != "%s://%s" % (protocol, src_host):
                                    if "%s://%s" % (protocol, src_host) in list(priv_net_cloud_map.values()):
                                        for key, value in priv_net_cloud_map.items():
                                            if value == "%s://%s" % (protocol, src_host):
                                                new_net_id = key
                                                break
                                    else:
                                        # This net appears in two cloud, create another one
                                        new_net = network.createNetwork("private.%s" % src_host, False)
                                        # Move also the net params to the new one
                                        for item in ["provider_id", "cidr", "create", "router", "outports"]:
                                            if net.getValue(item):
                                                new_net.setValue(item, net.getValue(item))
                                                net.delValue(item)
                                        radl.networks.append(new_net)
                                        new_net_id = new_net.id
                                        # and replace the connection id in the system
                                    i = 0
                                    while s.getValue("net_interface.%d.connection" % i):
                                        if s.getValue("net_interface.%d.connection" % i) == net_id:
                                            s.setValue("net_interface.%d.connection" % i, new_net_id)
                                        i += 1

                                    priv_net_cloud_map[new_net_id] = "%s://%s" % (protocol, src_host)
                            else:
                                priv_net_cloud_map[net_id] = "%s://%s" % (protocol, src_host)

        return

    @staticmethod
    def _order_deploys(radl):
        """
        Order the RADL deploys to assure VMs with Public IPs a set a the beginning
        (to avoid problems with cluster configuration)
        """
        pub = []
        priv = []
        for d in radl.deploys:
            if radl.hasPublicNet(d.id):
                pub.append(d)
            else:
                priv.append(d)

        # This is patch, we need an actual solution for that
        wn = []
        fe = []
        for d in pub:
            if "wn" in d.id:
                wn.append(d)
            else:
                fe.append(d)

        radl.deploys = fe + wn + priv

    @staticmethod
    def _get_num_instances(sys_name, inf_info):
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
            protocol = "tcp"
            source_range = None
            remote_cidr = ""
            if "protocol" in port:
                protocol = port["protocol"]
            if "remote_cidr" in port:
                remote_cidr = "%s-" % port["remote_cidr"]
            if "source_range" in port:
                source_range = port["source_range"]
            else:
                if "source" in port:
                    remote_port = port["source"]
                else:
                    raise Exception("source port must be specified in PortSpec type.")
                if "target" in port:
                    local_port = port["target"]
                else:
                    local_port = remote_port

            # In case of source_range do not use port mapping only direct ports
            if source_range:
                if res:
                    res += ","
                res += "%s%s:%s/%s" % (remote_cidr, source_range[0], source_range[1], protocol)
            else:
                if res:
                    res += ","
                res += "%s%s/%s-%s/%s" % (remote_cidr, remote_port, protocol, local_port, protocol)

        return res

    def _get_node_endpoints(self, node, nodetemplates):
        """ Get all endpoint associated with a node """
        endpoints = []

        # First add its own endpoints
        node_caps = node.get_capabilities()
        if node_caps:
            if "endpoint" in node_caps and node_caps["endpoint"]:
                endpoints.append(node_caps["endpoint"])

        # Now other hosted nodes ones
        for other_node in nodetemplates:
            root_type = Tosca._get_root_parent_type(other_node).type
            compute = None
            if root_type != "tosca.nodes.Compute":
                # Select the host to host this element
                compute = self._find_host_compute(other_node, nodetemplates)

            if compute and compute.name == node.name:
                node_caps = other_node.get_capabilities()
                for cap in node_caps.values():
                    root_type = Tosca._get_root_parent_type(cap).type
                    if root_type == "tosca.capabilities.Endpoint":
                        endpoints.append(cap)

        return endpoints

    def _add_node_nets(self, node, radl, system, nodetemplates):
        public_ip = False
        private_ip = True

        # This is the solution using the deprecated public_ip property
        node_props = node.get_properties()
        if node_props and "public_ip" in node_props:
            public_ip = self._final_function_result(node_props["public_ip"].value, node)

        # This is the solution using endpoints
        net_provider_id = None
        dns_name = None
        additional_dns_names = []
        additional_ip = None
        ports = {}
        endpoints = self._get_node_endpoints(node, nodetemplates)

        for endpoint in endpoints:
            cap_props = endpoint.get_properties()
            if cap_props and "network_name" in cap_props:
                network_name = str(self._final_function_result(cap_props["network_name"].value, node))
                pool_name = None
                parts = network_name.split(",")
                if len(parts) > 1:
                    # This is for the special case of OST with net name and pool name
                    network_name = parts[0].strip()
                    pool_name = parts[1].strip()
                    public_ip = True

                if network_name == "PUBLIC":
                    public_ip = True
                # In this case the user is specifying the provider_id
                elif network_name.endswith(".PUBLIC"):
                    public_ip = True
                    parts = network_name.split(".")
                    net_provider_id = ".".join(parts[:-1])
                elif network_name.endswith(".PRIVATE"):
                    parts = network_name.split(".")
                    net_provider_id = ".".join(parts[:-1])
                elif network_name != "PRIVATE":
                    # assume that is a private one
                    net_provider_id = network_name
            if cap_props and "dns_name" in cap_props:
                dns_name = self._final_function_result(cap_props["dns_name"].value, node)
            if cap_props and "additional_dns_names" in cap_props:
                additional_dns_names = self._final_function_result(cap_props["additional_dns_names"].value, node)
            if cap_props and "private_ip" in cap_props:
                private_ip = self._final_function_result(cap_props["private_ip"].value, node)
            if cap_props and "ports" in cap_props:
                node_ports = self._final_function_result(cap_props["ports"].value, node)
                if node_ports:
                    for p in node_ports.values():
                        ports[id(p)] = p
            if cap_props and "port" in cap_props:
                port = self._final_function_result(cap_props["port"].value, node)
                protocol = "tcp"
                if "protocol" in cap_props:
                    protocol = self._final_function_result(cap_props["protocol"].value, node)
                ports["im-%s-%s" % (protocol, port)] = {"protocol": protocol, "source": port}
                if "remote_cidr" in cap_props:
                    remote_cidr = self._final_function_result(cap_props["remote_cidr"].value, node)
                    if remote_cidr:
                        ports["im-%s-%s" % (protocol, port)]['remote_cidr'] = remote_cidr
            if cap_props and "additional_ip" in cap_props:
                additional_ip = self._final_function_result(cap_props["additional_ip"].value, node)

        if dns_name:
            system.setValue('net_interface.0.dns_name', dns_name)
        if additional_ip:
            system.setValue('net_interface.0.additional_ip', additional_ip)

        # Find associated Networks
        nets = self._get_bind_networks(node, nodetemplates)
        if nets:
            # If there are network nodes, use it to define system network
            # properties
            port_net = None
            for net_name, ip, dns_name, additional_dns_names, num, additional_ip in nets:
                net = radl.get_network_by_id(net_name)
                if not net:
                    raise Exception("Node %s with a port binded to a non existing network: %s." % (node.name,
                                                                                                   net_name))

                system.setValue('net_interface.%d.connection' % num, net_name)
                if ip:
                    system.setValue('net_interface.%d.ip' % num, ip)
                # These are not normative properties
                if dns_name:
                    system.setValue('net_interface.%d.dns_name' % num, dns_name)
                if additional_ip:
                    system.setValue('net_interface.%d.additional_ip' % num, additional_ip)
                if additional_dns_names:
                    system.setValue('net_interface.%d.additional_dns_names' % num, additional_dns_names)

                if net.isPublic():
                    port_net = net
                elif port_net is None:
                    port_net = net

            if port_net and ports:
                outports = Tosca._format_outports(ports)
                if port_net.getValue("outports"):
                    outports = "%s,%s" % (port_net.getValue("outports"), outports)
                port_net.setValue("outports", outports)
        else:
            private_net = None
            # The private net is always added
            if not public_ip or private_ip:
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

                if not public_ip and ports:
                    outports = Tosca._format_outports(ports)
                    if private_net.getValue("outports"):
                        outports = "%s,%s" % (private_net.getValue("outports"), outports)
                    private_net.setValue("outports", outports)

                system.setValue('net_interface.' + str(num_net) + '.connection', private_net.id)

            public_net = None
            # If the node needs a public IP
            if public_ip:
                # Always create a public IP per VM
                # to enable to specify different outports
                net_name = "public_net"
                i = 1
                while radl.get_network_by_id(net_name) is not None:
                    net_name = "public_net_%d" % i
                    i += 1
                public_net = network.createNetwork(net_name, True)
                radl.networks.append(public_net)
                num_net = system.getNumNetworkIfaces()

                if ports:
                    outports = Tosca._format_outports(ports)
                    if public_net.getValue("outports"):
                        outports = "%s,%s" % (public_net.getValue("outports"), outports)
                    public_net.setValue("outports", outports)

                system.setValue('net_interface.%d.connection' % num_net, public_net.id)
                # allways add the additional_dns_names in the public interface
                if additional_dns_names:
                    system.setValue('net_interface.%d.additional_dns_names' % num_net, additional_dns_names)

            if net_provider_id:
                if private_net:
                    # There are a private IP, net the provider_id to the priv net
                    private_net.setValue("provider_id", net_provider_id)
                else:
                    # There are no a private IP, net the provider_id to the priv net
                    if not public_net:
                        Tosca.logger.warn("Node %s does not require any IP!!" % node.name)

                if public_net:
                    if pool_name:
                        public_net.setValue("provider_id", pool_name)
                    elif not private_net:
                        public_net.setValue("provider_id", net_provider_id)

    def _get_scalable_properties(self, node):
        count = min_instances = max_instances = default_instances = None
        removal_list = []
        scalable = node.get_capability("scalable")
        if scalable:
            for prop in scalable.get_properties_objects():
                if prop.value is not None:
                    final_value = self._final_function_result(prop.value, node)
                    if prop.name == "count":
                        count = final_value
                    elif prop.name == "max_instances":
                        max_instances = final_value
                    elif prop.name == "min_instances":
                        min_instances = final_value
                    elif prop.name == "default_instances":
                        default_instances = final_value
                    elif prop.name == "removal_list":
                        removal_list = final_value

        return min_instances, max_instances, default_instances, count, removal_list

    @staticmethod
    def _get_relationship_template(rel, src, trgt):
        rel_tpls = src.get_relationship_template()
        rel_tpls.extend(trgt.get_relationship_template())
        for rel_tpl in rel_tpls:
            if rel_tpl.source.name == src.name and rel_tpl.target.name == trgt.name:
                if rel.type == rel_tpl.type:
                    return rel_tpl
                else:
                    root_type = Tosca._get_root_parent_type(rel_tpl).type
                    if root_type == rel.type:
                        return rel_tpl
        return None

    @staticmethod
    def _get_relationships_interfaces(relationships, node):
        res = {}
        for src, trgt, rel in relationships:
            rel_tpl = Tosca._get_relationship_template(rel, src, trgt)

            rel_tlp_def_interfaces = {}
            for inteface_name in ['Standard', 'Configure']:
                if rel_tpl.type_definition.interfaces and inteface_name in rel_tpl.type_definition.interfaces:
                    rel_tlp_def_interfaces = rel_tpl.type_definition.interfaces[inteface_name]

            if src.name == node.name:
                # Also add the configure of the target node of the relation
                trgt_interfaces = Tosca._get_interfaces(trgt, steps=['pre_configure_source', 'post_configure_source'])
                for name in ['pre_configure_source', 'post_configure_source', 'add_source']:
                    if trgt_interfaces and name in trgt_interfaces:
                        res[name] = trgt_interfaces[name]
                    if rel_tpl.interfaces:
                        for iface in rel_tpl.interfaces:
                            if iface.name == name:
                                res[name] = iface
                    if rel_tlp_def_interfaces and name in rel_tlp_def_interfaces:
                        res[name] = InterfacesDef(rel_tpl.type_definition, 'Standard',
                                                  name=name, value=rel_tlp_def_interfaces[name],
                                                  node_template=rel_tpl)

            elif trgt.name == node.name:
                src_interfaces = Tosca._get_interfaces(src, steps=['pre_configure_target', 'post_configure_target'])
                for name in ['pre_configure_target', 'post_configure_target', 'add_target',
                             'target_changed', 'remove_target']:
                    if src_interfaces and name in src_interfaces:
                        res[name] = src_interfaces[name]
                    if rel_tpl.interfaces:
                        for iface in rel_tpl.interfaces:
                            if iface.name == name:
                                res[name] = iface
                    if rel_tlp_def_interfaces and name in rel_tlp_def_interfaces:
                        res[name] = InterfacesDef(rel_tpl.type_definition, 'Standard',
                                                  name=name, value=rel_tlp_def_interfaces[name],
                                                  node_template=rel_tpl)

        return res

    def _get_artifact_full_uri(self, node, artifact_name):
        artifact_def = artifact_name
        artifacts = self._get_node_artifacts(node)
        for name, artifact in artifacts.items():
            if name == artifact_name:
                artifact_def = artifact

        res = None
        if isinstance(artifact_def, dict):
            res = artifact_def['file']
            if 'repository' in artifact_def:
                repo = artifact_def['repository']
                repositories = self.tosca.tpl.get('repositories')

                if repositories:
                    for repo_name, repo_def in repositories.items():
                        if repo_name == repo:
                            repo_url = ((repo_def['url']).strip()).rstrip("//")
                            res = repo_url + "/" + artifact_def['file']
        else:
            res = artifact_def

        return res

    def _get_implementation_url(self, node, implementation):
        res = implementation
        if implementation:
            artifact_url = self._get_artifact_full_uri(node, implementation)
            if artifact_url:
                res = artifact_url

        return res

    def _gen_configure_from_interfaces(self, node, compute, interfaces):
        if not interfaces:
            return None

        variables = ""
        tasks = ""
        recipe_list = []
        remote_artifacts_path = "/tmp"
        # Take the interfaces in correct order
        for name in ['create', 'pre_configure_source', 'pre_configure_target', 'configure_rel',
                     'configure', 'post_configure_source', 'post_configure_target', 'start',
                     'add_target', 'add_source', 'target_changed', 'remove_target']:
            interface = interfaces.get(name, None)
            if interface:
                if interface.node_template:
                    orig_node = node
                    node = interface.node_template
                artifacts = []
                # Get the inputs
                env = {}
                if interface.inputs:
                    for param_name, param_value in interface.inputs.items():
                        val = None

                        if self._is_artifact(param_value):
                            artifact_uri = self._get_artifact_uri(param_value, node)
                            if artifact_uri:
                                val = remote_artifacts_path + "/" + os.path.basename(artifact_uri)
                                artifacts.append(artifact_uri)
                        else:
                            val = self._final_function_result(param_value, node)

                        if val is not None:
                            env[param_name] = val
                        else:
                            raise Exception("input value for %s in interface %s of node %s not valid" % (
                                param_name, name, node.name))

                name = node.name + "_" + interface.name

                # if there are artifacts to download
                if artifacts:
                    for artifact in artifacts:
                        tasks += "  - name: Download artifact " + artifact + "\n"
                        tasks += "    get_url: dest=" + remote_artifacts_path + "/" + \
                            os.path.basename(artifact) + " url='" + artifact + "'\n"

                implementation = self._get_implementation_url(node, interface.implementation)
                implementation_url = urlparse(implementation)

                if implementation_url[0] in ['http', 'https', 'ftp']:
                    script_path = implementation_url[2]
                    try:
                        resp = requests.get(implementation)
                        script_content = resp.text
                        if resp.status_code != 200:
                            raise Exception(resp.reason + "\n" + resp.text)
                    except Exception as ex:
                        raise Exception("Error downloading the implementation script '%s': %s" % (
                            implementation, str(ex)))
                else:
                    if implementation_url[0] == 'file':
                        script_path = implementation_url[2]
                    else:
                        script_path = os.path.join(Tosca.ARTIFACTS_PATH, implementation)
                    if os.path.isfile(script_path):
                        f = open(script_path)
                        script_content = f.read()
                        f.close()
                    else:
                        try:
                            resp = requests.get(Tosca.ARTIFACTS_REMOTE_REPO + implementation)
                            script_content = resp.text
                            if resp.status_code != 200:
                                raise Exception(resp.reason + "\n" + resp.text)
                        except Exception:
                            raise Exception("Implementation file: '%s' is not located in the artifacts folder '%s' "
                                            "or in the artifacts remote url '%s'." % (implementation,
                                                                                      Tosca.ARTIFACTS_PATH,
                                                                                      Tosca.ARTIFACTS_REMOTE_REPO))

                if script_path.endswith(".yaml") or script_path.endswith(".yml"):
                    if env:
                        for var_name, var_value in env.items():
                            if isinstance(var_value, str) and not var_value.startswith("|"):
                                var_value = '"%s"' % var_value
                            else:
                                var_value = str(var_value)
                            var_value = var_value.replace("\n", "\\n")
                            variables += '    %s: %s ' % (var_name, var_value) + "\n"
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
                        for var_name, var_value in env.items():
                            recipe += "      %s: %s\n" % (var_name, var_value)

                    recipe_list.append(recipe)

        if tasks or recipe_list:
            name = node.name
            if node.name != compute.name:
                name = name + "_" + compute.name
            if node.name != orig_node.name:
                name = name + "_" + orig_node.name
            name = name + "_conf"
            if variables:
                recipes = "---\n- vars:\n" + variables + "\n"
                recipes += "  "
            else:
                recipes = "- "

            if tasks:
                recipes += "tasks:\n" + tasks + "\n"

            # Merge the main recipe with the other yaml files
            for recipe in recipe_list:
                recipes = merge_recipes(recipes, recipe)

            return configure(name, recipes)
        else:
            return None

    @staticmethod
    def _remove_recipe_header(script_content):
        """
        Removes the "hosts" and "connection" elements from the recipe
        to make it "RADL" compatible
        """

        try:
            yamlo = yaml.safe_load(script_content)
            if not isinstance(yamlo, list):
                Tosca.logger.warn("Error parsing YAML: " + script_content + "\n.Do not remove header.")
                return script_content
        except Exception:
            Tosca.logger.exception("Error parsing YAML: " + script_content + "\n.Do not remove header.")
            return script_content

        for elem in yamlo:
            if 'hosts' in elem:
                del elem['hosts']
            if 'connection' in elem:
                del elem['connection']

        return yaml.safe_dump(yamlo, default_flow_style=False, explicit_start=True, width=256)

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

    def _get_default_attribute(self, node, attribute_name, inf_info=None):
        """Get the default value set to an attribute."""
        try:
            node_type = node.type_definition
        except AttributeError:
            node_type = node.definition

        attributes_def = node_type.get_attributes_def()
        if attribute_name in attributes_def:
            attr_schema = attributes_def[attribute_name].schema
            if 'default' in attr_schema:
                return self._final_function_result(attr_schema['default'], node, inf_info)

        return None

    def _get_ansible_output(self, cont_out, attribute_params):
        """
        Get values from ansible output.

        Accepted parameters: ctxt_task_name, ansible_task_name
        Each ansible task has the following attributes:
        - state: str with the ansible state returned
        - output: str only available in some tasks (as debug ones)
        """
        if not cont_out:
            return None

        ctxt_task = {}
        for task in cont_out.split("Launch task: ")[1:]:
            task_name = task[:task.find("\n")]
            ctxt_task[task_name] = {'tasks': {}}
            ansible_task_name = None

            for num, atask in enumerate(task.split("\nTASK [")[1:]):
                ansible_task_name = atask[:atask.find("] **")]
                if ansible_task_name in ctxt_task[task_name]:
                    ansible_task_name = "%s_%d" % (ansible_task_name, num)
                ctxt_task[task_name]['tasks'][ansible_task_name] = {'state': None, 'output': None}

                state_search = re.search("\n([a-z]+): \[.*\]", atask)
                if state_search:
                    ctxt_task[task_name]['tasks'][ansible_task_name]['state'] = state_search.group(1)
                output_search = re.search("\n[a-z]+: \[.*\] => \{", atask)
                if output_search:
                    output_endpos = atask.find("}\n", output_search.end(0))
                    output = atask[output_search.end(0) - 1:output_endpos + 1]
                    try:
                        json_out = json.loads(output)
                        if "var" in json_out:
                            json_out = json_out["var"]
                        if len(json_out) == 1:
                            output = json[list(json_out.keys())[0]]
                        if "msg" in json_out:
                            output = json_out["msg"]
                        ctxt_task[task_name]['tasks'][ansible_task_name]['output'] = output
                    except Exception:
                        ctxt_task[task_name]['tasks'][ansible_task_name]['output'] = output

        return self._get_object_values(ctxt_task, attribute_params)

    @staticmethod
    def _get_object_values(value, attribute_params):
        """Get values from dict."""
        res = value
        for param in attribute_params:
            if param in res:
                res = res[param]
            else:
                Tosca.logger.error("Invalid map index: %s in value: %s" % (param, value))
                return None
        return res

    def _get_attribute_result(self, func, node, inf_info):
        """Get an attribute value of an entity defined in the service template

        Node template attributes values are set in runtime and therefore its the
        responsibility of the Tosca engine to implement the evaluation of
        get_attribute functions.

        Grammar:
        get_attribute: [ <modelable_entity_name>, <optional_req_or_cap_name>, <attribute_name>,
                         <nested_attribute_name_or_index_1>, ..., <nested_attribute_name_or_index_n> ]

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
        if len(func.args) < 2:
            Tosca.logger.error("Calling get_attribute function. Min 2 parameters.")
            return None
        node_name = func.args[0]

        # Get node
        if node_name == "HOST":
            node = self._find_host_compute(node, self.tosca.nodetemplates)
        elif node_name == "SOURCE":
            node = func.context.source
        elif node_name == "TARGET":
            node = func.context.target
        elif node_name != "SELF":
            node = None
            for n in self.tosca.nodetemplates:
                if n.name == node_name:
                    node = n
                    break

        if not node:
            Tosca.logger.error("Calling get_attribute function for non existing node: %s" % node_name)
            return None

        #  if capability_name refers a requirement, try to get the referred node
        capability_name = func.args[1]
        args_cont = 1
        cap_or_req_names = list(node.get_capabilities().keys())
        cap_or_req_names.extend([name for r in node.requirements for name, _ in r.items()])
        if capability_name in cap_or_req_names:
            args_cont += 1
            if len(func.args) < 3:
                Tosca.logger.error("Calling get_attribute function. Min 3 parameters with cap or req name.")
                return None
        else:
            capability_name = None
            Tosca.logger.debug("%s is not a cap or req on node %s. It must be an attribute." % (capability_name,
                                                                                                node.name))

        # Find capability in node template's requirements
        if capability_name:
            for r in node.requirements:
                for req, name in r.items():
                    if req == capability_name:
                        node = func._find_node_template(name)

        attribute_name = func.args[args_cont]
        attribute_params = func.args[args_cont + 1:]

        # Index is the value of the first int parameter
        index = None
        if attribute_params:
            try:
                index = int(attribute_params[0])
                attribute_params.pop(0)
            except Exception:
                Tosca.logger.debug("First parameter is not an index.")

        attribute_default = self._get_default_attribute(node, attribute_name, inf_info)
        if attribute_default:
            return attribute_default

        root_type = Tosca._get_root_parent_type(node).type

        host_node = self._find_host_compute(node, self.tosca.nodetemplates)
        if root_type == "tosca.nodes.aisprint.FaaS.Function" and host_node is None:
            # in case of FaaS functions without host, the node is the host
            host_node = node

        if inf_info:
            vm_list = inf_info.get_vm_list_by_system_name()

            if host_node.name not in vm_list:
                Tosca.logger.warn("There are no VM associated with the name %s." % host_node.name)
                return None
            else:
                # As default assume that there will be only one VM per group
                vm = vm_list[host_node.name][0]
                if index is not None and len(vm_list[host_node.name]) < index:
                    index = len(vm_list[host_node.name]) - 1

            if attribute_name == "tosca_id":
                return vm.id
            elif attribute_name == "tosca_name":
                return node.name
            elif attribute_name == "ctxt_log":
                if node.type == "tosca.nodes.indigo.Compute":
                    return vm.cont_out
                else:
                    Tosca.logger.warn("Attribute ctxt_log only supported"
                                      " in tosca.nodes.indigo.Compute nodes.")
                    return None
            elif attribute_name == "ansible_output":
                if node.type == "tosca.nodes.indigo.Compute":
                    return self._get_ansible_output(vm.cont_out, attribute_params)
                else:
                    Tosca.logger.warn("Attribute ansible_output only supported"
                                      " in tosca.nodes.indigo.Compute nodes.")
                    return None
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
                        res.append(self._get_object_values(val, attribute_params))
                    if index is not None:
                        res = res[index]
                    return res
                else:
                    Tosca.logger.warn("Attribute credential of capability endpoint only"
                                      " supported in tosca.nodes.indigo.Compute nodes.")
                    return None
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
                    order = self._final_function_result(node.get_property_value('order'), node)
                    return vm.getNumNetworkWithConnection(order)
                else:
                    if vm.getPublicIP():
                        return vm.getPublicIP()
                    else:
                        return vm.getPrivateIP()
            elif attribute_name == "endpoint":
                if root_type == "tosca.nodes.aisprint.FaaS.Function":
                    oscar_host = self._find_host_compute(node, self.tosca.nodetemplates,
                                                         "tosca.nodes.SoftwareComponent")
                    if host_node != node and oscar_host:
                        # OSCAR function deployed in a deployed VM
                        dns_host = self._final_function_result(oscar_host.get_property_value('dns_host'), oscar_host)
                        if dns_host and dns_host.strip("'\""):
                            return "https://%s" % dns_host

                        if vm.getPublicIP():
                            return "http://%s" % vm.getPublicIP()
                        else:
                            return "http://%s" % vm.getPrivateIP()
                    else:
                        # OSCAR function deployed in a pre-deployed cluster or not dns_host set
                        return vm.getCloudConnector().cloud.get_url()

                Tosca.logger.warn("Attribute endpoint only supported in tosca.nodes.aisprint.FaaS.Function")
                return None
            elif attribute_name == "credential":
                if root_type == "tosca.nodes.aisprint.FaaS.Function":
                    oscar_host = self._find_host_compute(node, self.tosca.nodetemplates,
                                                         "tosca.nodes.SoftwareComponent")
                    if host_node != node and oscar_host:
                        # OSCAR function deployed in a deployed VM
                        oscar_pass = self._final_function_result(oscar_host.get_property_value('password'), oscar_host)
                        if oscar_pass and oscar_pass.strip("'\""):
                            return self._get_object_values({"user": "oscar",
                                                            "token_type": "password",
                                                            "token": oscar_pass},
                                                           attribute_params)

                        Tosca.logger.warn("No password defined in tosca.nodes.indigo.OSCAR host node")
                        return None
                    else:
                        # OSCAR function deployed in a pre-deployed cluster or not dns_host set
                        if vm.getCloudConnector().auth:
                            auth = vm.getCloudConnector().auth
                            if 'username' in auth and 'password' in auth:
                                return self._get_object_values({"user": auth["username"],
                                                                "token_type": "password",
                                                                "token": auth["password"]},
                                                               attribute_params)
                            elif 'token' in auth:
                                return self._get_object_values({"user": "",
                                                                "token_type": "bearer",
                                                                "token": auth["token"]},
                                                               attribute_params)
                            else:
                                Tosca.logger.warn("No valid auth data in OSCAR connector")
                                return None

                        Tosca.logger.warn("No auth data in OSCAR connector")
                        return None

                Tosca.logger.warn("Attribute credential only supported in tosca.nodes.aisprint.FaaS.Function")
                return None
            else:
                Tosca.logger.warn("Attribute %s not supported." % attribute_name)
                return None
        else:
            if attribute_name == "tosca_id":
                if node_name in ["HOST", "SELF"]:
                    return "{{ IM_NODE_VMID }}"
                else:
                    return "{{ hostvars[groups['%s'][0]]['IM_NODE_VMID'] }}" % host_node.name
            elif attribute_name == "tosca_name":
                return node.name
            elif attribute_name == "private_address":
                if node.type == "tosca.nodes.indigo.Compute":
                    if index is not None:
                        return "{{ hostvars[groups['%s'][%d]]['IM_NODE_PRIVATE_IP'] }}" % (host_node.name, index)
                    else:
                        return ("{{ groups['%s']|map('extract', hostvars,'IM_NODE_PRIVATE_IP')|list"
                                " if '%s' in groups else []}}" % (host_node.name, host_node.name))
                else:
                    if node_name in ["HOST", "SELF"]:
                        return "{{ IM_NODE_PRIVATE_IP }}"
                    else:
                        return "{{ hostvars[groups['%s'][0]]['IM_NODE_PRIVATE_IP'] }}" % host_node.name
            elif attribute_name == "public_address":
                if node.type == "tosca.nodes.indigo.Compute":
                    if index is not None:
                        return "{{ hostvars[groups['%s'][%d]]['IM_NODE_PUBLIC_IP'] }}" % (host_node.name, index)
                    else:
                        return ("{{ groups['%s']|map('extract', hostvars,'IM_NODE_PUBLIC_IP')|list"
                                " if '%s' in groups else []}}" % (host_node.name, host_node.name))
                else:
                    if node_name in ["HOST", "SELF"]:
                        return "{{ IM_NODE_PUBLIC_IP }}"
                    else:
                        return "{{ hostvars[groups['%s'][0]]['IM_NODE_PUBLIC_IP'] }}" % host_node.name
            elif attribute_name == "ip_address":
                if root_type == "tosca.nodes.network.Port":
                    order = self._final_function_result(node.get_property_value('order'), node)
                    return "{{ hostvars[groups['%s'][0]]['IM_NODE_NET_%s_IP'] }}" % (host_node.name, order)
                else:
                    # TODO: check this
                    if node_name == "HOST":
                        return "{{ IM_NODE_PUBLIC_IP }}"
                    else:
                        return ("{{ hostvars[groups['%s'][0]]['IM_NODE_PUBLIC_IP']"
                                " if 'IM_NODE_PUBLIC_IP' in hostvars[groups['%s'][0]] else "
                                "hostvars[groups['%s'][0]]['IM_NODE_PRIVATE_IP']}}" % (host_node.name,
                                                                                       host_node.name,
                                                                                       host_node.name))
            elif attribute_name == "endpoint":
                if root_type == "tosca.nodes.aisprint.FaaS.Function":
                    oscar_host = self._find_host_compute(node, self.tosca.nodetemplates,
                                                         "tosca.nodes.SoftwareComponent")
                    if host_node != node and oscar_host:
                        # OSCAR function deployed in a deployed VM
                        dns_host = self._final_function_result(oscar_host.get_property_value('dns_host'), oscar_host)
                        if dns_host.strip("'\""):
                            return "https://%s" % dns_host

                Tosca.logger.warn("Attribute endpoint only supported in tosca.nodes.aisprint.FaaS.Function")
                return None
            else:
                Tosca.logger.warn("Attribute %s not supported." % attribute_name)
                return None

    def _final_function_result(self, func, node, inf_info=None):
        """
        Take a translator.toscalib.functions.Function and return the final result
        (in some cases the result of a function is another function)
        """
        if not isinstance(func, (Function, dict, list)):
            return func
        elif isinstance(func, Function):
            if isinstance(func, GetAttribute):
                func = self._get_attribute_result(func, node, inf_info)
            elif isinstance(func, Concat):
                func = self._get_intrinsic_value({"concat": func.args}, node, inf_info)
            elif isinstance(func, Token):
                func = self._get_intrinsic_value({"token": func.args}, node, inf_info)
            else:
                func = func.result()
            return self._final_function_result(func, node, inf_info)
        elif isinstance(func, list):
            for i, elem in enumerate(func):
                func[i] = self._final_function_result(elem, node, inf_info)
            return func
        else:  # is a dict
            if is_function(func):
                func = get_function(self.tosca, node, func)
                return self._final_function_result(func, node, inf_info)
            elif self._is_intrinsic(func):
                func = self._get_intrinsic_value(func, node, inf_info)
                return self._final_function_result(func, node, inf_info)
            else:  # a plain dict
                for k, v in func.items():
                    func[k] = self._final_function_result(v, node, inf_info)
                return func
        # TODO: resolve function values related with run-time values as IM
        # or ansible variables

    def _find_host_compute(self, node, nodetemplates, base_root_type="tosca.nodes.Compute"):
        """
        Select the node to host each node, using the node requirements
        In most of the cases the are directly specified, otherwise "node_filter" is used
        """

        # check for a HosteOn relation
        root_type = Tosca._get_root_parent_type(node).type
        if root_type == base_root_type:
            return node

        if node.requirements:
            for r, n in node.relationships.items():
                if Tosca._is_derived_from(r, r.HOSTEDON) or Tosca._is_derived_from(r, r.BINDSTO):
                    root_type = Tosca._get_root_parent_type(n).type
                    if root_type == base_root_type:
                        return n
                    else:
                        return self._find_host_compute(n, nodetemplates)

        # There are no direct HostedOn node
        # check node_filter requirements
        if node.requirements and base_root_type == "tosca.nodes.Compute":
            for requires in node.requirements:
                if 'host' in requires:
                    value = requires.get('host')
                    if isinstance(value, dict):
                        if 'node_filter' in value:
                            node_filter = value.get('node_filter')
                            return self._get_compute_from_node_filter(node_filter, nodetemplates)

        return None

    def _node_fulfill_filter(self, node, node_filter):
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
                        value = self._final_function_result(prop.value, node)
                        if prop.name in ['disk_size', 'mem_size']:
                            value, unit = Tosca._get_size_and_unit(value)
                        node_props[prop.name] = (value, unit)

        filter_props = {}
        # Get node_filter properties
        for elem in node_filter:
            if isinstance(elem, dict):
                for cap_type in ['os', 'host']:
                    if cap_type in elem:
                        for p in elem.get(cap_type).get('properties'):
                            p_name = list(p.keys())[0]
                            p_value = list(p.values())[0]
                            if isinstance(p_value, dict):
                                filter_props[p_name] = (list(p_value.keys())[0],
                                                        list(p_value.values())[0])
                            else:
                                filter_props[p_name] = ("equal", p_value)

        operator_map = {
            'equal': operator.eq,
            'greater_than': operator.gt,
            'greater_or_equal': operator.ge,
            'less_than': operator.lt,
            'less_or_equal': operator.le
        }

        # Compare the properties
        for name, value in filter_props.items():
            op, filter_value = value
            if name in ['disk_size', 'mem_size']:
                filter_value, _ = Tosca._get_size_and_unit(filter_value)

            if name in node_props:
                node_value, _ = node_props[name]
                conv_operator = operator_map.get(op, None)
                if conv_operator:
                    comparation = conv_operator(node_value, filter_value)
                else:
                    if op == "in_range":
                        comparation = node_value >= filter_value[0] and node_value <= filter_value[1]
                    elif op == "valid_values":
                        comparation = node_value in filter_value
                    else:
                        Tosca.logger.warn("Logical operator %s not supported." % op)

                if not comparation:
                    return False
            else:
                # if this property is not specified in the node, return False
                # TODO: we must think about default values
                return False

        return True

    def _get_compute_from_node_filter(self, node_filter, nodetemplates):
        """
        Select the first node that fulfills the specified "node_filter"
        """

        for node in nodetemplates:
            root_type = Tosca._get_root_parent_type(node).type

            if root_type == "tosca.nodes.Compute":
                if self._node_fulfill_filter(node, node_filter.get('capabilities')):
                    return node

        return None

    @staticmethod
    def _get_dependency_level(node):
        """
        Check the relations to get the contextualization level
        """
        if node.requirements:
            maxl = 0
            for r, n in node.relationships.items():
                if Tosca._is_derived_from(r, [r.HOSTEDON, r.DEPENDSON, r.CONNECTSTO]):
                    level = Tosca._get_dependency_level(n)
                else:
                    level = 0

                if level > maxl:
                    maxl = level
            return maxl + 1
        else:
            return 1

    @staticmethod
    def _get_size_and_unit(str_value):
        """
        Normalize the size and units to bytes
        """
        return ScalarUnit_Size(str_value).get_num_from_scalar_unit('B'), 'B'

    def _gen_network(self, node):
        """
        Take a node of type "Network" and get the RADL.network to represent it
        """
        res = network(node.name)

        nework_type = self._final_function_result(node.get_property_value('network_type'), node)
        network_name = self._final_function_result(node.get_property_value('network_name'), node)
        network_cidr = self._final_function_result(node.get_property_value('cidr'), node)
        network_router = self._final_function_result(node.get_property_value('gateway_ip'), node)
        proxy_host = self._final_function_result(node.get_property_value('proxy_host'), node)
        proxy_credential = self._final_function_result(node.get_property_value('proxy_credential'), node)

        # TODO: get more properties -> must be implemented in the RADL
        if nework_type and nework_type.lower() == "public":
            res.setValue("outbound", "yes")

        if network_name:
            res.setValue("provider_id", network_name)

        if network_cidr:
            res.setValue("cidr", network_cidr)
            # assume that if the cidr is specified the net will be created
            res.setValue("create", "yes")

        if network_router:
            res.setValue("router", network_router)

        if proxy_host:
            host = proxy_host
            if proxy_credential:
                user = ""
                if "user" in proxy_credential:
                    user = proxy_credential["user"]
                else:
                    raise Exception("Property 'user' must bet set in proxy_credential.")
                token_type, token = self._get_credential_values(proxy_credential)
                if token_type == "password" and token:
                    host = "%s:%s@%s" % (user, token, host)
                else:
                    host = "%s@%s" % (user, host)
                res.setValue("proxy_host", host)
                if token_type == "private_key" and token:
                    res.setValue("proxy_key", token)
            else:
                raise Exception("Property 'proxy_credential' must bet set if proxy_host is set.")

        return res

    @staticmethod
    def _get_credential_values(credential):
        token_type = "password"
        if 'token_type' in credential and credential['token_type']:
            token_type = credential['token_type']
        token = None
        if 'token' in credential and credential['token']:
            token = credential['token']
        return token_type, token

    @staticmethod
    def _get_node_artifacts(node):
        """ Get a dict will the node artifacts """
        artifacts = []
        artifacts.append(node.type_definition.get_value('artifacts', node.entity_tpl, True))

        if (isinstance(node, NodeTemplate)):
            # Get also artifacts of related nodes and relations
            for relationship, trgt in node.relationships.items():
                artifacts.append(relationship.get_value('artifacts'))
                artifacts.append(trgt.type_definition.get_value('artifacts', trgt.entity_tpl, True))

        artifacts_dict = {}

        for artifact in artifacts:
            if artifact:
                if isinstance(artifact, dict):
                    artifacts_dict.update(artifact)
                else:
                    for elem in artifact:
                        artifacts_dict.update(elem)

        return artifacts_dict

    def _add_ansible_roles(self, node, nodetemplates, system):
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
                compute = self._find_host_compute(other_node, nodetemplates)

            if compute and compute.name == node.name:
                # Get the artifacts to see if there is a ansible galaxy role
                # and add it as an "ansible.modules" app requirement in RADL
                artifacts = self._get_node_artifacts(other_node)
                for _, artifact in artifacts.items():
                    if ('type' in artifact and artifact['type'] == 'tosca.artifacts.AnsibleGalaxy.role' and
                            'file' in artifact and artifact['file']):
                        if artifact['file'] not in roles:
                            roles.append(artifact['file'])

        for role in roles:
            app_features = Features()
            app_features.addFeature(Feature('name', '=', 'ansible.modules.' + role))
            feature = Feature('disk.0.applications', 'contains', app_features)
            system.addFeature(feature)

    def _gen_system(self, node, nodetemplates):
        """
        Take a node of type "Compute" and get the RADL.system to represent it
        """
        res = system(node.name)

        res.setValue("instance_name", node.name)

        for prop in node.get_properties_objects():
            if prop.name == "tags" and prop.value:
                if isinstance(prop.value, dict):
                    instance_tags = ""
                    for k, v in prop.value.items():
                        if instance_tags != "":
                            instance_tags += ","
                        instance_tags += "%s=%s" % (k, v)
                    res.setValue("instance_tags", instance_tags)
                else:
                    raise Exception("tags property must be a dictionary.")
            elif prop.name == "instance_name" and prop.value:
                res.setValue("instance_name", prop.value)

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
            'cpu_frequency': 'cpu.performance',
            'instance_type': 'instance_type',
            'preemtible_instance': 'spot',
            'num_gpus': 'gpu.count',
            'gpu_vendor': 'gpu.vendor',
            'gpu_model': 'gpu.model',
            'sgx': 'cpu.sgx',
            'sgx_epc_size': 'cpu.sgx.epc_size'
        }

        for cap_type in ['os', 'host']:
            if node.get_capability(cap_type):
                for prop in node.get_capability(cap_type).get_properties_objects():
                    name = property_map.get(prop.name, None)
                    if name and prop.value is not None:
                        unit = None
                        value = self._final_function_result(prop.value, node)
                        if prop.name in ['disk_size', 'mem_size']:
                            value, unit = Tosca._get_size_and_unit(value)
                        elif prop.name == "version":
                            value = str(value)
                        elif prop.name == "image":
                            if value.find("://") == -1:
                                value = "docker://%s" % value
                        elif prop.name == "credential":
                            token_type, token = self._get_credential_values(value)
                            if token:
                                if token_type == "password":
                                    feature = Feature("disk.0.os.credentials.password", "=", token)
                                    res.addFeature(feature)
                                elif token_type == "private_key":
                                    feature = Feature("disk.0.os.credentials.private_key", "=", token)
                                    res.addFeature(feature)
                                elif token_type == "public_key":
                                    feature = Feature("disk.0.os.credentials.public_key", "=", token)
                                    res.addFeature(feature)
                                else:
                                    Tosca.logger.warn("Unknown tyoe of token %s. Ignoring." % token_type)
                            if 'user' not in value or not value['user']:
                                raise Exception("User must be specified in the image credentials.")
                            name = "disk.0.os.credentials.username"
                            value = value['user']
                        elif prop.name in ["preemtible_instance", "sgx"]:
                            value = 'yes' if value else 'no'

                        if isinstance(value, float) or isinstance(value, int):
                            operator = ">="
                        else:
                            operator = "="

                        feature = Feature(name, operator, value, unit)
                        res.addFeature(feature)

        # Find associated BlockStorages
        disks = self._get_attached_disks(node)

        for size, unit, location, device, num, fstype, vol_id, _, vol_type in disks:
            if vol_id:
                res.setValue('disk.%d.image.url' % num, vol_id)
            else:
                if vol_type:
                    res.setValue('disk.%d.type' % num, vol_type)
                if size:
                    res.setValue('disk.%d.size' % num, size, unit)
            if device:
                res.setValue('disk.%d.device' % num, device)
            if location:
                res.setValue('disk.%d.mount_path' % num, location)
                res.setValue('disk.%d.fstype' % num, fstype)

        self._add_ansible_roles(node, nodetemplates, res)

        availability_zone = self._get_placement_property(res.name, "availability_zone")
        if availability_zone:
            res.setValue('availability_zone', availability_zone)

        return res

    def _get_bind_networks(self, node, nodetemplates):
        nets = []

        for port in nodetemplates:
            root_type = Tosca._get_root_parent_type(port).type
            if root_type == "tosca.nodes.network.Port":
                binding = None
                link = None
                for requires in port.requirements:
                    binding = requires.get('binding', binding)
                    if isinstance(binding, dict):
                        if "node" in binding:
                            binding = binding["node"]
                        else:
                            raise Exception("Incorrect binding in Port node %s" % node.name)
                    link = requires.get('link', link)
                    if isinstance(link, dict):
                        if "node" in link:
                            link = link["node"]
                        else:
                            raise Exception("Incorrect link in Port node %s" % node.name)

                if binding == node.name:
                    ip = self._final_function_result(port.get_property_value('ip_address'), port)
                    order = self._final_function_result(port.get_property_value('order'), port)
                    dns_name = self._final_function_result(port.get_property_value('dns_name'), port)
                    additional_ip = self._final_function_result(port.get_property_value('additional_ip'), port)
                    additional_dns_names = self._final_function_result(port.get_property_value('additional_dns_names'),
                                                                       port)
                    nets.append((link, ip, dns_name, additional_dns_names, order, additional_ip))

        return nets

    def _get_attached_disks(self, node):
        """
        Get the disks attached to a node
        """
        disks = []
        count = 1

        for rel, trgt in node.relationships.items():
            src = node
            rel_tpl = Tosca._get_relationship_template(rel, src, trgt)
            # TODO: ver root_type
            if rel.type.endswith("AttachesTo"):
                props = rel_tpl.get_properties_objects()

                vol_type = None
                size = None
                location = None
                # set a default device
                device = None
                fs_type = "ext4"

                for prop in props:
                    value = self._final_function_result(prop.value, node)
                    if prop.name == "location":
                        location = value
                    elif prop.name == "device":
                        device = value
                    elif prop.name == "fs_type":
                        fs_type = value

                if trgt.type_definition.type.endswith(".BlockStorage"):
                    vol_type = self._final_function_result(trgt.get_property_value('type'), trgt)
                    full_size = self._final_function_result(trgt.get_property_value('size'), trgt)
                    volume_id = self._final_function_result(trgt.get_property_value('volume_id'), trgt)
                    snapshot_id = self._final_function_result(trgt.get_property_value('snapshot_id'), trgt)
                    size, unit = Tosca._get_size_and_unit(full_size)
                    disks.append((size, unit, location, device, count, fs_type, volume_id, snapshot_id, vol_type))
                    count += 1
                else:
                    Tosca.logger.debug("Attached item of type %s ignored." % trgt.type_definition.type)

        return disks

    @staticmethod
    def _is_derived_from(rel, parent_type):
        """
        Check if a node is a descendant from a specified parent type
        """
        if isinstance(parent_type, list):
            parent_types = parent_type
        else:
            parent_types = [parent_type]
        while True:
            if rel.type in parent_types:
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
        try:
            node_type = node.type_definition
        except AttributeError:
            node_type = node.definition

        while True:
            if node_type.parent_type is not None:
                if node_type.parent_type.type.endswith(".Root"):
                    return node_type
                else:
                    node_type = node_type.parent_type
            else:
                return node_type

    @staticmethod
    def _get_interfaces(node, interface_names=['Standard', 'Configure'],
                        steps=['create', 'configure', 'start', 'stop', 'delete']):
        """
        Get a dict of InterfacesDef of the specified node
        """
        interfaces = {}
        for interface in node.interfaces:
            interfaces[interface.name] = interface

        node_type = node.type_definition

        while True:
            for interface_name in interface_names:
                if node_type.interfaces and interface_name in node_type.interfaces:
                    for name, elems in node_type.interfaces[interface_name].items():
                        if name in steps:
                            if name not in interfaces:
                                interfaces[name] = InterfacesDef(node_type, interface_name, name=name,
                                                                 value=elems, node_template=node)

            if node_type.parent_type is not None:
                node_type = node_type.parent_type
            else:
                return interfaces

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

    def merge(self, other_tosca):
        Tosca._merge_yaml(self.yaml, other_tosca.yaml)
        self.tosca = ToscaTemplate(yaml_dict_tpl=copy.deepcopy(self.yaml))
        return self

    @staticmethod
    def _merge_yaml(yaml1, yaml2):
        if yaml2 is None:
            return yaml1
        elif isinstance(yaml1, dict) and isinstance(yaml2, dict):
            for k, v in yaml2.items():
                if k not in yaml1:
                    yaml1[k] = v
                else:
                    yaml1[k] = Tosca._merge_yaml(yaml1[k], v)
        elif isinstance(yaml1, list) and isinstance(yaml2, (list, tuple)):
            for i, v in enumerate(yaml2):
                if i < len(yaml1):
                    yaml1[i] = Tosca._merge_yaml(yaml1[i], v)
                else:
                    yaml1.append(v)
        else:
            yaml1 = yaml2

        return yaml1

    def _gen_oscar_system(self, node):
        """Generate the system for an OSCAR function."""
        res = system(node.name)

        property_map = {
            'name': 'name',
            'cpu': 'cpu.count',
            'image': 'disk.0.image.url',
            'script': 'script',
            'image_pull_secrets': 'image_pull_secrets'
        }

        for prop in node.get_properties_objects():
            value = self._final_function_result(prop.value, node)
            if value not in [None, [], {}]:
                if prop.name in property_map:
                    res.setValue(property_map[prop.name], value)
                elif prop.name == 'alpine':
                    res.setValue('alpine', 1 if value else 0)
                elif prop.name == 'memory':
                    if not value.endswith("B"):
                        value += "B"
                    value = int(ScalarUnit_Size(value).get_num_from_scalar_unit('B'))
                    res.setValue("memory.size", value, 'B')
                elif prop.name == 'env_variables':
                    variables = ["%s:%s" % (k, v) for k, v in value.items()]
                    res.setValue("environment.variables", variables)
                elif prop.name in ['input', 'output']:
                    for num, elem in enumerate(value):
                        res.setValue("%s.%d.provider" % (prop.name, num), elem.get("storage_provider"))
                        res.setValue("%s.%d.path" % (prop.name, num), elem.get("path"))
                        if elem.get("suffix"):
                            res.setValue("%s.%d.suffix" % (prop.name, num), elem.get("suffix"))
                        if elem.get("prefix"):
                            res.setValue("%s.%d.prefix" % (prop.name, num), elem.get("prefix"))
                elif prop.name == 'storage_providers':
                    cont = {"minio": 0, "s3": 0, "onedata": 0}

                    for provider_type in ["minio", "s3", "onedata"]:
                        if provider_type in value:
                            for prov_id, provider in value[provider_type].items():
                                provider_pref = "%s.%d" % (provider_type, cont[provider_type])
                                cont[provider_type] += 1
                                res.setValue("%s.id" % provider_pref, prov_id)

                                for elem in ['access_key', 'secret_key', 'region', 'endpoint',
                                             'verify', 'oneprovider_host', 'token', 'space']:
                                    if provider.get(elem):
                                        res.setValue("%s.%s" % (provider_pref, elem), provider.get(elem))
                else:
                    # this should never happen
                    Tosca.logger.warn("Property %s not expected. Ignoring." % prop.name)

        return res

    def _get_oscar_service_json(self, node):
        """Get the OSCAR service json"""
        res = {}

        for prop in node.get_properties_objects():
            value = self._final_function_result(prop.value, node)
            if value not in [None, [], {}]:
                if prop.name in ['name', 'script', 'alpine', 'input', 'output', 'storage_providers']:
                    res[prop.name] = value
                elif prop.name == 'cpu':
                    res['cpu'] = "%g" % value
                elif prop.name == 'memory':
                    if not value.endswith("B"):
                        value += "B"
                    res[prop.name] = "%gMi" % ScalarUnit_Size(value).get_num_from_scalar_unit('MiB')
                elif prop.name == 'image':
                    if value.startswith('oscar://'):
                        url_image = urlparse(value)
                        if url_image.path:
                            res["image"] = url_image.path[1:]
                    elif value.startswith('docker://'):
                        res["image"] = value[9:]
                    else:
                        res["image"] = value
                elif prop.name == 'env_variables':
                    res['environment'] = {'Variables': value}
                elif prop.name == 'image_pull_secrets':
                    if not isinstance(value, list):
                        value = [value]
                    res['image_pull_secrets'] = value
                else:
                    # this should never happen
                    Tosca.logger.warn("Property %s not expected. Ignoring." % prop.name)

        return json.dumps(res)
