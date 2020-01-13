.. _radl:

Resource and Application Description Language (RADL)
====================================================

The main purpose of the *Resource and Application description Language* (RADL)
is to specify the requirements of the scientific applications needed to be
deployed in a virtualized computational infrastructure (cloud). Using a
declarative scheme RADL considers distinct features related to

- hardware, like CPU number, CPU architecture, and RAM size;
- software, like applications, libraries and data base systems;
- network, like network interface and DNS configuration; and
- contextualization, extra steps to set up an adequate environment for the
  application.

RADL is intended to be more abstract that other standards to specify virtual
appliances, like `OVF <http://www.dmtf.org/standards/ovf>`_, and easily
extensible with other tools, like contextualization languages such as 
`Ansible <http://www.ansible.com>`_.

Basic structure
---------------

An RADL document has the next general structure::

   ansible <ansible_host_id> (<features>)
   
   network <network_id> (<features>)

   system <system_id> (<features>)

   configure <configure_id> (<Ansible recipes>)

   contextualize [max_time] (
     system <system_id> configure <configure_id> [step <num>]
     ...
   )

   deploy <system_id> <num> [<cloud_id>] 

The keywords ``ansible``, ``network``, ``system`` and ``configure`` assign some *features*
or *recipes* to an identity ``<id>``. The features are a list of constrains
separated by ``and``, and a constrain is form by
``<feature name> <operator> <value>``. For instance::

   system tomcat_node (
      memory.size >= 1024M and
      disk.0.applications contains (name='tomcat')
   )

this RADL defines a *system* with the feature ``memory.size`` greater or equal
than ``1024M`` and with the feature ``disk.0.applications`` containing an
element with ``name`` ``tomcat``.

The ``network`` keyword enables to represent different networks so that the 
VMs can be attached to them.

The ``ansible`` keyword enables to specify external nodes that will act as the
ansible master node to configure the VMs. These nodes must be connected in a
network connected will all the VMs of the infrastructure.

The sentences under the keyword ``contextualize`` indicate the recipes that
will be executed during the deployment of the virtual machine.

The ``deploy`` keyword is a request to deploy a number of virtual machines.
If some identity of a cloud provider is specified the VM will be deployed in the
Cloud provider with the "id" specified.

Use Cases
---------

RADL is not limited to deploy different configurations of virtual machines
easily. In many applications infrastructures need management during their life
cycle, like deploying virtual machines with new features, changing the
features of already deployed virtual machine and undeploying some of them.
Next we detail valid RADL examples for every use.

.. todo::

   Add support in RADL to undeploy virtual machine.

.. todo::

   Add support in RADL to modify features of already deployed virtual machine.

Create a New Infrastructure
^^^^^^^^^^^^^^^^^^^^^^^^^^^

A common RADL defines a network and at least one kind of virtual machine and
deploys some virtual machines. However the minimum RADL document to create
an infrastructure is an empty one.

Add New Definitions
^^^^^^^^^^^^^^^^^^^

After the creation of the infrastructure, new networks, systems and recipes
can be defined. The new definitions can refer to already defined elements,
but they must be mentioned. For instance, an infrastructure is created as::

   network net (outbound = 'no')
   system small_node (
      cpu.arch = 'x86_64' and
      cpu.count = 1 and
      memory.size >= 512M and
      net_interface.0.connection = 'net' and
      disk.0.os.name = 'linux'
   )

A new system with more memory and CPUs, and in the same network can be defined
as::

   network net
   system big_node (
      cpu.arch = 'x86_64' and
      cpu.count = 4 and
      memory.size >= 3G and
      net_interface.0.connection = 'net' and
      disk.0.os.name = 'linux'
   )


Deploy New Virtual Machines
^^^^^^^^^^^^^^^^^^^^^^^^^^^

In the same way, new virtual machines from already defined systems can deployed.
For instance, this example deploys one ``small_node`` and other ``big_node``::

   system small_node
   system big_node

   deploy small_node 1
   deploy big_node 1

Ansible Features
----------------

Under the keyword ``ansible`` there are the features needed to access the ansible
master node with SSH.
The supported features are:

``host = '<ip or hostname>'``
   Indicate the hostname or IP to of the ansible node. 
   
``credentials.username = '<username>'``
   Indicate the SSH username. 
   
``credentials.password = '<password>'``
   Indicate the SSH password. 
   
``credentials.private_key = '<private_key>'``
   Indicate the SSH private key.

Network Features
----------------

Under the keyword ``network`` there are the features describing a Local Area
Network (LAN) that some virtual machines can share in order to communicate
to themselves and to other external networks.
The supported features are:

``outbound = 'yes|no'``
   Indicate whether the IP that will have the virtual machines in this network
   will be public (accessible from any external network) or private.
   If ``yes``, IPs will be public, and if ``no``, they will be private.
   The default value is ``no``.

``outports = <outports_string>``
   Indicate the ports to be open in the VM at the Cloud provider system.
   Valid formats:

	* 8899/tcp-8899/tcp,22/tcp-22/tcp
	* 8899/tcp-8899,22/tcp-22
	* 8899-8899,22-22
	* 8899/tcp,22/udp
	* 8899,22
	* 9000:9100/tcp
	* 9000:9100

   The usage of ``-`` means port mapping the first port (remote) will be opened and
   redirected the the second port (local). 
   The usage of ``:`` means port range.  
   The default value is ``''``.
   
``provider_id = <string>``
   Indicate the name of the network in a specific Cloud provider.
   In case of setting this field in a public network in an **OpenStack** deployment
   it specifies the name of floating ip pool to get the external floating IP.
   The default value is ``''``.

``create = 'yes|no'``
   Indicate if the IM must create the network or will try to find the most appropriate 
   from the existing networks. In some connectors (e.g. Azure) the networks are always
   created independently the value of this parameter.
   The default value is ``'no'``.

``cidr = <string>``
   Indicate the CIDR of the network (e.g. 10.0.0.0/24) in case of network creation.
   Wildcards can be used (i.e. 10.*.*.0/24) and the IM will select the first option
   that is not used in the current Cloud provider.
   The default value is ``''``.

``sg_name = <string>``
   The name of the Security Group associated with the network that will be created to
   manage the security in this network.
   The default value is ``''``.

``router = <string>``
   Add static routes in the network settings. Currently only supported in OpenStack, 
   GCE and AWS. The format is 'net_cidr, system_name' e.g. '10.1.0.0/16,front' to route
   all the traffic to the net 10.1.0.0/16 through the front node, or '0.0.0.0/0,front' to 
   route all the traffic through the front node.
   The default value is ``''``.

System Features
---------------

Under the keyword ``system`` there are the features describing a virtual
machine.  The supported features are:

``ansible_host = '<ansible_host id>'``
   Set the ansible master node that will contextualize the virtual machine.
   The ansible host need to have ansible (2.0 or later) installed and the
   ansible.cfg file configured with similar values than the ansible in the IM
   server.

``image_type = vmdk|qcow|qcow2|raw``
   Constrain the virtual machine image disk format.

``virtual_system_type = '<hypervisor>-<version>'``
   Constrain the hypervisor and the version used to deploy the virtual machine.

``price <=|=|=> <positive float value>``
   Constrain the price per hour that will be paid, if the virtual machine is
   deployed in a public cloud.

``cpu.count <=|=|=> <positive integer value>``
   Constrain the number of virtual CPUs in the virtual machine.

``cpu.arch = i686|x86_64``
   Constrain the CPU architecture.

``cpu.performance <=|=|=> <positive float value>ECU|GCEU``
   Constrain the total computational performance of the virtual machine.

``memory.size <=|=|=> <positive integer value>B|K|M|G``
   Constrain the amount of *RAM* memory (principal memory) in the virtual
   machine.

``net_interface.<netId>``
   Features under this prefix refer to virtual network interface attached to
   the virtual machine.

``net_interface.<netId>.connection = <network id>``
   Set the virtual network interface is connected to the LAN with ID
   ``<network id>``.

``net_interface.<netId>.ip = <IP>``
   Set a static IP to the interface, if it is supported by the cloud provider.

``net_interface.<netId>.dns_name = <string>``
   Set the string as the DNS name for the IP assigned to this interface. If the
   string contains ``#N#`` they are replaced by a number that is distinct for
   every virtual machine deployed with this ``system`` description.

``availability_zone``
   Set the availability zone or region where this VM will be launched.
   It only applies to Google Cloud, Microsoft Azure, Amazon AWS, and Fogbow
   connectors. In the Fogbow case it specifies the site and cloud where the VM will
   be launched (in format cloud@site).

``instance_id``
   Get the instance ID assigned by the Cloud provider for this VM. 
   
``instance_name``
   Set the instance name for this VM. 

``instance_type``
   Set the instance type name of this VM. 

``instance_tags``
   A set of keypair values to be set to the VMs.
   With the following format: key=value,key2=value2 ...   

``disk.<diskId>.<feature>``
   Features under this prefix refer to virtual storage devices attached to
   the virtual machine. ``disk.0`` refers to system boot device.

``disk.<diskId>.image.url = <url> or [comma separated list of urls]``
   Set the source of the disk image. The URI designates the cloud provider:

   * ``one://<server>:<port>/<image-id>``, for OpenNebula;
   * ``one://<server>:<port>/<image-name>``, for OpenNebula;
   * ``ost://<server>:<port>/<image-id>``, for OpenStack;
   * ``aws://<region>/<ami-id>``, for Amazon Web Service;
   * ``aws://<region>/<snapshot-id>``, for Amazon Web Service;
   * ``aws://<region>/<snapshot-name>``, for Amazon Web Service;
   * ``gce://<region>/<image-id>``, for Google Cloud;
   * ``azr://<image-id>``, for Microsoft Azure Clasic;
   * ``azr://<publisher>/<offer>/<sku>/<version>``, for Microsoft Azure;
   * ``azr://[snapshots|disk]/<rgname>/<diskname>``, for Microsoft Azure;
   * ``<fedcloud_endpoint_url>/<image_id>``, for FedCloud OCCI connector.
   * ``appdb://<site_name>/<apc_name>?<vo_name>``, for FedCloud OCCI or OpenStack connector using AppDB info (from vers. 1.6.0 and 1.8.6).
   * ``docker://<docker_image>``, for Docker images.
   * ``fbw://<fns_server>/<image-id>``, for FogBow images.

   In case of using a list of URLs, the IM will select the final image based on
   the credentials provided by the user. 

``disk.<diskId>.image.name = <string>``
   Set the source of the disk image by its name in the VMRC server.

``disk.<diskId>.device = <string>``
   Set the device name, if it is disk with no source set.
   It specifies the device where the disk will be located in the system
   (hdb, hdc, etc.). Depending on the Cloud provider the meaning of this
   field may change. In Docker and Kubernetes connectors the device
   refers to a path to create a bind in the container, if it starts with
   character ``/`` or the name of a volume otherwise.
   
``disk.<diskId>.mount_path = <string>``
   Set the mount point, if it is disk with no source set.
   It specifies a path to mount the device. In Docker and Kubernetes 
   connectors this path refers to the directory in the container to 
   bind the host directory specified in ``device``.
   
``disk.<diskId>.fstype = <string>``
   Set the mount point, if it is disk with no source set.
   It specifies the type of the filesystem of this disk. If specified
   the contextualization agent will try to format and mount this disk
   in the path specified in ``mount_path`` field. In case of Docker 
   the fstype refers to the driver to use in case of using a volume.

``disk.<diskId>.size = <positive integer value>B|K|M|G``
   Set the size of the disk, if it is a disk with no source set.

``disk.<diskId>.type = <string>``
   Set the type of the disk, if it is a disk with no source set.
   The types depends on the provider: e.g. in GCE posible types are: pd-standard | pd-ssd,
   in EC2 possible values are: standard | io1 | gp2.

``disk.0.free_size = <positive integer value>B|K|M|G``
   Set the free space available in boot disk.

``disk.<diskId>.os.name = linux|windows|mac os x``
   Set the operating system associated to the content of the disk.

``disk.<diskId>.os.flavour = <string>``
   Set the operating system distribution, like ``ubuntu``, ``centos``,
   ``windows xp`` and ``windows 7``.

   .. todo::

      Suggestion: ``disk.<diskId>.os.flavour`` is British. Change or add also ``flavor``.

   .. todo::

      Suggestion: considering Windows, the version is concreted in
      ``disk.<diskId>.os.flavour``. Maybe it is better in
      ``disk.<diskId>.os.version``.

``disk.<diskId>.os.version = <string>``
   Set the version of the operating system distribution, like ``12.04`` or
   ``7.1.2``.

``disk.0.os.credentials.username = <string>`` and ``disk.0.os.credentials.password = <string>``
   Set a valid username and password to access the operating system with sudo privileges.

``disk.0.os.credentials.public_key = <string>`` and ``disk.0.os.credentials.private_key = <string>``
   Set a valid public-private keypair to access the operating system with sudo privileges.

``disk.0.os.credentials.new.password = <string>`` and ``disk.0.os.credentials.new.private_key = <string>``
   Changes the credentials of the user with admin privileges.

``disk.<diskId>.applications contains (name=<string>, version=<string>, preinstalled='yes|no')``
   Set that the disk must have installed the application with name ``name``.
   Optionally a version can be specified. Also if ``preinstalled`` is ``yes``
   the application must have already installed; and if ``no``, the application
   can be installed during the contextualization of the virtual machine if it
   is not installed.
   
   There are a **special** type of application that starts with ``ansible.modules.``.
   These applications installs `ansible roles <https://docs.ansible.com/playbooks_roles.html>`_
   that can be used in the ``configure`` sections of the RADL.
   These roles will be installed with the ``ansible-galaxy`` tool so the format of the string
   after ``ansible.modules.`` must follow one of the supported formats of this tool (see 
   `Ansible Galaxy docs <https://galaxy.ansible.com/intro>`_ for more info):
   
   There are three type of ansible modules:
   
   * `Ansible Galaxy <https://galaxy.ansible.com/>`_ roles: ``ansible.modules.micafer.hadoop``: The user
     specifies the name of the galaxy role afther the string ``ansible.modules.``
   * HTTP URL: ``ansible.modules.https://github.com/micafer/ansible-role-hadoop/archive/master.tar.gz|hadoop``: The user 
     specifies an HTTP URL afther the string ``ansible.modules.``. The file must be compressed. 
     It must contain the ansible role content. Furthermore the user can specify the rolename using 
     a ``|`` afther the url, as shown in the example.
   * Git Repo: ``ansible.modules.git+https://github.com/micafer/ansible-role-hadoop|hadoop``: The user specifies a Git repo
     (using the git scheme in the URL) afther the string ``ansible.modules.``. Furthermore the 
     user can specify the rolename using a ``|`` afther the url, as shown in the example.

``nat_instance = yes|no``
   Set that this instance will be used as a NAT router for a set of nodes. 
   It will configure the node to enable nat with the appropriate iptables rules
   (experimental).

Disk Management
^^^^^^^^^^^^^^^

In the RADL documents there are two different types of disks: ``disk.0`` as the boot disk with the O.S. and
the rest of disks assumed as data disks. In the first case if you are using an VMRC server you can specify the
features of the requested O.S. and let VMRC to get the most suitable image::   

	disk.0.os.name='linux' and
	disk.0.os.flavour='ubuntu' and
	disk.0.os.version>='16.04'

Otherwise you can directly specify the image and, if required, the credentials to access the O.S.::

	disk.0.os.name='linux' and  
	disk.0.image.url = 'one://someserver.com/123' and
	disk.0.os.credentials.username = 'ubuntu' and
	disk.0.os.credentials.password = 'somepass'

In case of the rest of disks you can specify the requirements of the data disk to be attached:: 

	disk.1.size=1GB and
	disk.1.device='hdc' and
	disk.1.fstype='ext4' and
	disk.1.mount_path='/mnt/disk1'

The fields fstype and mount_path are optional and they enable the IM (through Ansible) to format and mount
the disk in the specified path. The device field is optional in most of the connectors but some of them 
require it to correctly attach the disk to the VM.

You can also specify an image to be attached to the VM::

	disk.1.image.url = 'one://someserver.com/456' and

Parametric Values
-----------------
RADL documents can use parametric values to be requested to the user in launch time.
It make easy to launch different infrastructures without modifying the RADL document,
only changing a set of values in launch time. This parametric values are requested to
the user in the launch time by the client application (CLI or Web). 

This values are specified with the following syntax::
  
	@input.<variable_name>@

In the following example the user will be asked for specifing the ``CPUs`` and the  ``NumNodes``
variables (in the CLI and in the Web Interface)::

   system node (
      cpu.count = @input.CPUs@ and
      memory.size >= 512M
   )
   deploy node @input.NumNodes@

Contextualization
-----------------

RADL documents also enable to specify contextualization, extra steps to set up an
 adequate environment for the application. 

Configure Recipes
^^^^^^^^^^^^^^^^^

Contextualization recipes are specified under the keyword ``configure``.
Only Ansible and Cloud-Init recipes are supported currently. They are 
enclosed between the tags ``@begin`` and ``@end``, like that::

   configure add_user1 (
   @begin
   ---
     - tasks:
       - user: name=user1   password=1234
   @end
   )

In the Ansible case, to easy some contextualization tasks, IM publishes a set 
of variables that can be accessed by the recipes and have information about 
the virtual machine.

``IM_NODE_HOSTNAME``
   Hostname of the virtual machine (without the domain).

``IM_NODE_DOMAIN``
   Domain name of the virtual machine.

``IM_NODE_FQDN``
   Complete FQDN of the virtual machine.

``IM_NODE_PRIVATE_IP``
   Private IP of the virtual machine. In case that the VM has more that one the first one will be returned.

``IM_NODE_PUBLIC_IP``
   Public IP of the virtual machine. In case that the VM has more that one the first one will be returned.

``IM_NODE_NUM``
   The value of the substitution ``#N#`` in the virtual machine.

``IM_NODE_CLOUD_TYPE``
   Cloud type where the VM has been deployed.

``IM_MASTER_HOSTNAME``
   Hostname (without the domain) of the virtual machine doing the *master*
   role.

``IM_MASTER_DOMAIN``
   Domain name of the virtual machine doing the *master* role.

``IM_MASTER_FQDN``
   Complete FQDN of the virtual machine doing the *master* role.

``IM_<application name>_VERSION``
   The version installed of an application required by the virtual machine.

``IM_<application name>_PATH``
   The path to an installed application required by the virtual machine.

``IM_NODE_VMID``
   The identifier asigned by the Cloud provider to the virtual machine.
   
``IM_NODE_NET_<iface num>_IP``
   The IP assigned to the network interface num ``iface num``.

``IM_INFRASTRUCTURE_ID``
   The identifier asigned by the IM to the infrastrucure this VM belongs to.

``IM_INFRASTRUCTURE_RADL``
   The RADL in JSON format: networks, systems and deploys. (from ver. 1.6.2). It enables to use
   RADL values in Ansible recipes. The ``.`` in the properties are replaced by ``_``
   (e.g. ``net.interface.0.dns_name`` is replaced by ``net_interface_0_dns_name``).
   It can be used in combination with the `Ansible json_query filter <http://docs.ansible.com/ansible/latest/playbooks_filters.html#json-query-filter>`_
   to extract values as shown in this example::
   
      NODENAME: '{{IM_INFRASTRUCTURE_RADL|json_query("[?id == ''front''].net_interface_0_dns_name|[0]")}}'

   Ansible json_query filter is built upon `jmespath <http://jmespath.org/>`_ so this library must be installed
   on the managed node that uses this function. IM installs it on the master VM but no in the rest of VMs. If you
   want to use it on other VMs you have to prepare them installing jmespath in a previous step.


Including roles of Ansible Galaxy
---------------------------------

To include a role available in Ansible Galaxy a special application requirement
must be added: it must start with: "ansible.modules" as shown in the following
example. In this case the Ansible Galaxy role called "micafer.hadoop" will be installed::

   network net (outbound = 'yes')

   system node_ubuntu (
      cpu.arch = 'i686' and
      memory.size >= 512M and
      net_interface.0.connection = "net" and
      disk.0.os.name = "linux" and
      disk.0.os.flavour = "ubuntu" and
      disk.0.applications contains (name="ansible.modules.micafer.hadoop")
   )

Then the configuration section of the RADL can use the role as described in the role's
documentation. In the particular case of the "micafer.hadoop" role is the following::

   configure wn (
   @begin
   ---
    - roles:
       - { role: 'micafer.hadoop', hadoop_master: 'hadoopmaster' }
   
   @end
   )

You can request an specific version/tag/branch of a galaxy role using the following format::

	disk.0.applications contains (name="ansible.modules.micafer.hadoop,v1.0.0")

Disable Contextualization
-------------------------

By default the contextualize is performed in all the infrastructures. If the user wants to disable 
this step he must add an empty contextualize section::

   contextualize ()

Advanced Contextualization
--------------------------

By default the IM will apply the ``configure`` section to the nodes with the same name of the ``system`` 
defined. Furthermore all ``configure`` sections will be executed at the same time, in parallel.   

But RADL also enables to specify the order in which the ``configure`` sections will be performed and which 
configure sections will be executed to a specific type of node. It can also be specified the contextualization
tool to use en each case.

The contextualize section has the next structure::

   contextualize <max_context_time> (
      system <system_id> configure <configure_id> [step <num>] [with (Ansible|cloud_init)]
      ...
   )

The ``max_context_time`` value enables to set a timeout for the contextualization step to enable to
kill the process if some of the steps takes more time than expected.

Each line inside the contextualize section enables to specify which configure section ``configure_id``
will be applied in the nodes of type ``system_id``. Optionally a step number can be specified to set
the execution order. For example::

   system nodeA (
      ...
   )
   
   system nodeB (
      ...
   )
   
   configure conf_server (
      ...
   )
   
   configure conf_client (
      ...
   )
   
   configure launch_client (
      ...
   )
   
   contextualize 1200 (
      system nodeA configure conf_server step 1
      system nodeB configure conf_client step 1
      system nodeB configure launch_client step 2
   )

This RADL specifies that the configure section ``conf_server`` will be applied to the ``nodeA``
type nodes in the first step. In parallel the the configure section ``conf_client`` will be applied to the ``nodeB``
type nodes. Finally the configure section ``launch_client`` will be applied to the ``nodeB``
type nodes. This is a tipical example of a client-server application where the client must be launched 
afther the server has fully configured. 

Examples
--------

Hello Cloud!
^^^^^^^^^^^^

The next RADL is a simple example that launches two virtual machines in the
default cloud provider with at least 512M of RAM::

   system node (
      memory.size >= 512M
   )
   deploy node 2


Deploy ten Ubuntu
^^^^^^^^^^^^^^^^^

The next RADL deploys ten Ubuntu of 32 bits with version 12.04 at least, that
can be accessed from extern networks and with DNS names ``node-0``, ``node-1``,
..., ``node-9``::

   network net (outbound = 'yes')

   system node_ubuntu (
      cpu.arch = 'i686' and
      memory.size >= 512M and
      net_interface.0.connection = 'net' and
      net_interface.0.dns_name = 'node-#N#' and
      disk.0.os.name = 'linux' and
      disk.0.os.flavour = 'ubuntu' and
      disk.0.os.version >= '12.04' and
      disk.0.applications contains (name='toncat')
   )

   deploy node_ubuntu 10

Including a recipe from another
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The next RADL defines two recipes and one of them (``add_user1``) is called by
the other (``add_torque``)::

   configure add_user1 (
   @begin
   ---
     - tasks:
       - user: name=user1   password=1234
   @end
   )

   configure add_torque (
   @begin
   ---
     - tasks:
       - include: add_user1.yml
       - yum: pkg=${item} state=installed
         with_item:
         - torque-client
         - torque-server
   @end
   )

Using Cloud-Init contextualization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The next RADL deploys a single node that will be configured using Cloud-Init instead of Ansible::

   network privada ()
   
   system node (
      cpu.count>=1 and
      ...
   )
   
   configure node (
   @begin
     runcmd:
       - [ wget, "http://slashdot.org", -O, /tmp/index.html ]
   @end
   )
   
   deploy node 1
   
   contextualize (
      system node configure node with cloud_init
   )

It depends on the Cloud provider to process correctly the cloud-init recipes of the configure section.
More information about Cloud-Init in `Cloud-Init documentation <http://cloudinit.readthedocs.org/>`_).


JSON Version
------------

There is a JSON version of the RADL language. It has the same semantics that the original RADL but 
using JSON syntax to describe the objects. This is a complete example of the JSON format::

   [
     {
       "class": "ansible",
       "id": "ansible_jost",
       "credentials.username": "user",
       "credentials.password": "pass",
       "host": "server"
     },
     {
       "class": "network",
       "id": "publica",
       "outbound": "yes"
     },
     {
       "class": "system",
       "cpu.arch": "x86_64",
       "cpu.count_min": 1,
       "disk.0.os.name": "linux",
       "id": "front",
       "memory.size_min": 536870912,
       "net_interface.0.connection": "publica"
     },
     {
       "class": "configure",
       "id": "front",
       "recipes": "\\n---\\n- roles:\\n- { role: 'micafer.hadoop', hadoop_master: 'hadoopmaster', hadoop_type_of_node: 'master' }"
     },
     {
       "class": "deploy",
       "system": "front",
       "vm_number": 1,
       "cloud": "cloud_id"
     },
     {
       "class": "contextualize",
       "items": [
         {
           "configure": "front",
           "system": "front",
           "ctxt_tool": "Ansible"
         }
       ]
     }
   ]

The RADL JSON document is described as a list of objects. Each main object has a field named ``class`` that
described the type of RADL object (ansible, network, system, configure, contextualize or deploy). In case of
ansible, network, system and configure, the must also have and ``id`` field. Then the other fields correspond
to the features described in the RADL object. A particularity of the JSON format is that it does not uses
the comparators (``<=`` or ``>=``) so it is expressed using the ``_min`` and ``_max`` suffixes as show in the
example in ``cpu.count_min`` and ``memory.size_min``. Also the JSON format does not use units in the amount of
memory or disk size, so all these quantities are expresed in bytes.

Currently this format is only supported in the REST API (not in the native XML-RPC one).