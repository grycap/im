
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

   network <network_id> (<features>)

   system <system_id> (<features>)

   configure <configure_id> (<Ansible recipes>)

   contextualize [max_time] (
     system <system_id> configure <configure_id> [step <num>]
     ...
   )

   deploy <system_id> <num> [<cloud_id>] 

The keywords ``network``, ``system`` and ``configure`` assign some *features*
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


Network Features
----------------

Under the keyword ``network`` there are the features describing a Local Area
Network (LAN) that some virtual machines can share in order to communicate
to themselves and to other external networks.
The supported features are:

``outbound = yes|no``
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

   The default value is ``''``.
   
``provider_id = <string>``
   Indicate the name of the network in a specific Cloud provider.
   The default value is ``''``.

System Features
---------------

Under the keyword ``system`` there are the features describing a virtual
machine.  The supported features are:

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

``instance_type``
   Set the instance type name of this VM. 

``disk.<diskId>.<feature>``
   Features under this prefix refer to virtual storage devices attached to
   the virtual machine. ``disk.0`` refers to system boot device.

``disk.<diskId>.image.url = <url>``
   Set the source of the disk image. The URI designates the cloud provider:

   * ``one://<server>:<port>/<image-id>``, for OpenNebula;
   * ``ost://<server>:<port>/<ami-id>``, for OpenStack;
   * ``aws://<region>/<ami-id>``, for Amazon Web Service;
   * ``gce://<region>/<image-id>``, for Google Cloud;
   * ``azr://<image-id>``, for Microsoft Azure; and
   * ``<fedcloud_endpoint_url>/<image_id>``, for FedCloud OCCI connector.
   * ``docker://<docker_image>``, for Docker images.
   * ``fbw://<fogbow_image>``, for FogBow images.

   Either ``disk.0.image.url`` or ``disk.0.image.name`` must be set.

``disk.<diskId>.image.name = <string>``
   Set the source of the disk image by its name in the VMRC server.
   Either ``disk.0.image.url`` or ``disk.0.image.name`` must be set.

``disk.<diskId>.type = swap|iso|filesystem``
   Set the type of the image.

``disk.<diskId>.device = <string>``
   Set the device name, if it is disk with no source set.

   .. todo::

      ``disk.<diskId>.device = <string>`` does not have a clear description.

``disk.<diskId>.size = <positive integer value>B|K|M|G``
   Set the size of the disk, if it is a disk with no source set.

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
   Set a valid username and password to access the operating system.

``disk.0.os.credentials.public_key = <string>`` and ``disk.0.os.credentials.private_key = <string>``
   Set a valid public-private keypair to access the operating system.

``disk.<diskId>.applications contains (name=<string>, version=<string>, preinstalled=yes|no)``
   Set that the disk must have installed the application with name ``name``.
   Optionally a version can be specified. Also if ``preinstalled`` is ``yes``
   the application must have already installed; and if ``no``, the application
   can be installed during the contextualization of the virtual machine if it
   is not installed.
   
   There are a **special** type of application that starts with ``ansible.modules.``.
   These applications installs `ansible roles <https://docs.ansible.com/playbooks_roles.html>`_
   that can be used in the ``configure`` sections of the RADL.
   There are three type of ansible modules:
   
   * `Ansible Galaxy <https://galaxy.ansible.com/>`_ roles: ``ansible.modules.micafer.hadoop``: The user
     specifies the name of the galaxy role afther the string ``ansible.modules.``
   * HTTP URL: ``ansible.modules.http://server.com/hadoop.tgz``: The user specifies an HTTP URL afther the
     the string ``ansible.modules.``. The file must be compressed. it must contain only one directory 
     with the same name of the compressed file (without extension) with the ansible role content.
   * Git Repo: ``ansible.modules.git://github.com/micafer/ansible-role-hadoop|hadoop``: The user specifies a Git repo
     (using the git scheme in the URL) afther the string ``ansible.modules.``. Furthermore the 
     user must specify the rolname using a | afther the url, ash shown in the example.


Parametric Values
-----------------
RADL documents can use parametric values to be requested to the user in launch time.
It make easy to launch different infrastructures without modifying the RADL document,
only changing a set of values in launch time.

This values are specified with the following syntax::
  
	@input.<variable_name>@

In the following example the user will be asked for specifing the ``CPUs`` and the  ``NumNodes``
variables (in the CLI and in the Web Interface)::

   system node (
      cpu.count = @input.CPUs@ and
      memory.size >= 512M
   )
   deploy node @input.NumNodes@

Configure Recipes
-----------------

Contextualization recipes are specified under the keyword ``configure``.
Only Ansible recipes are supported currently. They are enclosed between the
tags ``@begin`` and ``@end``, like that::

   configure add_user1 (
   @begin
   ---
     - tasks:
       - user: name=user1   password=1234
   @end
   )

To easy some contextualization tasks, IM publishes a set of variables that 
can be accessed by the recipes and have information about the virtual machine.

``IM_NODE_HOSTNAME``
   Hostname of the virtual machine (without the domain).

``IM_NODE_DOMAIN``
   Domain name of the virtual machine.

``IM_NODE_FQDN``
   Complete FQDN of the virtual machine.

``IM_NODE_NUM``
   The value of the substitution ``#N#`` in the virtual machine.

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


Including roles of Ansible Galaxy
---------------------------------

To include a role available in Ansible Galaxy a special application requirement
must be added: it must start with: "ansible.modules" as shown in the following
example. In this case the Ansible Galaxy role called "micafer.hadoop" will be installed::

   network net (outbound = "yes")

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

   network net (outbound = "yes")

   system node_ubuntu (
      cpu.arch = 'i686' and
      memory.size >= 512M and
      net_interface.0.connection = "net" and
      net_interface.0.dns_name = "node-#N#" and
      disk.0.os.name = "linux" and
      disk.0.os.flavour = "ubuntu" and
      disk.0.os.version >= "12.04" and
      disk.0.applications contains (name="toncat")
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

