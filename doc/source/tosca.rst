.. _tosca:

TOSCA
======

The Infrastructure Manager supports the definition of Cloud topologies using `OASIS TOSCA Simple Profile in YAML Version 1.0 <http://docs.oasis-open.org/tosca/TOSCA-Simple-Profile-YAML/v1.0/TOSCA-Simple-Profile-YAML-v1.0.html>`_.

The TOSCA support has been developed under de framework of the `INDIGO DataCloud EU project <http://http://www.indigo-datacloud.eu>`_.
You can see some input examples at 
`https://github.com/indigo-dc/tosca-types/tree/master/examples <https://github.com/indigo-dc/tosca-types/tree/master/examples>`_.

Basic example
^^^^^^^^^^^^^

This TOSCA file describes a cloud topology with 2 VM with at least 2 CPUs and
2 GB of RAM and 40 GB of root disk, connected with a public IP, using an Ubuntu
20.04 image. As outputs, the TOSCA file will return the public IP of the VM and
the SSH credentials to access it::

    tosca_definitions_version: tosca_simple_yaml_1_0

    imports:
    - indigo_custom_types: https://raw.githubusercontent.com/indigo-dc/tosca-types/master/custom_types.yaml

    topology_template:
    
      node_templates:
    
        simple_node:
          type: tosca.nodes.Compute
          scalable:
            properties:
              count: 2
          capabilities:
            endpoint:
              properties:
                network_name: PUBLIC
            host:
              properties:
                num_cpus: 2
                mem_size: 2 GB
                disk_size: 40 GB
            os:
              properties:
                type: linux
                distribution: ubuntu
                version: 22.04

      outputs:
        node_ip:
          value: { get_attribute: [ simple_node, public_address, 0 ] }
        node_creds:
          value: { get_attribute: [ simple_node, endpoint, credential, 0 ] }

Setting VMI URI
^^^^^^^^^^^^^^^^

As in RADL you can set an specific URI identifying the VMI to use in the VM.
The URI format is the same used in RADL (:ref:`radl_system`). In this case
the type must be changed to ``tosca.nodes.indigo.Compute`` (the Compute normative
type does not support the ``os image`` property), and the image property must
be added in the ``os`` capability::

    ...

        simple_node:
          type: tosca.nodes.indigo.Compute
          capabilities:
            endpoint:
              properties:
                network_name: PUBLIC
            host:
              properties:
                num_cpus: 2
                mem_size: 2 GB
            os:
              properties:
                image: one://someserver.com/123

    ...

Advanced Compute host properties
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``tosca.nodes.indigo.Compute`` custom type add a new set of advanced features to the
host properties, enabling the request of GPUs and
`Intel SGX <https://www.intel.com/content/www/us/en/architecture-and-technology/software-guard-extensions.html>`_ CPU support
in the compute node::

    ...

    simple_node:
      type: tosca.nodes.indigo.Compute
      capabilities:
        host:
          properties:
            num_cpus: 2
            mem_size: 2 GB
            num_gpus: 1
            gpu_vendor: nvidia
            gpu_model: Tesla V100
            sgx: false

    ...

Network properties
^^^^^^^^^^^^^^^^^^

Basic properties
-----------------

The easiest way to specify network requirements of the Compute node is sing the endpoint capability properties.
For example the following example the compute node requests for a public IP::

    ...
        simple_node:
          type: tosca.nodes.Compute
          capabilities:
            endpoint:
              properties:
                network_name: PUBLIC
    ...

Possible values of the ``network_name`` endpoint property:

  * PRIVATE: The Compute node does not requires a public IP. **This is the default behavior if no
    endpoint capability is defined**.
  * PUBLIC: The Compute node requires a public IP.
  * Network provider ID: As the `provider_id` network property in RADL
    It defines the name of the network in a specific Cloud provider
    (see :ref:`_radl_network`):

Furthermore the endpoint capability has a set of additional properties
to set the DNS name of the node or the set of ports to be externally accesible::

    ...

      capabilities:
        endpoint:
          properties:
            dns_name: slurmserver
            network_name: PUBLIC
            ports:
              http_port:
                protocol: tcp
                source: 80
                remote_cidr: 0.0.0.0/0 # optional

    ...

Advanced properties
-------------------

In case that you need a more detailed definition of the networks, you can use the 
``tosca.nodes.network.Network`` and ``tosca.nodes.network.Port`` TOSCA normative types.
In this way you can define the set of networks needed in your topology using the ports to 
link the networks with the Compute nodes::

    ...

    pub_network:
      type: tosca.nodes.network.Network
      properties:
        network_type: public

    server_pub_port:
      type: tosca.nodes.network.Port
      properties:
        order: 1
        ip_address: X.X.X.X # optional to request specific IP
      requirements:
        - binding: simple_node
        - link: pub_network

    priv_network:
      type: tosca.nodes.network.Network
      properties:
        network_type: private

    server_port:
      type: tosca.nodes.network.Port
      properties:
        order: 0
      requirements:
        - binding: simple_node
        - link: priv_network

    ...


Custom defined Port type ``tosca.nodes.indigo.network.Port`` has a set of additional properties:

  * dns_name: DNS name to assing to the network interface.
  * additional_ip: (OpenStack specific) Additional IP to be allowed to the network interface.
  * additional_dns_names: Additional DNS names.


Software Components
^^^^^^^^^^^^^^^^^^^

IM enable to use Ansible playbooks as implementation scripts. Furthermore it enables to specify
Ansible roles (``tosca.artifacts.AnsibleGalaxy.role``) and collections (``tosca.artifacts.AnsibleGalaxy.collections``)
to be installed and used in the playbooks::

    ...

    software:
      type: tosca.nodes.SoftwareComponent
      artifacts:
        docker_role:
          file: grycap.docker
          type: tosca.artifacts.AnsibleGalaxy.role
      requirements:
        - host: simple_node 
      interfaces:
        Standard:
          configure:
            implementation: https://raw.githubusercontent.com/grycap/ec3/tosca/tosca/artifacts/dummy.yml
            inputs:
              some_input: { get_input: some_input }

    ...

Storage
^^^^^^^

IM enables the definition of BlockStorage volumes to be attached to the compute nodes.
In this example we can see how to define a volume of 10GB to be attached to the compute node
and mounted in the path /mnt/disk. The device parameter is optional and it is only needed in
some cloud providers, in general is better not to add it::

    ...

    simple_node:
      type: tosca.nodes.Compute

      ...

      requirements:
        - local_storage:
            node: my_storage
            relationship:
              type: AttachesTo
              properties:
                location: /mnt/disk
                device: hdb # optional

    my_storage:
      type: tosca.nodes.BlockStorage
      properties:
        size: 10GB

    ...

Policies & groups
^^^^^^^^^^^^^^^^^

IM enables the definition of the specific cloud provider where the Compute nodes will be deployed in an hybrid deployment.
For example, in the following code we assume that we have defined three computes nodes (compute_one, compute_two and compute_three).
We can create a placement group with two of them (compute_one and compute_two) and then set a placement policy with a cloud_id
(that must be defined in the :ref:`auth-file`), and create a second placement policy where we can set a different cloud provider
and, optionally, an availability zone::

    ...

    groups:
      my_placement_group:
        type: tosca.groups.Root
        members: [ compute_one, compute_two ]

    policies:
      - deploy_group_on_cloudid:
        type: tosca.policies.Placement
        properties: { cloud_id: cloudid1 }
        targets: [ my_placement_group ]

      - deploy_on_cloudid:
        type: tosca.policies.Placement
        properties: { cloud_id: cloudid2, availability_zone: some_zone }
        targets: [ compute_three ]

    ...

Advanced Output values
^^^^^^^^^^^^^^^^^^^^^^^

The ``tosca.nodes.indigo.Compute`` node type adds a new
attribute named: ``ansible_output``. It is a map that has one element per each IM
configuration step, so you can access it by name. The steps have the keyword
``tasks`` that is also a map that has one element per ansible task. In this case
it can bes accessed using the task name as defined in the playbook. Finally
there is an ``output`` keyword that returns the output of the task.
In most of the cases the task is a ``debug`` ansible task that shows anything you
want to return.

In the following example the specified task was a debug ansible task that shows the
value of a internal defined value::

    ...

      outputs:
        node_ip:
          value: { get_attribute: [ front, ansible_output, lrms_front_end_front_conf_front, tasks, 'grycap.nomad : nomad_secret_id', output ] }
