Quick Start
===========

Launch IM Service
-----------------

To launch an instance of the Infrastructure Manager the easiest solution is to use the Docker image named 
`grycap/im` that has been created using the default configuration. 

To launch the IM service using docker::

  $ sudo docker run -d -p 8899:8899 -p 8800:8800 --name im grycap/im

More information about this image can be found here: `https://registry.hub.docker.com/u/grycap/im/ <https://registry.hub.docker.com/u/grycap/im/>`_.

IM Client tools
---------------

To access the IM service two client tools can be used (apart from the two APIs):

* The IM client: You only have to call the install command of the pip tool with the IM-client package::

	$ pip install IM-client

  See full reference in IM Client :ref:`inv-client`.

* The IM web: To launch the IM Web portal in the same machine where we have previously launched the IM service use
  the followiing docker command::

    $ sudo docker run -d -p 80:80 --name im-web --link im:im grycap/im-web

  Then you can access the im-web interface using the following url: `http://localhost/im-web`.
  
  See full manual in IM Web :ref:`use-web`.

In this first examples we will use the IM-client tool to create, manage and finally destroy a single VM.

Authentication file
^^^^^^^^^^^^^^^^^^^
To access the IM service an authenticatio file must be created. It must have one line per authentication element.
It must have at least one line with the authentication data for the IM service and another one for the Cloud/s
provider/s the user want to access.

An example to access an OpenNebula and/or an OpenStack site::

    id = im; type = InfrastructureManager; username = user; password = pass
    id = one; type = OpenNebula; host = osenserver:2633; username = user; password = pass
    id = ost; type = OpenStack; host = https://ostserver:5000; username = user; password = pass; tenant = tenant

See all the options of the auth file are describe in section :ref:`auth-file`.

RADL basic example
^^^^^^^^^^^^^^^^^^^
Then the user must describe in a input file the cloud topology. It can be done in the IM native language (RADL) or
the TOSCA standard. In this first example we will so how to launch a single VM using RADL::

   network net (outbound = 'yes')
   system node (
      cpu.count >= 2 and
      memory.size >= 2G and
      net_interface.0.connection = 'net' and
      disk.0.image.url = 'one://someserver.com/123'
   )
   deploy node 1

In this RADL user is requesting 1 VM with at least 2 CPUs and 2 GB of RAM connected with a public IP. Finally
the user must specify the image used to boot the VM with the field `disk.0.image.url`. In this URL the user must
specify an existing image on the cluod provider where VM will be launched. O.S. image URLs for different
Cloud providers:

   * **one://<server>:<port>/<image-id>**, for OpenNebula;
   * **ost://<server>/<ami-id>**, for OpenStack;
   * **aws://<region>/<ami-id>**, for Amazon Web Service;
   * **gce://<region>/<image-id>**, for Google Cloud;
   * **azr://<publisher>/<offer>/<sku>/<version>**, for Microsoft Azure; and
   * **<fedcloud_endpoint_url>/<image_id>**, for FedCloud OCCI connector.
   * **appdb://<site_name>/<apc_name>?<vo_name>**, for FedCloud OCCI connector using AppDB info (from ver. 1.6.0).
   * **docker://<docker_image>**, for Docker images.
   * **fbw://<fns_server>/<image-id>**, for FogBow images.

See full information about RADL language at :ref:`radl`. More RADL examples are available at the IM GitHub repo
`examples folder <https://github.com/grycap/im/tree/master/examples>`_.

TOSCA basic example
^^^^^^^^^^^^^^^^^^^

In case of you want to use a TOSCA file to define a similar example to the previous RADL one the file
should be like that::

    tosca_definitions_version: tosca_simple_yaml_1_0

    imports:
    - indigo_custom_types: https://raw.githubusercontent.com/indigo-dc/tosca-types/master/custom_types.yaml

    topology_template:
    
    node_templates:
    
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

    outputs:
        node_ip:
        value: { get_attribute: [ simple_node, public_address, 0 ] }
        node_creds:
        value: { get_attribute: [ simple_node, endpoint, credential, 0 ] }

For more information about TOSCA see the 
`OASIS TOSCA Simple Profile in YAML Version 1.0 <http://docs.oasis-open.org/tosca/TOSCA-Simple-Profile-YAML/v1.0/TOSCA-Simple-Profile-YAML-v1.0.html>`_.
The TOSCA support has been developed under de framework of the `INDIGO DataCloud EU project <http://http://www.indigo-datacloud.eu>`_.
You can see some input examples at 
`https://github.com/indigo-dc/tosca-types/tree/master/examples <https://github.com/indigo-dc/tosca-types/tree/master/examples>`_.

Basic IM Client usage
^^^^^^^^^^^^^^^^^^^^^

Now that we have the authentication file and the RADL input file we can create our first infrastructure using
the IM client::

    $ im_client.py -a auth.dat create input_file

By default this command expects the IM to be hosted on the `localhost` machine. If the server is located at other
host you must specify the `-u` or `-r` parameters to set the URL of the XML-RPC API or REST API respectively::

    $ im_client.py -a auth.dat create input_file -r http://imhost.com:8800
    $ im_client.py -a auth.dat create input_file -u http://imhost.com:8899

To avoid putting this parameters on all the IM Cleint calls you can create an `im_client.cfg` file with the
default options to use. See all the options at the client manual page: :ref:`inv-client`.

In this moment the IM client with contact the IM service to start the creation of the infrastructure. It will require
some time depending on the number of VMs or the cloud provider. Finally when all the VMs are created it will retun a
message like that::

    Connected with: http://locahost:8899
    Infrastructure successfully created with ID: 573c4b0a-67d9-11e8-b75f-0a580af401da

In case of error in the creation of all the VMs it will return an error message describing the errors raised.
If only some of them fails it will return the ID and the user must check the status of the VMs and take the
corresponding decissions. To get the state of of the infrastructure call the `getstate` option of the client::

    $ im_client.py -a auth.dat getstate 573c4b0a-67d9-11e8-b75f-0a580af401da

    The infrastructure is in state: running
    VM ID: 0 is in state: running.

You have to wait untill your infrastructure is the state `configured`. In the meanwhile you can get the output
of the contextualization process to follow the status::

    $ im_client.py -a auth.dat getcontmsg 573c4b0a-67d9-11e8-b75f-0a580af401da

    Msg Contextualizator: 

    2018-05-02 14:20:31.816193: Select master VM
    2018-05-02 14:20:31.819775: Wait master VM to boot
    . 
    . 
    . 

This message will show all the steps made by the IM to fully configure the VM including the outputs of all
Ansible processes. Then you can access via SSH the created VM with the command::

    $ im_client.py -a auth.dat ssh 573c4b0a-67d9-11e8-b75f-0a580af401da

And Enjoy you customized VM!!

Finally to destroy the infrastructure and all the related resources call the `destroy` operation::

    $ im_client.py -a auth.dat destroy 573c4b0a-67d9-11e8-b75f-0a580af401da

    Connected with: http://locahost:8899
    Infrastructure successfully destroyed

IM Video Demos
-----------------

There is an Infrastructure Manager YouTube reproduction list with a set of videos with demos
of the functionality of the platform: see section: :ref:`videos`.
