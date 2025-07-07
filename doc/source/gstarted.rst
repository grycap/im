Quick Start
===========

UPV already offers :ref:`production-ready IM server endpoints <endpoints>`.
Therefore **there is no need for end users to deploy the IM server**. But if you
need it, please read the manual with the :ref:`instructions to launch the IM service <launch_im>`.

Instead, consider using the :ref:`dashboard`, for easier deployment of virtual infrastructures
(you need an `EGI Checkin OIDC <https://www.egi.eu/services/check-in/>`_ account.)
or the :ref:`client`, for a fully-featured functionality (no registration needed).


IM Client tool
---------------

In these examples we will use the IM-client tool to create, manage and finally destroy a single VM.
You only have to call the install command of the pip tool with the IM-client package::

	$ pip install IM-client

See full reference in :ref:`IM client manual page <inv-client>`.

Authentication file
^^^^^^^^^^^^^^^^^^^
To access the IM service an authentication file must be created. It must have one line per authentication element.
**It must have at least one line with the authentication data for the IM service** and another one for each Cloud
provider the user wants to access. In case of InfrastructureManager credentials you can use any user/password 
pair as the service is free to use by default).

An example to access an OpenNebula and/or an OpenStack site::

    #auth.dat
    id = im; type = InfrastructureManager; username = user; password = pass # mandatory
    id = one; type = OpenNebula; host = osenserver:2633; username = user; password = pass
    id = ost; type = OpenStack; host = https://ostserver:5000; username = user; password = pass; tenant = tenant

See all the options of the auth file described in section :ref:`auth-file`.

RADL basic example
^^^^^^^^^^^^^^^^^^^

The user must describe in an input file the cloud topology. It can be done in the IM native language (RADL) or
the TOSCA standard. In this first example we will show how to launch a single VM using RADL::

   #radlExample.radl
   network net (outbound = 'yes')
   system node (
      cpu.count >= 2 and
      memory.size >= 2G and
      net_interface.0.connection = 'net' and
      disk.0.image.url = 'one://osenserver/image-id'
   )
   deploy node 1

In this RADL the user is requesting 1 VM with at least 2 CPUs and 2 GB of RAM connected with a public IP. Finally
the user must specify the image used to boot the VM with the field `disk.0.image.url`. In this URL the user must
specify an existing image on the Cloud provider where VM will be launched. O.S. image URLs for different
Cloud providers:

   * **one://<server>:<port>/<image-id>**, for OpenNebula;
   * **ost://<server>/<ami-id>**, for OpenStack or EGI;
   * **aws://<region>/<ami-id>**, for Amazon Web Service;
   * **gce://<region>/<image-id>**, for Google Cloud;
   * **azr://<publisher>/<offer>/<sku>/<version>**, for Microsoft Azure; and
   * **appdb://<site_name>/<apc_name>?<vo_name>**, for EGI or OpenStack connector using AppDB info.
   * **docker://<docker_image>**, for Docker images.
   * **fbw://<fns_server>/<image-id>**, for FogBow images.
   * **lin://linode/<image-id>**, for Linode images.
   * **ora://<region>/<image-id>**, for Orange Flexible Engine images.

See full information about RADL language at :ref:`RADL section <radl>`
 More RADL examples are available at the IM GitHub repo `examples folder <https://github.com/grycap/im/tree/master/examples>`_.

TOSCA basic example
^^^^^^^^^^^^^^^^^^^

In case you want to use a TOSCA file to define a similar example to the previous RADL one, the file
will look like this.

.. code-block:: yaml

    #toscaExample.yaml
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


For more information about TOSCA see the :ref:`tosca` section.

Basic IM Client usage
^^^^^^^^^^^^^^^^^^^^^

Now that we have the authentication file and the RADL/TOSCA input file we can create our first infrastructure using
the IM client::

    $ im_client.py -a auth.dat create input_file

By default this command expects the IM server to be hosted on the `localhost` machine. If the server is located at other
host you must specify the `-r` parameters to set the URL of the REST API::

    $ im_client.py -a auth.dat create input_file -r https://im.egi.eu/im

To avoid putting this parameters on all the IM Client calls, create/edit the `im_client.cfg` file with the
default options to use (see all the options at the :ref:`IM client manual page <inv-client>`). Create a file
named im_client.cfg in the current directory with the following contents::

	[im_client]
	restapi_url=https://im.egi.eu/im
	auth_file=auth.dat

From now on, you can omit the ``-a`` and ``-r`` parameters since they are read from this config file.

In this moment the IM client will contact the IM service to start the creation of the infrastructure. It will require
some time depending on the number of VMs or the Cloud provider. Finally when all the VMs are created it will return a
message like the following::

    Connected with: https://im.egi.eu/im
    Infrastructure successfully created with ID: 573c4b0a-67d9-11e8-b75f-0a580af401da

In case of error in the creation of all the VMs it will return an error message describing the errors raised.
If only some of them fails it will return the ID and the user must check the status of the VMs and take the
corresponding decisions. To get the state of the infrastructure, call the `getstate` option of the client::

    $ im_client.py getstate 573c4b0a-67d9-11e8-b75f-0a580af401da

    The infrastructure is in state: running
    VM ID: 0 is in state: running.

You will have to wait until your infrastructure is in the `configured` state. In the meanwhile you can get the output
of the contextualization process to follow the status::

    $ im_client.py getcontmsg 573c4b0a-67d9-11e8-b75f-0a580af401da

    Msg Contextualizator: 

    2018-05-02 14:20:31.816193: Select master VM
    2018-05-02 14:20:31.819775: Wait master VM to boot
    . 
    . 
    . 

This message will show all the steps made by the IM to fully configure the VM including the outputs of all
Ansible processes. Then you can access via SSH to the created VM with the command::

    $ im_client.py ssh 573c4b0a-67d9-11e8-b75f-0a580af401da

And enjoy you customized VM!!

Finally to destroy the infrastructure and all related resources call the `destroy` operation::

    $ im_client.py destroy 573c4b0a-67d9-11e8-b75f-0a580af401da

    Connected with: http://locahost:8899
    Infrastructure successfully destroyed

IM Video Demos
-----------------

There is an Infrastructure Manager YouTube reproduction list with a set of videos with demos
of the functionality of the platform: see section: :ref:`videos`.
