IM XML-RPC API
==============

IM Service can be accessed through the API that
follows the `XML-RPC specification <http://xmlrpc.scripting.com/spec>`_. The
port number and the security settings are controlled by the options listed in
:ref:`options-xmlrpc`.

The last parameter in every call refers
to the credentials for the IM Service, the VMRC and cloud providers.
Every credential is represented as a struct datatype, whose keys and values are
described in :ref:`auth-file`. Then the parameter is an array of these
structs.

.. _IM-States:

IM valid States
----------------

List of valid VM and infrastructure states:

   The ``state`` can be

   * ``pending``, launched, but still in initialization stage;
   * ``running``, created successfully and running, but still in the configuration stage;
   * ``configured``, running and contextualized;
   * ``unconfigured``, running but not correctly contextualized;
   * ``stopped``, stopped or suspended;
   * ``off``, shutdown or removed from the infrastructure;
   * ``failed``, an error happened during the launching; or
   * ``unknown``, unable to obtain the status.
   * ``deleting``, in the deletion process.

   The next figure shows a state diagram of virtual machine status. This figure is illustrative
   as if may differ in case of Cloud Providers.

   .. digraph:: stategraph
   
      layout=dot;
      node [shape=circle, fontsize=10, fixedsize=true, height=.9, weight=.9];
      "pending" -> "running" -> "configured" -> "off" ;
      "pending" -> "failed";
      "running" -> "unconfigured";
      "configured" -> "stopped";
      "configured" -> "running";
      "stopped" -> "pending";
      "configured" -> "deleting";

Methods
-------

This is the list of method names:

``GetInfrastructureList``
   :parameter 0: ``auth``: array of structs
   :parameter 1: ``filter``: (optional, default value None) string
   :ok response: [true, ``infIds``: array of integers]
   :fail response: [false, ``error``: string]

   Return the ID associated to the infrastructure created by the user.
   In case of using a filter it will be used as a regular expression to search
   in the RADL or TOSCA used to create the infrastructure.

``CreateInfrastructure``
   :parameter 0: ``radl``: string
   :parameter 1: ``auth``: array of structs
   :parameter 2: ``async``: (optional, default value False) boolean
   :ok response: [true, ``infId``: integer]
   :fail response: [false, ``error``: string]

   Create and configure an infrastructure with the requirements specified in
   the RADL document passed as string. Return the ID associated to the created
   infrastructure. If ``async`` is set to ``True`` the call will not wait the VMs
   to be created.

``GetInfrastructureInfo``
   :parameter 0: ``infId``: integer
   :parameter 1: ``auth``: array of structs
   :ok response: [true, ``vm_list``: array of integers]
   :fail response: [false, ``error``: string]

   Return a list of IDs associated to the virtual machines of the
   infrastructure with ID ``infId``.
   
``GetInfrastructureContMsg``
   :parameter 0: ``infId``: integer
   :parameter 1: ``auth``: array of structs
   :parameter 2: ``headeronly``: (optional, default value False) boolean
   :ok response: [true, ``cont_out``: string]
   :fail response: [false, ``error``: string]

   Return the contextualization log associated to the infrastructure with ID ``infId``. 
   In case of ``headeronly`` flag is set to True. Only the initial part of the infrastructure
   contextualization log will be returned (without any VM contextualization log).
   
``GetInfrastructureState``
   :parameter 0: ``infId``: integer
   :parameter 1: ``auth``: array of structs
   :ok response: [true, struct(``state``: string, ``vm_states``: dict of integer (VM ID) to string (VM state)]
   :fail response: [false, ``error``: string]

   Return the aggregated state associated to the 
   infrastructure with ID ``infId``. 

``GetInfrastructureRADL``
   :parameter 0: ``infId``: integer
   :parameter 1: ``auth``: array of structs
   :ok response: [true, ``radl_info``: string]
   :fail response: [false, ``error``: string]

   Return a string with the original RADL specified to create the 
   infrastructure with ID ``infId``.

.. _GetVMInfo-xmlrpc:

``GetVMInfo``
   :parameter 0: ``infId``: integer
   :parameter 1: ``vmId``: string
   :parameter 2: ``auth``: array of structs
   :ok response: [true, ``radl_info``: string]
   :fail response: [false, ``error``: string]

   Return a string with information about the virtual machine with ID ``vmId``
   in the infrastructure with ID ``infId``. The returned string is in RADL format.
   
``GetVMProperty``
   :parameter 0: ``infId``: integer
   :parameter 1: ``vmId``: string
   :parameter 2: ``property_name``: string
   :parameter 3: ``auth``: array of structs
   :ok response: [true, ``property_value``: string]
   :fail response: [false, ``error``: string]

   Return a string with the specific property of the RADL information about the virtual
   machine with ID ``vmId`` in the infrastructure with ID ``infId``. It enables to get a single
   property of the RADL of the function :ref:`GetVMInfo <GetVMInfo-xmlrpc>`. 
   
``GetVMContMsg``
   :parameter 0: ``infId``: integer
   :parameter 1: ``vmId``: string
   :parameter 2: ``auth``: array of structs
   :ok response: [true, ``cont_msg``: string]
   :fail response: [false, ``error``: string]

   Return a string with contextualization log of the virtual machine with ID ``vmId``
   in the infrastructure with ID ``infId``.

   
``AlterVM``
   :parameter 0: ``infId``: integer
   :parameter 1: ``vmId``: string
   :parameter 2: ``radl``: string
   :parameter 3: ``auth``: array of structs
   :ok response: [true, struct(``info``: string, ``cloud``: string, ``state``: string)]
   :fail response: [false, ``error``: string]

   Change the features of the virtual machine with ID ``vmId`` in the
   infrastructure with with ID ``infId``, specified by the RADL ``radl``.
   Return a struct with information about the nodified virtual machine, like 
   :ref:`GetVMInfo <GetVMInfo-xmlrpc>`.

   .. todo::

      Bug: specify the contrains of RADL used for modifying features of
      already deployed virtual machine.
      Proposal: define a special keyword, for instance ``you``, that should be
      used as id in the ``system`` sentences in RADL used in AlterVM request::

         system you ( memory.size = 1G )


``DestroyInfrastructure``
   :parameter 0: ``infId``: integer
   :parameter 1: ``auth``: array of structs
   :parameter 2: ``force``: (optional, default value False) boolean
   :parameter 3: ``async``: (optional, default value False) boolean
   :ok response: [true, string of length zero]
   :fail response: [false, ``error``: string]

   Undeploy all the virtual machines associated to the infrastructure with ID
   ``infId``. The ``force`` parameter is optional and is a flag to specify that the infra
   will be from the IM although not all resources are deleted. If ``async`` is set to ``True``
   the call will not wait the infrastructure to be deleted.

.. _AddResource-xmlrpc:

``AddResource``
   :parameter 0: ``infId``: integer
   :parameter 1: ``radl``: string
   :parameter 2: ``auth``: array of structs
   :parameter 3: ``context``: (optional, default value True) boolean
   :ok response: [true, ``infId``: integer]
   :fail response: [false, ``error``: string]

   Add the resources specified in ``radl`` to the infrastructure with ID
   ``infId``. The last  ``context`` parameter is optional and is a flag to
   specify if the contextualization step will be launched just after the VM
   addition. The default value is True. 
   The ``deploy`` instructions in the ``radl`` must refer to
   *systems* already defined. If all the *systems* defined in ``radl`` are
   new, they will be added. Otherwise the new *systems* defined will be
   ignored. All the *systems* specified in the ``deploy`` must be specified
   in the ``radl``. If they has been already defined only a reference is needed.
   This is a simple example to deploy one new VM from an alreay defined system::

      network public 
      system node
      deploy node 1


``RemoveResource``
   :parameter 0: ``infId``: integer
   :parameter 1: ``vmIds``: string
   :parameter 2: ``auth``: array of structs
   :parameter 3: ``context``: (optional, default value True) boolean
   :ok response: [true, integer]
   :fail response: [false, ``error``: string]

   Updeploy the virtual machines with IDs in ``vmIds`` associated to the
   infrastructure with ID ``infId``. The different virtual machine IDs in
   ``vmIds`` are separated by commas. On success it returns the number of
   VMs that have been undeployed. The last  ``context`` parameter is optional
   and is a flag to specify if the contextualization step will be launched
   just after the VM addition. The default value is True. 

.. _StopInfrastructure-xmlrpc:

``StopInfrastructure``
   :parameter 0: ``infId``: integer
   :parameter 1: ``auth``: array of structs
   :ok response: [true, string of length zero]
   :fail response: [false, ``error``: string]

   Stop (but do not undeploy) all the virtual machines associated to the
   infrastructure with ID ``infId``. They can resume by
   :ref:`StartInfrastructure <StartInfrastructure-xmlrpc>`.

.. _StopVM-xmlrpc:

``StopVM``
   :parameter 0: ``infId``: integer
   :parameter 1: ``vmId``: integer
   :parameter 2: ``auth``: array of structs
   :ok response: [true, string of length zero]
   :fail response: [false, ``error``: string]

   Stop (but do not undeploy) the specified virtual machine with ID ``vmId`` 
   associated to the infrastructure with ID ``infId``. They can resume by
   :ref:`StartVM <StartVM-xmlrpc>`.

.. _StartInfrastructure-xmlrpc:

``StartInfrastructure``
   :parameter 0: ``infId``: integer
   :parameter 1: ``auth``: array of structs
   :ok response: [true, string of length zero]
   :fail response: [false, ``error``: string]

   Resume all the virtual machines associated to the
   infrastructure with ID ``infId``, previously stopped by
   :ref:`StopInfrastructure <stopinfrastructure-xmlrpc>`.

.. _StartVM-xmlrpc:

``StartVM``
   :parameter 0: ``infId``: integer
   :parameter 1: ``vmId``: integer
   :parameter 2: ``auth``: array of structs
   :ok response: [true, string of length zero]
   :fail response: [false, ``error``: string]

   Resume the specified virtual machine with ID ``vmId`` associated to the
   infrastructure with ID ``infId``, previously stopped by
   :ref:`StopInfrastructure <stopinfrastructure-xmlrpc>` or
   :ref:`StopVM <stopvm-xmlrpc>`.

.. _RebootVM-xmlrpc:

``RebootVM``
   :parameter 0: ``infId``: integer
   :parameter 1: ``vmId``: integer
   :parameter 2: ``auth``: array of structs
   :ok response: [true, string of length zero]
   :fail response: [false, ``error``: string]

   Reboot the specified virtual machine with ID ``vmId`` associated to the
   infrastructure with ID ``infId``.

.. _Reconfigure-xmlrpc:

``Reconfigure``
   :parameter 0: ``infId``: integer
   :parameter 1: ``radl``: string
   :parameter 2: ``auth``: array of structs
   :parameter 3: ``vm_list``: (optional, default value None) array of integers
   :ok response: [true, string of length zero]
   :fail response: [false, ``error``: string]

   Update the infrastructure with ID ``infId`` using the *configuration
   sections* in the RADL ``radl``. Some virtual machines associated to the
   infrastructure may be reconfigured. The last  ``vm_list`` parameter is optional
   and is a list integers specifying the IDs of the VMs to reconfigure. The default
   value is None that means that all the VMs will be reconfigured. 

.. _ExportInfrastructure-xmlrpc:

``ExportInfrastructure``
   :parameter 0: ``infId``: integer
   :parameter 1: ``delete``: bool
   :parameter 2: ``auth``: array of structs
   :ok response: [true, string]
   :fail response: [false, ``error``: string]

   Return the serialization of the infrastructure with ID ``infId``. If
   ``delete`` is true, the infrastructure is marked as ``deleted`` after
   that (and no machine is undeployed). This function is useful to transfer
   the control of an infrastructure to other IM server. See 
   :ref:`ImportInfrastructure <ImportInfrastructure-xmlrpc>`.

.. _ImportInfrastructure-xmlrpc:

``ImportInfrastructure``
   :parameter 0: ``strInf``: string
   :parameter 1: ``auth``: array of structs
   :ok response: [true, ``infId``: integer]
   :fail response: [false, ``error``: string]

   Take control of the infrastructure serialized in ``strInf`` and return
   the ID associated in the server. See
   :ref:`ExportInfrastructure <ExportInfrastructure-xmlrpc>`.

.. _CreateDiskSnapshot-xmlrpc:

``CreateDiskSnapshot``
   :parameter 0: ``infId``: integer
   :parameter 1: ``vmId``: integer
   :parameter 2: ``diskNum``: integer
   :parameter 3: ``imageName``: string
   :parameter 4: ``autoDelete``: boolean   
   :parameter 5: ``auth``: array of structs
   :ok response: [true, string]
   :fail response: [false, ``error``: string]

   Create a snapshot of the specified ``diskNum`` in the VM ``vmId``
   of the infrastructure with ID ``infId`. The ``autoDelete`` flag
   specifies that the snapshot will be deleted when the infrastructure is
   destroyed. It returns the image url of the new created image in IM format
   (see disk.<diskId>.image.url format in RADL).