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

This is the list of method names:

``GetInfrastructureList``
   :parameter 0: ``auth``: array of structs
   :ok response: [true, ``infIds``: array of integers]
   :fail response: [false, ``error``: string]

   Return the ID associated to the infrastructure created by the user.

``CreateInfrastructure``
   :parameter 0: ``radl``: string
   :parameter 1: ``auth``: array of structs
   :ok response: [true, ``infId``: integer]
   :fail response: [false, ``error``: string]

   Create and configure an infrastructure with the requirements specified in
   the RADL document passed as string. Return the ID associated to the created
   infrastructure.

``GetInfrastructureInfo``
   :parameter 0: ``infId``: integer
   :parameter 1: ``auth``: array of structs
   :ok response: [true, struct(``cont_out``: string, ``vm_list``: array of integers)]
   :fail response: [false, ``error``: string]

   Return in ``vm_list`` a list of IDs associated to the virtual machine of the
   infrastructure with ID ``infId``. If the contextualization process has
   finished, ``cont_out`` may have a message indicating why the process failed.

.. _GetVMInfo-xmlrpc:

``GetVMInfo``
   :parameter 0: ``infId``: integer
   :parameter 1: ``vmId``: string
   :parameter 2: ``auth``: array of structs
   :ok response: [true, struct(``info``: string, ``cloud``: string, ``state``: string)]
   :fail response: [false, ``error``: string]

   Return a string with information about the virtual machine with ID ``vmId``
   in the infrastructure with ID ``infId``. The returned string is in RADL format.

   The ``state`` can be

   * ``pending``, launched, but still in initialization stage;
   * ``running``, created successfully and running, but still in the configuration stage;
   * ``configured``, running and contextualized;
   * ``stopped``, stopped or suspended;
   * ``off``, shutdown or removed from the infrastructure;
   * ``failed``, an error happened during the launching or the contextualization; or
   * ``unknown``, unable to obtain the status.

   The next figure shows a state diagram of virtual machine status.

   .. digraph:: stategraph
   
      layout=fdp;
      node [shape=circle, fontsize=8, fixedsize=true, height=.9, weight=.9];
      "pending" -> "running" -> "configured" -> "off" ;
      "pending" -> "failed";
      "running" -> "failed";
      "configured" -> "stopped";
      "configured" -> "running";
      "stopped" -> "running";
   
``AlterVM``
   :parameter 0: ``infId``: integer
   :parameter 1: ``vmId``: string
   :parameter 2: ``radl``: string
   :parameter 3: ``auth``: array of structs
   :ok response: [true, struct(``info``: string, ``cloud``: string, ``state``: string)]
   :fail response: [false, ``error``: string]

   Change the features of the virtual machine with ID ``vmId`` in the
   infrastructure with with ID ``infId``, specified by the RADL ``radl``.
   Return a struct with information about the virtual machine, like 
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
   :ok response: [true, string of length zero]
   :fail response: [false, ``error``: string]

   Undeploy all the virtual machines associated to the infrastructure with ID
   ``infId``.

.. _AddResource-xmlrpc:

``AddResource``
   :parameter 0: ``infId``: integer
   :parameter 1: ``radl``: string
   :parameter 2: ``auth``: array of structs
   :ok response: [true, ``infId``: integer]
   :fail response: [false, ``error``: string]

   Add the resources specified in ``radl`` to the infrastructure with ID
   ``infId``. The ``deploy`` instructions in the ``radl`` must refer to
   *systems* already defined. If all the *systems* defined in ``radl`` are
   new, they will be added. Otherwise the new *systems* defined will be
   ignored.

``RemoveResource``
   :parameter 0: ``infId``: integer
   :parameter 1: ``vmIds``: string
   :parameter 2: ``auth``: array of structs
   :ok response: [true, ``infId``: integer]
   :fail response: [false, ``error``: string]

   Updeploy the virtual machines with IDs in ``vmIds`` associated to the
   infrastructure with ID ``infId``. The different virtual machine IDs in
   ``vmIds`` are separated by commas.

.. _StopInfrastructure-xmlrpc:

``StopInfrastructure``
   :parameter 0: ``infId``: integer
   :parameter 1: ``auth``: array of structs
   :ok response: [true, string of length zero]
   :fail response: [false, ``error``: string]

   Stop (but do not undeploy) all the virtual machines associated to the
   infrastructure with ID ``infId``. They can resume by
   :ref:`StartInfrastructure <StartInfrastructure-xmlrpc>`.

.. _StartInfrastructure-xmlrpc:

``StartInfrastructure``
   :parameter 0: ``infId``: integer
   :parameter 1: ``auth``: array of structs
   :ok response: [true, string of length zero]
   :fail response: [false, ``error``: string]

   Resume all the virtual machines associated to the
   infrastructure with ID ``infId``, previously stopped by
   :ref:`StopInfrastructure <stopinfrastructure-xmlrpc>`.

.. _Reconfigure-xmlrpc:

``Reconfigure``
   :parameter 0: ``infId``: integer
   :parameter 1: ``radl``: string
   :parameter 2: ``auth``: array of structs
   :ok response: [true, string of length zero]
   :fail response: [false, ``error``: string]

   Update the infrastructure with ID ``infId`` using the *configuration
   sections* in the RADL ``radl``. Some virtual machines associated to the
   infrastructure may be reconfigured.

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
