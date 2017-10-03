IM REST API
===========

Optionally, IM Service can be accessed through a REST(ful) API. The port number
and the security settings are controlled by the options listed in
:ref:`options-rest`.

Every HTTP request must be companied by the header ``AUTHORIZATION`` with
the content of the :ref:`auth-file`, but putting all the elements in one line
using "\\n" as separator. If the content cannot be parsed successfully, or the user and
password are not valid, it is returned the HTTP error code 401.

Next tables summaries the resources and the HTTP methods available.

+-------------+------------------------------------+------------------------------------+-------------------------------------------+
| HTTP method | /infrastructures                   | /infrastructures/<infId>           | /infrastructures/<infId>/vms/<vmId>       |
+=============+====================================+====================================+===========================================+
| **GET**     | | **List** the infrastructure IDs. | | **List** the virtual machines    | | **Get** information associated to the   |
|             |                                    | | in the infrastructure ``infId``  | | virtual machine ``vmId`` in ``infId``.  |
+-------------+------------------------------------+------------------------------------+-------------------------------------------+
| **POST**    | | **Create** a new infrastructure  | | **Create** a new virtual machine |                                           |
|             | | based on the RADL posted         | | based on the RADL posted.        |                                           |
+-------------+------------------------------------+------------------------------------+-------------------------------------------+
| **PUT**     |                                    |                                    | | **Modify** the virtual machine based on |
|             |                                    |                                    | | the RADL posted.                        |
+-------------+------------------------------------+------------------------------------+-------------------------------------------+
| **DELETE**  |                                    | | **Undeploy** all the virtual     | | **Undeploy** the virtual machine.       |
|             |                                    | | machines in the infrastructure.  |                                           |
+-------------+------------------------------------+------------------------------------+-------------------------------------------+
 
+-------------+--------------------------------+---------------------------------+---------------------------------------+
| HTTP method | /infrastructures/<infId>/stop  | /infrastructures/<infId>/start  | /infrastructures/<infId>/reconfigure  |
+=============+================================+=================================+=======================================+
| **PUT**     | | **Stop** the infrastructure. | | **Start** the infrastructure. | | **Reconfigure** the infrastructure. |
+-------------+--------------------------------+---------------------------------+---------------------------------------+

+-------------+-----------------------------------------------------+----------------------------------------------------+
| HTTP method | /infrastructures/<infId>/vms/<vmId>/<property_name> | /infrastructures/<infId>/<property_name>           |
+=============+=====================================================+====================================================+
| **GET**     | | **Get** the specified property ``property_name``  | | **Get** the specified property ``property_name`` |
|             | | associated to the machine ``vmId`` in ``infId``.  | | associated to the infrastructure ``infId``.      |
|             | | It has one special property: ``contmsg``.         | | It has three properties: ``contmsg``, ``radl``,  |
|             |                                                     | | ``state`` and ``outputs``.                       |
+-------------+-----------------------------------------------------+----------------------------------------------------+

+-------------+-----------------------------------------------+------------------------------------------------+
| HTTP method | /infrastructures/<infId>/vms/<vmId>/stop      | /infrastructures/<infId>/start                 |
+=============+===============================================+================================================+
| **PUT**     | | **Stop** the machine ``vmId`` in ``infId``. | | **Start** the machine ``vmId`` in ``infId``. |
+-------------+-----------------------------------------------+------------------------------------------------+

+-------------+--------------------------------------------------------------+
| HTTP method | /infrastructures/<infId>/vms/<vmId>/disks/<diskNum>/snapshot |
+=============+==============================================================+
| **PUT**     | | **Create** an snapshot of the disk ``diskNum`` of the      |
|             | | machine ``vmId`` in ``infId``                              |
+-------------+--------------------------------------------------------------+

The error message returned by the service will depend on the ``Accept`` header of the request:

* text/plain: (default option).
* application/json: The request has a "Accept" header with value "application/json". In this case the format will be::

    {
      "message": "Error message text",
      "code" : 400
     }
     
* text/html: The request has a "Accept" with value to "text/html". 

GET ``http://imserver.com/infrastructures``
   :Response Content-type: text/uri-list or application/json
   :ok response: 200 OK
   :fail response: 401, 400

   Return a list of URIs referencing the infrastructures associated to the IM
   user. The result is JSON format has the following format::

    {
      "uri-list": [
         { "uri" : "http://server.com:8800/infrastructures/inf_id1" },
         { "uri" : "http://server.com:8800/infrastructures/inf_id2" }
       ] 
    }

POST ``http://imserver.com/infrastructures``
   :body: ``RADL document``
   :body Content-type: text/plain or application/json
   :Response Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 401, 400, 415

   Create and configure an infrastructure with the requirements specified in
   the RADL document of the body contents (in plain RADL or in JSON formats).
   If success, it is returned the URI of the new infrastructure.  
   The result is JSON format has the following format::

    {
      "uri" : "http://server.com:8800/infrastructures/inf_id
    }

GET ``http://imserver.com/infrastructures/<infId>``
   :Response Content-type: text/uri-list or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Return a list of URIs referencing the virtual machines associated to the infrastructure with ID ``infId``.
   The result is JSON format has the following format::

    {
      "uri-list": [
         { "uri" : "http://server.com:8800/infrastructures/inf_id/vms/0" },
         { "uri" : "http://server.com:8800/infrastructures/inf_id/vms/1" }
       ] 
    }
    
GET ``http://imserver.com/infrastructures/<infId>/<property_name>``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 404, 400, 403

   Return property ``property_name`` associated to the infrastructure with ID ``infId``. It has three properties:
      :``outputs``: in case of TOSCA documents it will return a JSON object with the outputs of the TOSCA document. 
      :``contmsg``: a string with the contextualization message. 
      :``radl``: a string with the original specified RADL of the infrastructure. 
      :``state``: a JSON object with two elements:
      
         :``state``: a string with the aggregated state of the infrastructure. 
         :``vm_states``: a dict indexed with the VM ID and the value the VM state.

   The result is JSON format has the following format::
   
    {
      ["radl"|"state"|"contmsg"|"outputs"]: <property_value>
    }

POST ``http://imserver.com/infrastructures/<infId>``
   :body: ``RADL document``
   :body Content-type: text/plain or application/json
   :input fields: ``context`` (optional)
   :Response Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400, 415

   Add the resources specified in the body contents (in plain RADL or in JSON formats)
   to the infrastructure with ID ``infId``. The RADL restrictions are the same as in
   :ref:`RPC-XML AddResource <addresource-xmlrpc>`. If success, it is returned
   a list of URIs of the new virtual machines. The ``context`` parameter is optional and 
   is a flag to specify if the contextualization step will be launched just after the VM
   addition. Accetable values: yes, no, true, false, 1 or 0. If not specified the flag is set to True. 
   The result is JSON format has the following format::

    {
      "uri-list": [
         { "uri" : "http://server.com:8800/infrastructures/inf_id/vms/2" },
         { "uri" : "http://server.com:8800/infrastructures/inf_id/vms/3" }
       ] 
    }

PUT ``http://imserver.com/infrastructures/<infId>/stop``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Perform the ``stop`` action in all the virtual machines in the
   the infrastructure with ID ``infID``. If the operation has been performed 
   successfully the return value is an empty string.
   
PUT ``http://imserver.com/infrastructures/<infId>/start``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Perform the ``start`` action in all the virtual machines in the
   the infrastructure with ID ``infID``. If the operation has been performed 
   successfully the return value is an empty string.
   
PUT ``http://imserver.com/infrastructures/<infId>/reconfigure``
   :body: ``RADL document``
   :body Content-type: text/plain or application/json
   :input fields: ``vm_list`` (optional)
   :Response Content-type: text/plain
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400, 415

   Perform the ``reconfigure`` action in all the virtual machines in the
   the infrastructure with ID ``infID``. It updates the configuration 
   of the infrastructure as indicated in the body contents (in plain RADL or in JSON formats). 
   The RADL restrictions are the same as in :ref:`RPC-XML Reconfigure <reconfigure-xmlrpc>`. If no
   RADL are specified, the contextualization process is stated again.
   The ``vm_list`` parameter is optional and is a coma separated list of
   IDs of the VMs to reconfigure. If not specified all the VMs will be reconfigured. 
   If the operation has been performed successfully the return value is an empty string.

DELETE ``http://imserver.com/infrastructures/<infId>``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Undeploy the virtual machines associated to the infrastructure with ID
   ``infId``. If the operation has been performed successfully 
   the return value is an empty string.

GET ``http://imserver.com/infrastructures/<infId>/vms/<vmId>``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Return information about the virtual machine with ID ``vmId`` associated to
   the infrastructure with ID ``infId``. The returned string is in RADL format,
   either in plain RADL or in JSON formats.
   See more the details of the output in :ref:`GetVMInfo <GetVMInfo-xmlrpc>`.
   The result is JSON format has the following format::
   
    {
      ["radl"|"state"|"contmsg"]: "<property_value>"
    }
   
GET ``http://imserver.com/infrastructures/<infId>/vms/<vmId>/<property_name>``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Return property ``property_name`` from to the virtual machine with ID 
   ``vmId`` associated to the infrastructure with ID ``infId``. It also has one
   special property ``contmsg`` that provides a string with the contextualization message
   of this VM. The result is JSON format has the following format::

    {
      "<property_name>": "<property_value>"
    }

PUT ``http://imserver.com/infrastructures/<infId>/vms/<vmId>``
   :body: ``RADL document``
   :body Content-type: text/plain or application/json
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400, 415

   Change the features of the virtual machine with ID ``vmId`` in the
   infrastructure with with ID ``infId``, specified by the RADL document specified
   in the body contents (in plain RADL or in JSON formats). If the operation has 
   been performed successfully the return value the return value is an RADL document 
   with the VM properties modified (also in plain RADL or in JSON formats).
   The result is JSON format has the following format::
   
    {
      "radl": <RADL_JSON_DATA>
    }

DELETE ``http://imserver.com/infrastructures/<infId>/vms/<vmId>``
   :input fields: ``context`` (optional)
   :Response Content-type: text/plain
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Undeploy the virtual machine with ID ``vmId`` associated to the
   infrastructure with ID ``infId``. If  ``vmId`` is a comma separated list of 
   VM IDs, all the VMs of this list will be undeployed.  The ``context`` parameter is optional and 
   is a flag to specify if the contextualization step will be launched just after the VM
   addition. Accetable values: yes, no, true, false, 1 or 0. If not specified the flag is set to True.
   If the operation has been performed successfully the return value is an empty string.

PUT ``http://imserver.com/infrastructures/<infId>/vms/<vmId>/start``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Perform the ``start`` action in the virtual machine with ID 
   ``vmId`` associated to the infrastructure with ID ``infId``.
   If the operation has been performed successfully the return value is an empty string.

PUT ``http://imserver.com/infrastructures/<infId>/vms/<vmId>/stop``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Perform the ``stop`` action in the virtual machine with ID 
   ``vmId`` associated to the infrastructure with ID ``infId``.
   If the operation has been performed successfully the return value is an empty string.

GET ``http://imserver.com/version``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 400

   Return the version of the IM service. The result is JSON format has the following format::

    {
      "version": "1.4.4"
    }

PUT ``http://imserver.com/infrastructures/<infId>/vms/<vmId>/disks/<diskNum>/snapshot``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :input fields: ``image_name`` (mandatory), ``auto_delete`` (optional)
   :fail response: 401, 403, 404, 400

   Create a snapshot of the specified ``diskNum`` in the VM ``vmId``
   of the infrastructure with ID ``infId`. 
   
   The ``autoDelete`` flag
   specifies that the snapshot will be deleted when the infrastructure is
   destroyed. If the operation has been performed successfully the return
   value is the image url of the new created image in IM format
   (see disk.<diskId>.image.url format in RADL).