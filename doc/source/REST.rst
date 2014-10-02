IM REST API
===========

Optionally, IM Service can be accessed through a REST(ful) API. The port number
and the security settings are controlled by the options listed in
:ref:`options-rest`.

Every HTTP request must be companied by the header ``AUTHORIZATION`` with
the content of the :ref:`auth-file`, but the lines separated with
"\\n" instead. If the content cannot be parsed successfully, or the user and
password are not valid, it is returned the HTTP error code 401.

Next tables summaries the resources and the HTTP methods available.

+-------------+-----------------------+-------------------+-------------------------+
| HTTP method |   /infrastructure     |   /inf/<infId>    |   /vms/<infId>/<vmId>   |
+=============+=======================+===================+=========================+
| **GET**     | **List** the          | **List** the      | **Get** information     |
|             | infrastructure        | virtual machines  | associated to the       |
|             | IDs.                  | in the            | virtual machine         |
|             |                       | infrastructure    | ``vmId`` in ``infId``.  |
|             |                       | ``infId``         |                         |
+-------------+-----------------------+-------------------+-------------------------+
| **POST**    | **Create** a new      | **Create** a new  |                         |
|             | infrastructure        | virtual machine   |                         |
|             | based on the RADL     | based on the RADL |                         |
|             | posted.               | posted.           |                         |
+-------------+-----------------------+-------------------+-------------------------+
| **PUT**     |                       |                   | **Modify** the virtual  |
|             |                       |                   | machine based on the    |
|             |                       |                   | RADL posted.            |
+-------------+-----------------------+-------------------+-------------------------+
| **DELETE**  |                       | **Undeploy** all  | **Undeploy** the        |
|             |                       | the virtual       | virtual machine.        |
|             |                       | machine in the    |                         |
|             |                       | infrastructure.   |                         |
+-------------+-----------------------+-------------------+-------------------------+
 
+-------------+--------------------+--------------------+----------------------------+
| HTTP method |  /inf/<infId>/stop |  /inf/<infId>/stop |  /inf/<infId>/reconfigure  |
+=============+====================+====================+============================+
| **PUT**     | **Stop** the       | **Start** the      | **Reconfigure** the        |
|             | infrastructure.    | infrastructure.    | infrastructure.            |
+-------------+--------------------+--------------------+----------------------------+


GET ``http://imserver.com/infrastructure``
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 409

   Return a list of URIs referencing the infrastructures associated to the IM
   user.

POST ``http://imserver.com/infrastructure``
   :body: ``RADL document``
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 409

   Create and configure an infrastructure with the requirements specified in
   the RADL document of the body contents. If success, it is returned the
   URI of the new infrastructure.  

GET ``http://imserver.com/inf/<infId>``
   :Content-type: application/json
   :ok response: 200 OK
   :fail response: 409

   Return a JSON object with two elements: 
    * vm_list: list of URIs referencing the virtual machines associated to the
     infrastructure with ID ``infId``.
    * cont_out: contextualization message.

POST ``http://imserver.com/inf/<infId>``
   :body: ``RADL document``
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 409

   Add the resources specified in the body contents to the infrastructure with ID
   ``infId``. The RADL restrictions are the same as in
   :ref:`RPC-XML AddResource <addresource-xmlrpc>`. If success, it is returned
   a list of URIs of the new virtual machines.

PUT ``http://imserver.com/inf/<infId>/stop``
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 409

   Perform the ``stop`` action in all the virtual machines in the
   the infrastructure with ID ``infID``:
   
PUT ``http://imserver.com/inf/<infId>/start``
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 409

   Perform the ``start`` action in all the virtual machines in the
   the infrastructure with ID ``infID``:
   
PUT ``http://imserver.com/inf/<infId>/reconfigure``
   :input fields: ``radl`` (compulsory)
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 409

   Perform the ``reconfigure`` action in all the virtual machines in the
   the infrastructure with ID ``infID``. It updates the configuration 
   of the infrastructure as indicated in ``radl``. The RADL restrictions 
   are the same as in :ref:`RPC-XML Reconfigure <reconfigure-xmlrpc>`. If no
   RADL are specified, the contextualization process is stated again.

DELETE ``http://imserver.com/inf/<infId>``
   :ok response: 200 OK
   :fail response: 409

   Undeploy the virtual machines associated to the infrastructure with ID
   ``infId``.

GET ``http://imserver.com/vms/<infId>/<vmId>``
   :Content-type: application/json
   :ok response: 200 OK
   :fail response: 409

   Return information about the virtual machine with ID ``vmId`` associated to
   the infrastructure with ID ``infId``. See the details of the output in
   :ref:`GetVMInfo <GetVMInfo-xmlrpc>`.

PUT ``http://imserver.com/vms/<infId>/<vmId>``
   :body: ``RADL document``
   :ok response: 200 OK
   :fail response: 409

   Change the features of the virtual machine with ID ``vmId`` in the
   infrastructure with with ID ``infId``, specified by the RADL document specified
   in the body contents.

DELETE ``http://imserver.com/vms/<infId>/<vmId>``
   :ok response: 200 OK
   :fail response: 409

   Undeploy the virtual machine with ID ``vmId`` associated to the
   infrastructure with ID ``infId``.
