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

+-------------+------------------------+-------------------------------+-----------------------------------------+
| HTTP method |   /infrastructures     |   /infrastructures/<infId>    |   /infrastructures/<infId>/vms/<vmId>   |
+=============+========================+===============================+=========================================+
| **GET**     | **List** the           | **List** the virtual machines | **Get** information associated to the   |
|             | infrastructure         | in the infrastructure         | virtual machine ``vmId`` in ``infId``.  |
|             | IDs.                   | ``infId``                     |                                         |
+-------------+------------------------+-------------------------------+-----------------------------------------+
| **POST**    | **Create** a new       | **Create** a new virtual      |                                         |
|             | infrastructure         | machine based on the RADL     |                                         |
|             | based on the RADL      | posted.                       |                                         |
|             | posted.                |                               |                                         |
+-------------+------------------------+-------------------------------+-----------------------------------------+
| **PUT**     |                        |                               | **Modify** the virtual machine based on |
|             |                        |                               | the RADL posted.                        |
+-------------+------------------------+-------------------------------+-----------------------------------------+
| **DELETE**  |                        | **Undeploy** all the virtual  | **Undeploy** the virtual machine.       |
|             |                        | machines in the               |                                         |
|             |                        | infrastructure.               |                                         |
+-------------+------------------------+-------------------------------+-----------------------------------------+
 
+-------------+--------------------------------+---------------------------------+----------------------------------------+
| HTTP method |  /infrastructures/<infId>/stop |  /infrastructures/<infId>/start |  /infrastructures/<infId>/reconfigure  |
+=============+================================+=================================+========================================+
| **PUT**     | **Stop** the infrastructure.   | **Start** the infrastructure.   | **Reconfigure** the infrastructure.    |
+-------------+--------------------------------+---------------------------------+----------------------------------------+

+-------------+--------------------------------------------------------+--------------------------------------------------+
| HTTP method |   /infrastructures/<infId>/vms/<vmId>/<property_name>  |     /infrastructures/<infId>/<property_name>     | 
+=============+========================================================+==================================================+
| **GET**     | **Get** the specified property ``property_name``       | **Get** the specified property ``property_name`` |
|             | associated to the machine ``vmId`` in ``infId``        | associated to the infrastructure ``infId``.      |
|             |                                                        | It has two properties: ``contmsg`` and ``radl``  |
+-------------+--------------------------------------------------------+--------------------------------------------------+

GET ``http://imserver.com/infrastructures``
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 401, 400

   Return a list of URIs referencing the infrastructures associated to the IM
   user.

POST ``http://imserver.com/infrastructures``
   :body: ``RADL document``
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 401, 400

   Create and configure an infrastructure with the requirements specified in
   the RADL document of the body contents. If success, it is returned the
   URI of the new infrastructure.  

GET ``http://imserver.com/infrastructures/<infId>``
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 401, 404, 400

   Return a list of URIs referencing the virtual machines associated to the
   infrastructure with ID ``infId``.
    
GET ``http://imserver.com/infrastructures/<infId>/<property_name>``
   :Content-type: application/json
   :ok response: 200 OK
   :fail response: 401, 404, 400, 403

   Return property ``property_name`` associated to the infrastructure with ID ``infId``.
   It has two properties:
   	:``contmsg``: a string with the contextualization message.
   	:``radl``: a string with the original specified RADL of the infrastructure.

POST ``http://imserver.com/infrastructures/<infId>``
   :body: ``RADL document``
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 401, 404, 400

   Add the resources specified in the body contents to the infrastructure with ID
   ``infId``. The RADL restrictions are the same as in
   :ref:`RPC-XML AddResource <addresource-xmlrpc>`. If success, it is returned
   a list of URIs of the new virtual machines.

PUT ``http://imserver.com/infrastructures/<infId>/stop``
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 401, 404, 400

   Perform the ``stop`` action in all the virtual machines in the
   the infrastructure with ID ``infID``:
   
PUT ``http://imserver.com/infrastructures/<infId>/start``
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 401, 404, 400

   Perform the ``start`` action in all the virtual machines in the
   the infrastructure with ID ``infID``:
   
PUT ``http://imserver.com/infrastructures/<infId>/reconfigure``
   :input fields: ``radl`` (compulsory)
   :Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 401, 404, 400

   Perform the ``reconfigure`` action in all the virtual machines in the
   the infrastructure with ID ``infID``. It updates the configuration 
   of the infrastructure as indicated in ``radl``. The RADL restrictions 
   are the same as in :ref:`RPC-XML Reconfigure <reconfigure-xmlrpc>`. If no
   RADL are specified, the contextualization process is stated again.

DELETE ``http://imserver.com/infrastructures/<infId>``
   :ok response: 200 OK
   :fail response: 401, 404, 400

   Undeploy the virtual machines associated to the infrastructure with ID
   ``infId``.

GET ``http://imserver.com/infrastructures/<infId>/vms/<vmId>``
   :Content-type: text/plain
   :ok response: 200 OK
   :fail response: 401, 404, 400

   Return information about the virtual machine with ID ``vmId`` associated to
   the infrastructure with ID ``infId``. The returned string is in RADL format. 
   See more the details of the output in :ref:`GetVMInfo <GetVMInfo-xmlrpc>`.
   
GET ``http://imserver.com/infrastructures/<infId>/vms/<vmId>/<property_name>``
   :Content-type: text/plain
   :ok response: 200 OK
   :fail response: 401, 404, 400

   Return property ``property_name`` from to the virtual machine with ID 
   ``vmId`` associated to the infrastructure with ID ``infId``.

PUT ``http://imserver.com/infrastructures/<infId>/vms/<vmId>``
   :body: ``RADL document``
   :ok response: 200 OK
   :fail response: 401, 404, 400

   Change the features of the virtual machine with ID ``vmId`` in the
   infrastructure with with ID ``infId``, specified by the RADL document specified
   in the body contents.

DELETE ``http://imserver.com/infrastructures/<infId>/vms/<vmId>``
   :ok response: 200 OK
   :fail response: 401, 404, 400

   Undeploy the virtual machine with ID ``vmId`` associated to the
   infrastructure with ID ``infId``.
