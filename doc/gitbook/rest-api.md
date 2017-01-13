# IM REST API


The IM Service can be accessed through a REST(ful) API.

Every HTTP request must be accompanied by the header `AUTHORIZATION` with
the content of the [auth-file](http://imdocs.readthedocs.io/en/devel/client.html#authorization-file), but putting all the elements in one line
using "\\n" as separator. If the content of some of the values has a also a "new line" character it must be replaced by a "\\\\n" as separator.
If the content cannot be parsed successfully,
or the user and password are not valid, it is returned the HTTP error
code 401.

In the special case of an IM configured as "Single site" support standard HTTP `AUTHORIZATION` header can be used:
* Basic: With a cloud provider that supports simple user/password authentication.
* Bearer: With a cloud provider that supports INDIGO IAM token authentication.

Next tables summaries the resources and the HTTP methods available.

| HTTP method | /infrastructures | /infrastructures/&lt;infId&gt; | /infrastructures/&lt;infId&gt;/vms/&lt;vmId&gt; |
| -- | -- | -- | -- |
| **GET** | List the infrastructure IDs.| List the virtual machines in the infrastructure infId | Get information associated to the virtual machine vmId in infId. |
| **POST** | Create a new infrastructure based on the RADL posted | Create a new virtual machine based on the RADL posted. | |
| **PUT** | | | Modify the virtual machine based on the RADL posted. |
| **DELETE** | | Undeploy all the virtual machines in the infrastructure. | Undeploy the virtual machine. |


| HTTP method | /infrastructures/&lt;infId&gt;/stop | /infrastructures/&lt;infId&gt;/start | /infrastructures/&lt;infId&gt;/reconfigure |
| -- | -- | -- | -- |
| **PUT** | Stop the infrastructure. | Start the infrastructure. | Reconfigure the infrastructure. |


| HTTP method | /infrastructures/&lt;infId&gt;/vms/&lt;vmId&gt;/&lt;property_name&gt; | /infrastructures/&lt;infId&gt;/&lt;property_name&gt; |
| -- | -- | -- |
| **GET** | Get the specified property property_name associated to the machine vmId in infId. It has one special property: contmsg. | Get the specified property property_name associated to the infrastructure infId. It has four properties: contmsg, radl, state and outputs. |


| HTTP method | /infrastructures/&lt;infId&gt;/vms/&lt;vmId&gt;/stop | /infrastructures/&lt;infId&gt;/vms/&lt;vmId&gt;/start |
| -- | -- | -- |
| **PUT** | Stop the machine vmId in infId. | Start the machine vmId in infId. |



The error message returned by the service will depend on the `Accept`
header of the request:

-   text/plain: (default option).
-   application/json: The request has a "Accept" header with
    value "application/json". In this case the format will be:

```json
        {
          "message": "Error message text",
          "code" : 400
         }
```

-   text/html: The request has a "Accept" with value to "text/html".

**GET** `http://imserver.com/infrastructures`:

  * Response Content-type: text/uri-list or application/json

  * ok response: 200 OK

  * fail response: 401, 400

  Return a list of URIs referencing the infrastructures associated to
  the IM user. The result is JSON format has the following format:

```json
      {
        "uri-list": [
           { "uri" : "http://server.com:8800/infrastructures/inf_id1" },
           { "uri" : "http://server.com:8800/infrastructures/inf_id2" }
         ]
      }
```

**POST** `http://imserver.com/infrastructures`:   

  * body: `RADL or TOSCA document`

  * body Content-type: text/yaml, text/plain or application/json

  * Response Content-type: text/uri-list

  * ok response: 200 OK

  * fail response: 401, 400, 415

  Create and configure an infrastructure with the requirements
  specified in the RADL or TOSCA document of the body contents (RADL in plain text
  or in JSON formats). If success, it is returned the URI of the new
  infrastructure. The result is JSON format has the following format:

```json
      {
        "uri" : "http://server.com:8800/infrastructures/inf_id
      }
```

**GET** `http://imserver.com/infrastructures/<infId>`:   

  * Response Content-type: text/uri-list or application/json

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400

  Return a list of URIs referencing the virtual machines associated to
  the infrastructure with ID `infId`. The result is JSON format has
  the following format:

```json
      {
        "uri-list": [
           { "uri" : "http://server.com:8800/infrastructures/inf_id/vms/0" },
           { "uri" : "http://server.com:8800/infrastructures/inf_id/vms/1" }
         ]
      }
```

**GET** `http://imserver.com/infrastructures/<infId>/<property_name>`:   

  * Response Content-type: text/plain or application/json

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400, 403

  Return property `property_name` associated to the infrastructure with ID `infId`. It has three properties:

      * `outputs`:  in case of TOSCA documents it will return a JSON object with
      the outputs of the TOSCA document.

      * `contmsg`: a string with the contextualization message.

      * `radl`: a string with the original specified RADL of the infrastructure.

      * `state`: a JSON object with two elements:

        * `state`: a string with the aggregated state of the infrastructure.

        * `vm_states`: a dict indexed with the VM ID and the value the VM state.

  The result is JSON format has the following format:

```json
      {
        ["radl"|"state"|"contmsg"|"outputs"]: <property_value>
      }
```

**POST** `http://imserver.com/infrastructures/<infId>`:   

  * body: `RADL or TOSCA document`

  * body Content-type: text/yaml or text/plain or application/json

  * input fields: `context` (optional)

  * Response Content-type: text/uri-list

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400, 415

  Add the resources specified in the body contents (in TOSCA, plain RADL or
  in JSON formats) to the infrastructure with ID `infId`. The RADL
  restrictions are the same as in RPC-XML AddResource &lt;addresource-xmlrpc&gt;.
  
  In case of TOSCA a whole TOSCA document is expected. In case of new template is
  added to the TOSCA document or the ``count`` of a node is increased new nodes
  will be added to de infrastructure. In case decreasing the number of the ``count``
  scalable property of a node a ``removal_list`` property has to be added to specify
  the ID of the VM to delete (see an example [here](https://github.com/indigo-dc/im/blob/master/test/files/tosca_remove.yml)).
  
  If success, it is returned a list of URIs of the new virtual machines.
  The `context` parameter is optional and is a flag to specify if the
  contextualization step will be launched just after the VM addition.
  Acceptable values: yes, no, true, false, 1 or 0. If not specified the
  flag is set to True. The result is JSON format has the following
  format:

```json
      {
        "uri-list": [
           { "uri" : "http://server.com:8800/infrastructures/inf_id/vms/2" },
           { "uri" : "http://server.com:8800/infrastructures/inf_id/vms/3" }
         ]
      }
```

**PUT** `http://imserver.com/infrastructures/<infId>/stop`:   

  * Response Content-type: text/plain or application/json

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400

  Perform the `stop` action in all the virtual machines in the the
  infrastructure with ID `infID`. If the operation has been performed
  successfully the return value is an empty string.

**PUT** `http://imserver.com/infrastructures/<infId>/start`:   

  * Response Content-type: text/plain or application/json

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400

  Perform the `start` action in all the virtual machines in the the
  infrastructure with ID `infID`. If the operation has been performed
  successfully the return value is an empty string.

**PUT** `http://imserver.com/infrastructures/<infId>/reconfigure`:   

  * body: `RADL document`

  * body Content-type: text/plain or application/json

  * input fields: `vm_list` (optional)

  * Response Content-type: text/plain

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400, 415

  Perform the `reconfigure` action in all the virtual machines in the
  the infrastructure with ID `infID`. It updates the configuration of
  the infrastructure as indicated in the body contents (in plain RADL
  or in JSON formats). The RADL restrictions are the same as
  in RPC-XML Reconfigure &lt;reconfigure-xmlrpc&gt;. If no RADL are
  specified, the contextualization process is stated again. The
  `vm_list` parameter is optional and is a coma separated list of IDs
  of the VMs to reconfigure. If not specified all the VMs will be
  reconfigured. If the operation has been performed successfully the
  return value is an empty string.

**DELETE** `http://imserver.com/infrastructures/<infId>`:   

  * Response Content-type: text/plain or application/json

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400

  Undeploy the virtual machines associated to the infrastructure with
  ID `infId`. If the operation has been performed successfully the
  return value is an empty string.

**GET** `http://imserver.com/infrastructures/<infId>/vms/<vmId>`:   

  * Response Content-type: text/plain or application/json

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400

  Return information about the virtual machine with ID `vmId`
  associated to the infrastructure with ID `infId`. The returned
  string is in RADL format, either in plain RADL or in JSON formats.
  See more the details of the output in
  GetVMInfo &lt;GetVMInfo-xmlrpc&gt;. The result is JSON format has
  the following format:

```json
      {
        ["radl"|"state"|"contmsg"]: "<property_value>"
      }
```

**GET** `http://imserver.com/infrastructures/<infId>/vms/<vmId>/<property_name>`:   

  * Response Content-type: text/plain or application/json

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400

  Return property `property_name` from to the virtual machine with ID
  `vmId` associated to the infrastructure with ID `infId`. It also has
  one special property `contmsg` that provides a string with the
  contextualization message of this VM. The result is JSON format has
  the following format:

```json
      {
        "<property_name>": "<property_value>"
      }
```

**PUT** `http://imserver.com/infrastructures/<infId>/vms/<vmId>`:   

  * body: `RADL document`

  * body Content-type: text/plain or application/json

  * Response Content-type: text/plain or application/json

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400, 415

  Change the features of the virtual machine with ID `vmId` in the
  infrastructure with with ID `infId`, specified by the RADL document
  specified in the body contents (in plain RADL or in JSON formats).
  If the operation has been performed successfully the return value
  the return value is an RADL document with the VM properties modified
  (also in plain RADL or in JSON formats). The result is JSON format
  has the following format:

```json
      {
        "radl": <RADL_JSON_DATA>
      }
```

**DELETE** `http://imserver.com/infrastructures/<infId>/vms/<vmId>`:   

  * input fields: `context` (optional)

  * Response Content-type: text/plain

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400

  Undeploy the virtual machine with ID `vmId` associated to the
  infrastructure with ID `infId`. If `vmId` is a comma separated list
  of VM IDs, all the VMs of this list will be undeployed. The
  `context` parameter is optional and is a flag to specify if the
  contextualization step will be launched just after the VM addition.
  Acceptable values: yes, no, true, false, 1 or 0. If not specified the
  flag is set to True. If the operation has been performed
  successfully the return value is an empty string.

**PUT** `http://imserver.com/infrastructures/<infId>/vms/<vmId>/start`:   

  * Response Content-type: text/plain or application/json

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400

  Perform the `start` action in the virtual machine with ID `vmId`
  associated to the infrastructure with ID `infId`. If the operation
  has been performed successfully the return value is an empty string.

**PUT** `http://imserver.com/infrastructures/<infId>/vms/<vmId>/stop`:   

  * Response Content-type: text/plain or application/json

  * ok response: 200 OK

  * fail response: 401, 403, 404, 400

  Perform the `stop` action in the virtual machine with ID `vmId`
  associated to the infrastructure with ID `infId`. If the operation
  has been performed successfully the return value is an empty string.

**GET** `http://imserver.com/version`:   

  * Response Content-type: text/plain or application/json

  * ok response: 200 OK

  * fail response: 400

  Return the version of the IM service. The result is JSON format has
  the following format:

```json
      {
        "version": "1.4.4"
      }
```
