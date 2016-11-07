# Infrastructure Manager - Service Reference Card

**Functional description:**  
   IM is a tool that deploys complex and customized virtual infrastructures on IaaS Cloud deployments (such as AWS, OpenStack, etc.). It eases the access and the usability of IaaS clouds by automating the VMI (Virtual Machine Image) selection, deployment, configuration, software installation, monitoring and update of the virtual infrastructure.  
   It supports APIs from a large number of virtual platforms, making user applications cloud-agnostic. In addition it integrates a contextualization system to enable the installation and configuration of all the user required applications providing the user with a fully functional infrastructure.  
   This version evolved in the INDIGO-Datacloud project (https://www.indigo-datacloud.eu/). It is used by the [INDIGO Orchestrator](https://github.com/indigo-dc/orchestrator) to contact Cloud sites to finally deploy the VMs/containers.

**Services running:**
   * im: Im daemon


**Configuration:**
  * Adjust the installation path by setting the IMDAEMON variable at `/etc/init.d/im` to the path where the IM im_service.py file is installed (e.g. /usr/local/im/im_service.py), or set the name of the script file (im_service.py) if the file is in the PATH (pip puts the im_service.py file in the PATH as default).

  * Check the parameters in `$IM_PATH/etc/im.cfg` or `/etc/im/im.cfg`. Please pay attention to the next configuration variables, as they are the most important

    * DATA_FILE - must be set to the full path where the IM data file will be created (e.g. `/usr/local/im/inf.dat`). Be careful if you have two different instances of the IM service running in the same machine!!.

    * DATA_DB - must be set to a full URL of a MySQL databse to store the IM data (e.g. mysql://username:password@server/db_name). If this value is set it overwrites the DATA_FILE value.

  * CONTEXTUALIZATION_DIR - must be set to the full path where the IM contextualization files are located. In case of using pip installation the default value is correct (`/usr/share/im/contextualization`) in case of installing from sources set to $IM_PATH/contextualization (e.g. /usr/local/im/contextualization)

**Logfile locations (and management) and other useful audit information:**
   * *IM log:* The log file is defined in the LOG_FILE variable of the im.cfg file. The default value is `/var/log/im/im.log`.

**Open ports needed:**
   * Default ports used by the IM:
     * XML-RPC API:
        * 8899
     * REST API:
        * 8800

**Where is service state held (and can it be rebuilt):**  
   Configuration information is stored in a data file or data base. Check the configuration section for more info about the files.

**Cron jobs:**
   None

**Security information**
   * Security is disabled by default. Please notice that someone with local network access can "sniff" the traffic and get the messages with the IM with the authorization data with the cloud providers.
   * Security can be activated both in the XMLRPC and REST APIs. Setting this variables:
    * XMLRCP_SSL = True  
    or
    * REST_SSL = True

    And then set the variables: XMLRCPSSL or RESTSSL to your certificates paths.

**Location of reference documentation:**
   [IM on Gitbook](https://indigo-dc.gitbooks.io/im/content/)
