# IM - Infrastructure Manager

* Build Status [![Build Status](http://jenkins.i3m.upv.es/buildStatus/icon?job=indigo/im-unit)](http://jenkins.i3m.upv.es/job/indigo/job/im-unit/) [![Build Status](https://jenkins.indigo-datacloud.eu:8080/buildStatus/icon?job=Pipeline-as-code/im/master)](https://jenkins.indigo-datacloud.eu:8080/job/Pipeline-as-code/job/im/job/master)

IM is a tool that deploys complex and customized virtual infrastructures on IaaS
Cloud deployments (such as AWS, OpenStack, etc.). It eases the access and the
usability of IaaS clouds by automating the VMI (Virtual Machine Image)
selection, deployment, configuration, software installation, monitoring and
update of the virtual infrastructure. It supports APIs from a large number of virtual
platforms, making user applications cloud-agnostic. In addition it integrates a
contextualization system to enable the installation and configuration of all the
user required applications providing the user with a fully functional
infrastructure.

This version evolved in the projects INDIGO-Datacloud (https://www.indigo-datacloud.eu/) and DEEP – Hybrid DataCloud
(https://deep-hybrid-datacloud.eu/). It is used by the [INDIGO Orchestrator](https://github.com/indigo-dc/orchestrator) to contact Cloud sites to finally deploy the VMs/containers.

New features added in both projects:

+ Support for TOSCA 1.0 YAML specification with the custom node types described in https://github.com/indigo-dc/tosca-types/blob/master/custom_types.yaml
+ Support for the Identity and Access Management Service (IAM).
+ Support for the Token Translation Service (TTS) to support IAM authetication on OpenNebula Clouds.
+ Improvements to access OpenStack Clouds that support IAM.
+ Improvements to enable hybrid deployments.

Read the documentation and more at http://www.grycap.upv.es/im.

There is also an Infrastructure Manager YouTube reproduction list with a set of videos with demos
of the functionality of the platform: https://www.youtube.com/playlist?list=PLgPH186Qwh_37AMhEruhVKZSfoYpHkrUp.

## 1 DOCKER IMAGE

The recommended option to use the Infrastructure Manager service is using the available docker image.
A Docker image named `indigodatacloud/im` has been created to make easier the deployment of an IM service using the
default configuration. Information about this image can be found here: https://registry.hub.docker.com/u/indigodatacloud/im/.

How to launch the IM service using docker::

```sh
$ sudo docker run -d -p 8899:8899 -p 8800:8800 --name im indigodatacloud/im
```

To make the IM data persistent you also have to specify a persistent location for the IM database using the IM_DATA_DB environment variable and adding a volume::

```sh
$ sudo docker run -d -p 8899:8899 -p 8800:8800 -v "/some_local_path/db:/db" -e IM_DATA_DB=/db/inf.dat --name im indigodatacloud/im
```

You can also specify an external MySQL server to store IM data using the IM_DATA_DB environment variable::

```sh
$ sudo docker run -d -p 8899:8899 -p 8800:8800 -e IM_DATA_DB=mysql://username:password@server/db_name --name im indigodatacloud/im
```

Or you can also add a volume with all the IM configuration::

```sh
$ sudo docker run -d -p 8899:8899 -p 8800:8800 -v "/some_local_path/im.cfg:/etc/im/im.cfg" --name im indigodatacloud/im
```


## 2 INSTALLATION

The IM provides a script to install the IM in one single step (using pip).
You only need to execute the following command:

```sh
$ wget -qO- https://raw.githubusercontent.com/indigodatacloud/im/master/install.sh | bash
```

It works for the most recent version of the main Linux distributions (RHEL, CentOS, Fedora, Ubuntu, Debian).
In case that you O.S. does not work with this install script see next sections.

### 3 CONFIGURATION

Check the parameters in $IM_PATH/etc/im.cfg or /etc/im/im.cfg.
See [IM Manual](https://imdocs.readthedocs.io/en/latest/manual.html#configuration) to get a full
reference of the configuration variables.

Please pay attention to the next configuration variables, as they are the most important:

#### 3.1 SECURITY

Security is disabled by default. Please notice that someone with local network access can "sniff" the traffic and
get the messages with the IM with the authorisation data with the cloud providers.

Security can be activated both in the XMLRPC and REST APIs. Setting this variables:

```sh
XMLRCP_SSL = True
```

or

```sh
REST_SSL = True
```

And then set the variables: XMLRCP_SSL_* or REST_SSL_* to your certificates paths.
