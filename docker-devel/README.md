 IM - Infrastructure Manager (With TOSCA Support)
=================================================

IM is a tool that deploys complex and customized virtual infrastructures on IaaS
Cloud deployments (such as AWS, OpenStack, etc.). It eases the access and the
usability of IaaS clouds by automating the VMI (Virtual Machine Image)
selection, deployment, configuration, software installation, monitoring and
update of the virtual infrastructure. It supports APIs from a large number of virtual
platforms, making user applications cloud-agnostic. In addition it integrates a
contextualization system to enable the installation and configuration of all the
user required applications providing the user with a fully functional
infrastructure.

This version evolved in the INDIGO-Datacloud project (https://www.indigo-datacloud.eu/) has
added support to TOSCA documents as input for the infrastructure creation.

Read the documentation and more at http://www.grycap.upv.es/im.

There is also an Infrastructure Manager YouTube reproduction list with a set of videos with demos
of the functionality of the platform: https://www.youtube.com/playlist?list=PLgPH186Qwh_37AMhEruhVKZSfoYpHkrUp.

DOCKER IMAGE
=============

A Docker image named `indigodatacloud/im` has been created to make easier the deployment of an IM service using the 
default configuration. Information about this image can be found here: https://hub.docker.com/r/indigodatacloud/im/.

How to launch the IM service using docker:

```sh
sudo docker run -d -p 8899:8899 -p 8800:8800 --name im indigodatacloud/im 
```
