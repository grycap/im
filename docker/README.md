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

Read the documentation and more at http://www.grycap.upv.es/im.

There is also an Infrastructure Manager YouTube reproduction list with a set of videos with demos
of the functionality of the platform: https://www.youtube.com/playlist?list=PLgPH186Qwh_37AMhEruhVKZSfoYpHkrUp.

DOCKER IMAGE
=============

A Docker image named `grycap/im` has been created to make easier the deployment of an IM service using the 
default configuration. Information about this image can be found here: https://hub.docker.com/r/grycap/im/.

How to launch the IM service using docker:

```sh
sudo docker run -d -p 8899:8899 -p 8800:8800 --name im grycap/im
```

You can also specify an external MySQL server to store IM data using the IM_DATA_DB environment variable::

```sh
sudo docker run -d -p 8899:8899 -p 8800:8800 -e IM_DATA_DB=mysql://username:password@server/db_name --name im grycap/im
```

Or you can also add a volume with all the IM configuration:

```sh
$ sudo docker run -d -p 8899:8899 -p 8800:8800 -v "/some_local_path/im.cfg:/etc/im/im.cfg" --name im grycap/im
```
