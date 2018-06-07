 IM - Infrastructure Manager (With TOSCA Support)
=================================================

* Version ![PyPI](https://img.shields.io/pypi/v/im.svg)

IM is a tool that deploys complex and customized virtual infrastructures on IaaS
Cloud deployments (such as AWS, OpenStack, etc.). It eases the access and the
usability of IaaS clouds by automating the VMI (Virtual Machine Image)
selection, deployment, configuration, software installation, monitoring and
update of the virtual infrastructure. It supports APIs from a large number of virtual
platforms, making user applications cloud-agnostic. In addition it integrates a
contextualization system to enable the installation and configuration of all the
user required applications providing the user with a fully functional
infrastructure.

This version evolved in the INDIGO-Datacloud project (https://www.indigo-datacloud.eu/). It is used by the [INDIGO Orchestrator](https://github.com/indigo-dc/orchestrator) to contact Cloud sites to finally deploy the VMs/containers.

New features added:

+ Support for TOSCA 1.0 YAML specification with the custom node types described in https://github.com/indigo-dc/tosca-types/blob/master/custom_types.yaml
+ Support for the Identity and Access Management Service (IAM).
+ Support for the Token Translation Service (TTS) to support IAM authetication on OpenNebula Clouds.
+ Improvements to access OpenStack Clouds that support IAM.

Read the documentation and more at the [IM Webpage](http://www.grycap.upv.es/im) or at [Gitbook](https://indigo-dc.gitbooks.io/im/content/).

There is also an Infrastructure Manager YouTube reproduction list with a set of videos with demos
of the functionality of the platform: https://www.youtube.com/playlist?list=PLgPH186Qwh_37AMhEruhVKZSfoYpHkrUp.
