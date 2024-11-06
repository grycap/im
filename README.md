# IM - Infrastructure Manager

[![PyPI](https://img.shields.io/pypi/v/im.svg)](https://pypi.org/project/im)
[![Tests](https://github.com/grycap/im/actions/workflows/main.yaml/badge.svg)](https://github.com/grycap/im/actions/workflows/main.yaml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/582a0d6e763f44bdade11133e5191439)](https://www.codacy.com/gh/grycap/im/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=grycap/im&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/582a0d6e763f44bdade11133e5191439)](https://www.codacy.com/gh/grycap/im/dashboard?utm_source=github.com&utm_medium=referral&utm_content=grycap/im&utm_campaign=Badge_Coverage)
[![License](https://img.shields.io/badge/license-GPL%20v3.0-brightgreen.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://imdocs.readthedocs.io/en/latest/)
[![SQAaaS badge](https://img.shields.io/badge/sqaaas%20software-gold-yellow)](https://eu.badgr.com/public/assertions/rkXyQH9FRj-EAMPgccz5ug)

IM is a tool that deploys complex and customized virtual infrastructures on
IaaS Cloud deployments (such as AWS, OpenStack, etc.). It eases the access and
the usability of IaaS clouds by automating the VMI (Virtual Machine Image)
selection, deployment, configuration, software installation, monitoring and
update of the virtual infrastructure. It supports APIs from a large number of
virtual platforms, making user applications cloud-agnostic. In addition it
integrates a contextualization system to enable the installation and
configuration of all the user required applications providing the user with a
fully functional infrastructure.

Read the documentation and more at <http://www.grycap.upv.es/im>.

There is also an Infrastructure Manager YouTube reproduction list with a set of
videos with demos of the functionality of the platform: <https://www.youtube.com/playlist?list=PLgPH186Qwh_37AMhEruhVKZSfoYpHkrUp>.

Please acknowledge the use of this software in your scientific publications by
including the following reference:

Miguel Caballer, Ignacio Blanquer, German Molto, and Carlos de Alfonso.
"[Dynamic management of virtual infrastructures](https://link.springer.com/article/10.1007/s10723-014-9296-5)".
Journal of Grid Computing, Volume 13, Issue 1, Pages 53-70, 2015, ISSN
1570-7873, DOI: 10.1007/s10723-014-9296-5.

## Achievements

[![SQAaaS badge][badge-img]][badge-link]

[badge-img]: https://github.com/EOSC-synergy/SQAaaS/raw/master/badges/badges_150x116/badge_software_gold.png
[badge-link]: https://api.eu.badgr.io/public/assertions/2DN4fpCNSFyCJD_TTTycjA "SQAaaS gold badge achieved"

This software has received a gold badge according to the
[Software Quality Baseline criteria](https://github.com/indigo-dc/sqa-baseline)
defined by the [EOSC-Synergy](https://www.eosc-synergy.eu) project.

## 1 DOCKER IMAGE

The recommended option to use the Infrastructure Manager service is using the
available docker image. A Docker image named `ghcr.io/grycap/im` has been
created to make easier the deployment of an IM service using the default
configuration. It is available in the IM
[Github Container registry](https://github.com/grycap/im/pkgs/container/im).

How to launch the IM service using docker::

```sh
sudo docker run -d -p 8899:8899 -p 8800:8800 --name im ghcr.io/grycap/im
```

To make the IM data persistent you also have to specify a persistent location
for the IM database using the IM_DATA_DB environment variable and adding a
volume::

```sh
sudo docker run -d -p 8899:8899 -p 8800:8800 -v "/some_local_path/db:/db" \
                -e IM_DATA_DB=/db/inf.dat --name im ghcr.io/grycap/im
```

You can also specify an external MySQL server to store IM data using the
IM_DATA_DB environment variable::

```sh
sudo docker run -d -p 8899:8899 -p 8800:8800 \
                -e IM_DATA_DB=mysql://username:password@server/db_name \
                --name im ghcr.io/grycap/im
```

Or you can also add a volume with all the IM configuration::

```sh
sudo docker run -d -p 8899:8899 -p 8800:8800 \
                -v "/some_local_path/im.cfg:/etc/im/im.cfg"
                --name im ghcr.io/grycap/im
```

## 2 Kubernetes Helm Chart

The IM service and web interface can be installed on top of [Kubernetes](https://kubernetes.io/)
using [Helm](https://helm.sh/).

How to install the IM chart:

First add the GRyCAP repo:

```sh
helm repo add grycap https://grycap.github.io/helm-charts/
```

Then install the IM chart (with Helm v2):

```sh
helm install --namespace=im --name=im  grycap/IM
```

Then install the IM chart (with Helm v3):

```sh
helm install --namespace=im --create-namespace im  grycap/IM
```

All the information about this chart is available at the [IM chart README](https://github.com/grycap/helm-charts/blob/master/IM/README.md).

### 3 CONFIGURATION

Check the parameters in $IM_PATH/etc/im.cfg or /etc/im/im.cfg.
See [IM Manual](https://imdocs.readthedocs.io/en/latest/manual.html#configuration)
to get a full reference of the configuration variables.

Please pay attention to the next configuration variables, as they are the most
important:

DATA_DB - must be set to the URL to access the database to store the IM data.
         Be careful if you have two different instances of the IM service
         running in the same machine!!.
         It can be a MySQL DB: `mysql://username:password@server/db_name`,
         SQLite: `sqlite:///etc/im/inf.dat` or MongoDB:
         `mongodb://username:password@server/db_name`,

#### 3.1 SECURITY

Security is disabled by default. Please notice that someone with local network
access can "sniff" the traffic and get the messages with the IM with the
authorisation data with the cloud providers.

Security can be activated both in the XMLRPC and REST APIs. Setting this
variables:

```sh
XMLRCP_SSL = True
```

or

```sh
REST_SSL = True
```

And then set the variables: XMLRCP_SSL_* or REST_SSL_* to your certificates
paths.
