# IM RADL examples

This directory has some RADL examples to deploy different types of virtual infrastructures: 

## Simple examples

* simple.radl: A very simple example. A single node with 1 CPU and 512 MB of RAM with an Ubuntu linux 10.04 or higher.
* image_url.radl: Another very simple example but in this case using directly the URL of the Virtual Machine Image, instead of searching it in the VMRC service (http://www.grycap.upv.es/vmrc).

## Single node examples

* octave.radl: Installs the Octave application in one node using ``disk.0.applications`` that installs it from system repositories.
* spark.radl: Installs Spark in one node.
* vault.radl: It is a test showing the posibility of using vault encrypted recipes in and RADL document. In this case it a simple ``sleep 30`` test task encryoted with the password ``grycap01``.

## Multiple node examples

* ganglia.radl: Installs the Ganglia monitoring system in two nodes. The ``front`` node is configured as the ``gmetad`` node and the ``wn`` only as monitored node.
* slurm.radl: Installs a SLURM cluster with one front-end node and two working nodes.
* hadoop.radl: Installs a Hadoop cluster with one front-end node and two working nodes.
* swarm.radl: Installs a Docker Swarm cluster with one front-end node and two working nodes.
* kubernetes.radl: Installs a Kubernetes cluster with one front-end node and two working nodes.
* galaxy.radl: Installs a Galaxy Portal on top of a a SLURM cluster with one front-end node and two working nodes.
