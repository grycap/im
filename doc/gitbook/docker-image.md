2. DOCKER IMAGE
===============

A Docker image named `indigodatacloud/im` has been created to make easier the deployment of an IM service using the
default configuration. Information about this image can be found here: https://hub.docker.com/r/indigodatacloud/im/.

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

You can use the IM as an entry point of an OpenNebula cloud provider as a TOSCA compliant endpoint for your site::

```sh
$ sudo docker run -d -p 8899:8899 -p 8800:8800 -e IM_SINGLE_SITE_ONE_HOST=oneserver.com --name im indigodatacloud/im
```
