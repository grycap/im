# IM MONITORING PROBE

## 1	INTRODUCTION

The monitorization agent is a client-side software, that connects with IM to probe an IM instance. Agent does not need any open ports, just gather data from IM via IM API REST by GET, POST, PUT and DELETE http requests. Agent is composed by scripts that use IM API, and loads configurations from files that must be edited correctly by an administrator.

## 2	FILE STRUCTURE

The agent is composed by a principal python script named probeim.py, one support library IMinfrastructureOper.py and a directory conf with two configuration files, test.radl and authorizationHeader.txt.

```sh
├── conf
│   ├── test.radl
│   └── authorizationHeader.txt
├── IMinfrastructureOper.py
└── probeim.py
```

### 2.1	SCRIPTS

* File [probeim.py](https://github.com/grycap/im/blob/master/monitoring/probeim.py) is the executable script that gathers all measured data and sends it to zabbix.
* File [IMinfrastructureOper.py](https://github.com/grycap/im/blob/master/monitoring/IMinfrastructureOper.py) contains functionalities related to interaction with IM environment through its API. Here we can throw actions like creating infrastructure, listing infrastructure, creating VM, deleting infrastructure, and get the status of each of these actions.

### 2.2	CONFIGURATION

* authorizationHeader.txt

Example from /conf [here](https://github.com/grycap/im/blob/master/monitoring/conf/authorizationHeader.txt)

* test.radl

Example from /conf [here](https://github.com/grycap/im/blob/master/monitoring/conf/test.radl)

## 3	DATA SOURCES

| METHOD /URL| Items|
| ------ | ------ |
| GET /infrastructures| List_inf |
| POST /infrastructures| Create_inf |
| PUT /infrastructures/<infId>/start | Start_inf |
| POST /infrastructures/<infId>
 body:	RADL document | Create_vm |
| DELETE /infrastructures/<infId|Delete_inf |


To connect to IM an appropriated header must be set.
```sh
HEADERS = {
        "Content-Type" : "text/plain",
        "Accept": "application/json",
        "Authorization" : authoriz
    }
 ```
Where the authoriz field comes from [authorizationHeader.txt](https://github.com/grycap/im/blob/master/monitoring/conf/authorizationHeader.txt) file.

## 4	DOCKER CONTAINER

Create or download a [Dockerfile](https://github.com/grycap/im/blob/master/monitoring/Dockerfile)  Use your Docker user and a name you want for your image.

In case you want to test the OpenID authentication you must provide a valid token to the IM instance. The IM instance must be configured to support the OpenID issuer that you will use in the probes. Then you can download and execute the [script](https://github.com/grycap/im/blob/master/monitoring/get-access-token.sh) used to request to IM an access token. You need your client credentials, IAM user and password.

```sh
[root@localhost imzabbix]# sh get-access-token.sh 

{"access_token":"eyJraWQiOiJyc2E...","token_type":"Bearer","refresh_token":"eyJhbGciOiJub25lIn0.eyJqd...","expires_in":3599,"scope":"address phone openid email profile offline_access","id_token":"eyJraWQiOi..."}
[root@localhost imzabbix]# 

```
Build an image from the directory where your Dockerfile is located.

```sh
[root@localhost imzabbix]# ls Dockerfile 
Dockerfile
[root@localhost imzabbix]# docker build -t <dockeruser>/<my_built_image> .
Sending build context to Docker daemon  35.33kB
Step 1/7 : FROM alpine:3.8
 ---> 0584b3d2cf6d
...
Successfully built afe963948e10
[root@localhost imzabbix]# 

```

After image was created, set up required parameters and run the docker container.

```sh

[root@localhost imzabbix]# TOKEN=eyJraWQiOiJyc2E...
[root@localhost imzabbix]# IM_URL=http://server.com/:8800

[root@localhost imzabbix]# docker run --name MY_IMZABBIX_CONTAINER -e TOKEN=$TOKEN -e IM_URL=$IM_URL -d <dockeruser>/<my_built_image>

```