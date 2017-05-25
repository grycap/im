# Dockerfile to create a container with the IM service
FROM ubuntu:16.04
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.5.4"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"
EXPOSE 8899 8800
RUN apt-get update && apt-get install -y gcc python-dbg python-dev python-pip libmysqld-dev python-pysqlite2 openssh-client sshpass libssl-dev libffi-dev python-requests
# Install CherryPy to enable REST API
RUN pip install cheroot
# Install pip optional libraries
RUN pip install MySQL-python msrest msrestazure azure-common azure-mgmt-storage azure-mgmt-compute azure-mgmt-network azure-mgmt-resource
RUN pip install IM
COPY ansible.cfg /etc/ansible/ansible.cfg
CMD im_service.py
