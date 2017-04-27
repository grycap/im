# Dockerfile to create a container with the IM service with python 3
FROM ubuntu:16.04
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.5.3"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im) with python 3"
EXPOSE 8899 8800
RUN apt-get update && apt-get install -y gcc python3-dbg python3-dev python3-pip libmysqld-dev openssh-client sshpass libssl-dev libffi-dev python3-requests python3-mysqldb
# Install CherryPy to enable REST API
RUN pip3 install setuptools --upgrade -I
RUN pip3 install cheroot
RUN pip3 install pyOpenSSL --upgrade -I
# Install pip optional libraries
RUN pip3 install msrest msrestazure azure-common azure-mgmt-storage azure-mgmt-compute azure-mgmt-network azure-mgmt-resource

RUN apt install -y git
RUN cd tmp \
 && git clone https://github.com/grycap/im.git \
 && cd im \
 && pip3 install /tmp/im


COPY ansible.cfg /etc/ansible/ansible.cfg
CMD im_service.py
