# Dockerfile to create a container with the IM service
FROM ubuntu:14.04
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.4.8"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"
EXPOSE 8899 8800
RUN apt-get update && apt-get install -y gcc python-dev python-pip python-mysqldb openssh-client sshpass libssl-dev libffi-dev
# Install CherryPy to enable HTTPS in REST API
RUN pip install setuptools --upgrade -I
RUN pip install CherryPy pyOpenSSL --upgrade -I
# Add unresolved LibCloud dependency
RUN pip install backports.ssl_match_hostname
RUN pip install IM
COPY ansible.cfg /etc/ansible/ansible.cfg
CMD im_service.py
