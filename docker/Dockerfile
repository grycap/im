# Dockerfile to create a container with the IM service
FROM ubuntu:18.04
LABEL maintainer="Miguel Caballer <micafer1@upv.es>"
LABEL version="1.9.0"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"
EXPOSE 8899 8800

# Ensure system is up to date with mandatory python packages installed
RUN apt-get update && apt-get install --no-install-recommends -y openssh-client sshpass vim libmysqlclient20 && \
     apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && rm -rf ~/.cache/

# Install IM
RUN apt-get update && apt-get install --no-install-recommends -y gcc git python python-dev python-pip libmysqld-dev libssl-dev libffi-dev libsqlite3-dev && \
     pip install setuptools --upgrade -I && \
     pip install pip --upgrade -I && \
     /usr/local/bin/pip install msrest msrestazure azure-common azure-mgmt-storage azure-mgmt-compute azure-mgmt-network azure-mgmt-resource azure-mgmt-dns azure-storage && \
     /usr/local/bin/pip install MySQL-python pyOpenSSL pycrypto xmltodict pymongo && \
     /usr/local/bin/pip install IM==1.9.0 && \
     /usr/local/bin/pip uninstall pip -y && \
     apt-get purge -y gcc git python-dev python-pip libmysqld-dev libssl-dev libffi-dev libsqlite3-dev && \
     apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && rm -rf ~/.cache/

# Copy a ansible.cfg with correct minimum values
COPY ansible.cfg /etc/ansible/ansible.cfg

# Start IM service
CMD im_service.py
