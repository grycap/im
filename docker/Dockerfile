# Dockerfile to create a container with the IM service
FROM ubuntu:16.04
LABEL maintainer="Miguel Caballer <micafer1@upv.es>"
LABEL version="1.6.1"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"
EXPOSE 8899 8800

# Ensure system is up to date with mandatory python packages installed
RUN apt-get update && apt-get install --no-install-recommends -y python-dbg python-dev python-pip openssh-client sshpass vim && \ 
     apt-get autoremove -y && \
     rm -rf /var/lib/apt/lists/*

RUN pip install setuptools pip --upgrade -I
RUN pip install pyOpenSSL --upgrade -I

# Install pip optional libraries
RUN pip install msrest msrestazure azure-common azure-mgmt-storage azure-mgmt-compute azure-mgmt-network azure-mgmt-resource azure-mgmt-dns cheroot xmltodict

# Install IM
RUN apt-get update && apt-get install --no-install-recommends -y gcc git libmysqld-dev libssl-dev libffi-dev libsqlite3-dev && \
     pip install MySQL-python && \
     cd /tmp && git clone https://github.com/indigo-dc/im.git && \ 
     cd /tmp && git clone https://github.com/indigo-dc/tosca-parser.git  && \ 
     cd /tmp/tosca-parser && pip install /tmp/tosca-parser && \
     cd /tmp/im && pip install /tmp/im && \
     apt-get remove -y gcc git libmysqld-dev libssl-dev libffi-dev libsqlite3-dev python-dev python-pip && \
     apt-get autoremove -y && \
     rm -rf /var/lib/apt/lists/*º

# Remove pip requests and force python-requests to be installed to avoid SSL ca errors
RUN pip uninstall -y requests
RUN apt-get update && apt-get install --no-install-recommends -y python-requests && rm -rf /var/lib/apt/lists/*

# Copy a ansible.cfg with correct minimum values
COPY ansible.cfg /etc/ansible/ansible.cfg

# Start IM service
CMD im_service.py
