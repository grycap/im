# Dockerfile to create a container with the IM service
FROM ubuntu:16.04
LABEL maintainer="Miguel Caballer <micafer1@upv.es>"
LABEL version="1.6.3"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"
EXPOSE 8899 8800

# Ensure system is up to date with mandatory python packages installed
RUN apt-get update && apt-get install --no-install-recommends -y python-dbg python-dev python-pip openssh-client sshpass vim python-requests && rm -rf /var/lib/apt/lists/*

RUN pip install setuptools pip --upgrade -I
RUN pip install pyOpenSSL --upgrade -I

# Install pip optional libraries
RUN pip install msrest msrestazure azure-common azure-mgmt-storage azure-mgmt-compute azure-mgmt-network azure-mgmt-resource azure-mgmt-dns cheroot xmltodict

# Install IM
RUN apt-get update && apt-get install --no-install-recommends -y gcc libmysqld-dev libssl-dev libffi-dev libsqlite3-dev && \
     pip install MySQL-python && \
     pip install IM==1.6.3 && \
     apt-get remove -y gcc libmysqld-dev libssl-dev libffi-dev libsqlite3-dev python-dev python-pip && \
     apt-get autoremove -y && \
     rm -rf /var/lib/apt/lists/*

# Copy a ansible.cfg with correct minimum values
COPY ansible.cfg /etc/ansible/ansible.cfg

# Start IM service
CMD im_service.py
