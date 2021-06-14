# Dockerfile to create a container with the IM service
FROM ubuntu:20.04
LABEL maintainer="Miguel Caballer <micafer1@upv.es>"
LABEL version="1.10.4"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"
EXPOSE 8899 8800

# Ensure system is up to date with mandatory python packages installed
RUN apt-get update && apt-get install --no-install-recommends -y python3 python3-distutils openssh-client sshpass vim libmysqlclient21 python3-mysqldb && \
     apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && rm -rf ~/.cache/

# Install IM
RUN apt-get update && apt-get install --no-install-recommends -y python3-setuptools python3-pip git && \
     pip3 install msrest msrestazure azure-common azure-mgmt-storage azure-mgmt-compute azure-mgmt-network azure-mgmt-resource azure-mgmt-dns && \
     pip3 install pyOpenSSL cheroot xmltodict pymongo ansible==2.9.21&& \
     cd /tmp && git clone https://github.com/openstack/tosca-parser && pip3 install /tmp/tosca-parser && \
     cd /tmp && git clone https://github.com/apache/libcloud && pip3 install /tmp/libcloud && \
     pip3 install IM==1.10.4 && \
     apt-get purge -y python3-pip git && \
     apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && rm -rf ~/.cache/

# Copy a ansible.cfg with correct minimum values
COPY ansible.cfg /etc/ansible/ansible.cfg

# Start IM service
CMD im_service.py
