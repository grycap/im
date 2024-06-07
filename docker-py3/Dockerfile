# Dockerfile to create a container with the IM service
FROM ubuntu:22.04

ENV VERSION=1.17.0

LABEL maintainer="Miguel Caballer <micafer1@upv.es>"
LABEL version="${VERSION}"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"
EXPOSE 8899 8800

# Ensure system is up to date with mandatory python packages installed
RUN apt-get update && apt-get install --no-install-recommends -y patch wget python3 openssh-client sshpass vim libmysqlclient21 python3-mysqldb && \
     apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && rm -rf ~/.cache/

# Install IM
RUN apt-get update && apt-get install --no-install-recommends -y python3-setuptools python3-pip git && \
     pip3 install -U pip  && \
     pip3 install msrest msrestazure azure-common azure-mgmt-storage azure-mgmt-compute azure-mgmt-network azure-mgmt-resource azure-mgmt-dns azure-identity==1.8.0 && \
     pip3 install pyOpenSSL cheroot xmltodict pymongo ansible==8.7.0&& \
     pip3 install apache-libcloud==3.8.0 git+https://github.com/grycap/im@wheel && \
     apt-get purge -y python3-pip git && \
     apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && rm -rf ~/.cache/

# Patch libcloud to add network extra
# untill this PR is merged and released
# https://github.com/apache/libcloud/pull/2016
COPY ost.patch /tmp/ost.patch
RUN patch /usr/local/lib/python3.12/dist-packages/libcloud/compute/drivers/openstack.py < /tmp/ost.patch && rm /tmp/ost.patch

# Copy im configuration files
RUN mkdir /etc/im
RUN mkdir /var/log/im
RUN wget https://raw.githubusercontent.com/grycap/im/wheel/etc/im.cfg -O /etc/im/im.cfg
RUN wget https://raw.githubusercontent.com/grycap/im/wheel/etc/logging.conf -O /etc/im/logging.conf

# Copy a ansible.cfg with correct minimum values
COPY ansible.cfg /etc/ansible/ansible.cfg

# Fix boto issue https://github.com/boto/boto/issues/3783
COPY endpoints.json /usr/local/lib/python3.12/dist-packages/boto/endpoints.json

# Start IM service
CMD /usr/local/bin/im_service
