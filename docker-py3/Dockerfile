# Dockerfile to create a container with the IM service
FROM ubuntu:24.04

ENV VERSION=1.19.0

LABEL maintainer="Miguel Caballer <micafer1@upv.es>"
LABEL version="${VERSION}"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"
EXPOSE 8899 8800

# Ensure system is up to date with mandatory python packages installed
RUN apt-get update && apt-get install --no-install-recommends -y patch wget python3 openssh-client sshpass vim libmysqlclient21 python3-mysqldb && \
     apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && rm -rf ~/.cache/

# Install IM
RUN apt-get update && apt-get install --no-install-recommends -y python3-setuptools python3-pip git && \
     pip3 install --break-system-packages msrest msrestazure azure-common azure-mgmt-storage azure-mgmt-compute azure-mgmt-network azure-mgmt-resource azure-mgmt-dns azure-identity && \
     pip3 install --break-system-packages pyOpenSSL cheroot xmltodict pymongo ansible==8.7.0&& \
     pip3 install --break-system-packages git+https://github.com/openstack/tosca-parser && \
     pip3 install --break-system-packages git+https://github.com/micafer/libcloud@im && \
     pip3 install --break-system-packages IM==${VERSION} &&\
     apt-get purge -y python3-pip python3-setuptools python3-pkg-resources git && \
     apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && rm -rf ~/.cache/

# Copy im configuration files
RUN mkdir /etc/im
RUN mkdir /var/log/im
RUN wget https://raw.githubusercontent.com/grycap/im/v${VERSION}/etc/im.cfg -O /etc/im/im.cfg
RUN wget https://raw.githubusercontent.com/grycap/im/v${VERSION}/etc/logging.conf -O /etc/im/logging.conf

# Copy a ansible.cfg with correct minimum values
COPY ansible.cfg /etc/ansible/ansible.cfg

# Start IM service
CMD ["/usr/local/bin/im_service"]
