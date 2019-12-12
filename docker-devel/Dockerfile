# Dockerfile to create a container with the IM service
FROM grycap/jenkins:ubuntu16.04-im
ARG BRANCH=devel
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.9.0"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"

EXPOSE 8899 8800

# Install im - '$BRANCH' branch
RUN cd tmp \
 && git clone -b $BRANCH https://github.com/grycap/im.git \
 && cd im \
 && pip install /tmp/im

# Install pip optional libraries
RUN pip install MySQL-python pyOpenSSL cheroot==8.1.0 pymongo msrest msrestazure azure-common azure-mgmt-storage azure-mgmt-compute azure-mgmt-network azure-mgmt-resource azure-mgmt-dns azure-storage

# Set the VM_NUM_USE_CTXT_DIST to 3 for the tests
RUN sed -i -e 's/VM_NUM_USE_CTXT_DIST = 30/VM_NUM_USE_CTXT_DIST = 3/g' /etc/im/im.cfg

COPY ansible.cfg /etc/ansible/ansible.cfg

CMD im_service.py
