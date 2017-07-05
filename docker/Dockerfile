# Dockerfile to create a container with the IM service and TOSCA support
FROM ubuntu:16.04
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.5.2"
LABEL description="Container image to run the IM service with TOSCA support. (http://www.grycap.upv.es/im)"

# Install Ansible
RUN echo "deb http://ppa.launchpad.net/ansible/ansible/ubuntu xenial main" > /etc/apt/sources.list.d/ansible-ubuntu-ansible-xenial.list && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 93C4A3FD7BB9C367 && \ 
    apt-get update && apt-get -y install wget ansible && \
    rm -rf /var/lib/apt/lists/*

# Install Azure python SDK
RUN wget https://launchpad.net/ubuntu/+archive/primary/+files/python-msrest_0.4.4-1_all.deb && \
    wget https://launchpad.net/ubuntu/+archive/primary/+files/python-msrestazure_0.4.3-1_all.deb && \
    wget https://launchpad.net/ubuntu/+archive/primary/+files/python-azure_2.0.0~rc6+dfsg-2_all.deb && \
    dpkg -i python-msrest_*_all.deb ; \
    dpkg -i python-msrestazure_*_all.deb ; \
    dpkg -i python-azure_*_all.deb ; \
    rm *.deb && \
    apt update && apt install -f -y && \
    rm -rf /var/lib/apt/lists/*

# Install IM
RUN wget https://github.com/grycap/RADL/releases/download/v1.0.6/python-radl_1.0.6-1_all.deb && \ 
    wget https://github.com/indigo-dc/im/releases/download/v1.5.2/python-im_1.5.2-1_all.deb && \
    wget https://github.com/indigo-dc/tosca-parser/releases/download/0.7.2/python-tosca-parser_0.7.2-1_all.deb && \
    dpkg -i python-radl_*_all.deb ; \
    dpkg -i python-tosca-parser_*_all.deb ; \
    dpkg -i python-im_*_all.deb ; \
    rm *.deb && \
    apt update && apt install -f -y && \
    rm -rf /var/lib/apt/lists/*

# Expose the IM ports
EXPOSE 8899 8800

# Launch the service at the beginning of the container
CMD im_service.py
