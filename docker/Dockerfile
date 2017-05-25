# Dockerfile to create a container with the IM service
FROM ubuntu:16.04
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.5.4"
LABEL description="Container image to run the IM service. (http://www.grycap.upv.es/im)"
EXPOSE 8899 8800
# Install Ansible
RUN echo "deb http://ppa.launchpad.net/ansible/ansible/ubuntu xenial main" > /etc/apt/sources.list.d/ansible-ubuntu-ansible-xenial.list && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 93C4A3FD7BB9C367 && \ 
    apt-get update && apt-get -y install wget ansible sshpass && \
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
RUN wget https://github.com/grycap/RADL/releases/download/v1.1.0/python-radl_1.1.0-1_all.deb && \ 
    wget https://github.com/grycap/im/releases/download/v1.5.4/python-im_1.5.4-1_all.deb && \
    dpkg -i python-radl_*_all.deb ; \
    dpkg -i python-im_*_all.deb ; \
    rm *.deb && \
    apt update && apt install -f -y && \
    rm -rf /var/lib/apt/lists/*

COPY ansible.cfg /etc/ansible/ansible.cfg
CMD im_service.py
