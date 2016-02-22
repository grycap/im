# Dockerfile to create a container with the IM service and TOSCA support
FROM ubuntu:14.04
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.4.3"
LABEL description="Container image to run the IM service with TOSCA support. (http://www.grycap.upv.es/im)"

# Update and install all the neccesary packages
RUN apt-get update && apt-get install -y \
    gcc \
    python-dev \
    python-pip \
    python-soappy \
    python-pbr \
    python-dateutil \
    openssh-client \
    sshpass \
    git \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install CherryPy to enable HTTPS in REST API
RUN pip install CherryPy

# Install tosca-parser
RUN cd tmp \
 && git clone --recursive https://github.com/indigo-dc/tosca-parser.git \
 && cd tosca-parser \
 && python setup.py install

# Install im indigo tosca fork 
RUN cd tmp \
 && git clone --recursive https://github.com/indigo-dc/im.git \
 && cd im \
 && python setup.py install
COPY ansible.cfg /etc/ansible/ansible.cfg

# Turn on the REST services
RUN sed -i "/ACTIVATE_REST =.*/c\ACTIVATE_REST=True" /etc/im/im.cfg

# Expose the IM ports
EXPOSE 8899 8800

# Launch the service at the beginning of the container
CMD im_service.py
