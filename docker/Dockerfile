# Dockerfile to create a container with the IM service and TOSCA support
FROM ubuntu:16.04
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.5.0"
LABEL description="Container image to run the IM service with TOSCA support. (http://www.grycap.upv.es/im)"

# Update and install all the necessary packages
RUN apt-get update && apt-get install -y \
    gcc \
    python-dev \
    python-pip \
    python-dateutil \
    openssh-client \
    sshpass \
    git \
    libssl-dev \
    libffi-dev \
    libmysqld-dev \
    python-pysqlite2
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install CherryPy to enable HTTPS in REST API
RUN pip install setuptools --upgrade -I
RUN pip install pbr CherryPy pyOpenSSL --upgrade -I

# Install tosca-parser
RUN cd tmp \
 && git clone --recursive https://github.com/indigo-dc/tosca-parser.git \
 && cd tosca-parser \
 && pip install /tmp/tosca-parser

# Install im indigo tosca fork 
RUN cd tmp \
 && git clone --recursive https://github.com/indigo-dc/im.git \
 && cd im \
 && pip install /tmp/im
COPY ansible.cfg /etc/ansible/ansible.cfg

# Turn on the REST services
RUN sed -i "/ACTIVATE_REST =.*/c\ACTIVATE_REST=True" /etc/im/im.cfg

# Expose the IM ports
EXPOSE 8899 8800

# Launch the service at the beginning of the container
CMD im_service.py
