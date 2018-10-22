FROM alpine:3.8
LABEL maintainer="Miguel Caballer <micafer1@upv.es>"
LABEL version="1.0"
LABEL description="Container image to run the IM probes. (http://www.grycap.upv.es/im)"

RUN apk add --no-cache py-pip python git && \
     pip install mock requests && \
     git clone https://github.com/grycap/im.git  --branch probe && \
     cp -rf im/monitoring /monitoring && \
     rm -rf im && \
     mkdir /monitoring/log && \
     pip --no-cache-dir install ec3-cli && \
     apk del py-pip git

WORKDIR /monitoring

# Set the default command to execute when creating a new container
CMD python probeim.py -t $TOKEN -u $IM_URL
