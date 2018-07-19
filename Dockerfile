
FROM jodogne/orthanc:1.2.0

WORKDIR /root/source

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install \
      libxml++2.6-dev libxml++2.6-doc uuid-dev \
      git \
      python3-dev \
      python3.4-venv \
      python3-pip && \
    rm -rf /var/lib/apt/lists/*

# Used to copy the plugin to AWS after successful integration tests
RUN pip3 install awscli

COPY . /root/source/

# Build the plugin
RUN mkdir /root/build/
WORKDIR /root/build
RUN cmake -DALLOW_DOWNLOADS=ON \
    -DSTATIC_BUILD=ON \
    -DCMAKE_BUILD_TYPE=Release \
    /root/source
RUN make "--jobs=$(grep --count ^processor /proc/cpuinfo)"
RUN make install

ENTRYPOINT [ "Orthanc" ]
CMD [ "/etc/orthanc/" ]
