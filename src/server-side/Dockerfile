FROM ubuntu:focal

LABEL org.opencontainers.image.authors="{1802962, 1802976, 2001240}@sit.singaporetech.edu.sg"

ARG DEBIAN_FRONTEND="noninteractive"
ARG DEBCONF_NONINTERACTIVE_SEEN=true
ARG LOCALE="en_SG.UTF-8"
ARG TZ_ZONE="Asia"
ARG TZ_COUNTRY="Singapore"

ENV TZ="${TZ_ZONE}/${TZ_COUNTRY}"

RUN rm -rf /tmp/* /var/tmp/* && \
    rm -f /etc/apt/apt.conf.d/docker-gzip-indexes /var/lib/apt/lists/*lz4 /etc/timezone /etc/localtime /etc/skel/.bash_history && \
    ln -s /dev/null /etc/skel/.bash_history && \
    # sed -i 's|http://archive.|http://azure.archive.|g' /etc/apt/sources.list && \
    echo "tzdata tzdata/Areas select ${TZ_ZONE}" | debconf-set-selections && \
    echo "tzdata tzdata/Zones/${TZ_ZONE} select ${TZ_COUNTRY}" | debconf-set-selections && \
    echo "locales locales/locales_to_be_generated multiselect ${LOCALE} en_US.UTF-8 UTF-8" | debconf-set-selections && \
    echo "locales locales/default_environment_locale select ${LOCALE}" | debconf-set-selections && \
    apt-get clean && \
    apt-get autoclean && \
    apt-get -o Acquire::GzipIndexes=false update && \
    apt-get full-upgrade -y && \
    apt-get install -y tzdata && \
    apt-get autoremove --purge -y

COPY ./dist/harc-server /usr/local/bin/harc-server

CMD ["/bin/bash"]
