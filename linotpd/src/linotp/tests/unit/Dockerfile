FROM linotp


#Unit test specific packages
RUN apt-get update && apt-get install --no-install-recommends --yes \
  		make \
  		python-nose \
  		python-pip \
  		python-dev \
  		build-essential \
  		autoconf \
  		libtool \
  		pkg-config \
  		python-setuptools


VOLUME /linotpsrc

WORKDIR /linotpsrc/linotpd/src/linotp/tests/unit

RUN    pip install coverage \
                diff-cover \
                mock


CMD [ "/usr/bin/make", "test" ]