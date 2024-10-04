FROM python:3.11

RUN mkdir /postfix_saslquota/ -p && \
        apt-get update && \
        apt-get install -y --no-install-recommends  net-tools ssl-cert && \
        apt dist-upgrade -y && \
        rm -rf /var/lib/apt/lists/*

RUN     rm -f   /etc/localtime && \
        ln -fs /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime 

RUN 	chmod ugo+rx /etc/ssl/* -R
#RUN make-ssl-cert generate-default-snakeoil --force-overwrite 

COPY /src/ /postfix_saslquota/


RUN useradd -ms /bin/bash www && \
        chown www: /postfix_saslquota
        
USER www

WORKDIR /postfix_saslquota

ENV _bind=0.0.0.0 \
  _bindport=10008 \
  _bindtimeout=120 \
  _redishost=redis \
  _redisport=6379 \
  _redisdb=0 \
  _logfacility=mail \
  _logaddress=localhost \
  _logport=514 \
  _loglevel=INFO \
  _loghandler=stdout \
  _quotafile=quotarules.json


RUN  mv  /postfix_saslquota/quotarules.json.orig  /postfix_saslquota/quotarules.json
RUN  mv  /postfix_saslquota/saslquota.json.orig  /postfix_saslquota/saslquota.json

RUN  pip3 install redis


HEALTHCHECK CMD netstat -an | grep ${_bindport} > /dev/null; if [ 0 != $? ]; then exit 1; fi;

#VOLUME ["/postfix_saslquota"]

CMD [ "python", "/postfix_saslquota/saslquota.py" ]
