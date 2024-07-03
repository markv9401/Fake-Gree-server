FROM python
RUN pip install cryptography pyopenssl==22.1.0 pycryptodome==3.19.1  scapy==2.5.0

RUN openssl genpkey -algorithm RSA -out server.key

COPY openssl.cnf openssl.cnf

RUN openssl req -new -key server.key -out server.csr -config openssl.cnf
RUN openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
CMD python3 -u /fakegree/gree_server.py $IP $PORT $HOSTNAME $TLS
