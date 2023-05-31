# Pull the minimal Debian image
FROM debian

# Install Nginx
RUN apt-get -y update && apt-get -y install nginx

COPY nginx/index.html /usr/share/nginx/html/index.html
COPY nginx/health-check.conf /etc/nginx/conf.d/health-check.conf

# Install all needed dependencies
RUN apt-get install -y --no-install-recommends --no-install-suggests \
  python3-minimal \
  openssh-server \
  socat libsecp256k1-0 \
  \
  python3-aiohttp python3-msgpack \
  python3-setuptools \
  python3-pip python3-cytoolz python3-pydantic \
  iproute2 unzip \
  nodejs npm \
  build-essential python3-dev \
  \
  docker.io \
  cgroupfs-mount \
  nftables \
  \
  iputils-ping curl

RUN pip3 install 'fastapi~=0.71.0'

RUN echo "Pip installing aleph-client"
RUN pip3 install 'aleph-client>=0.4.6' 'coincurve==15.0.0'

# Compile all Python bytecode
RUN python3 -m compileall -f /usr/local/lib/python3.9

RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Generate SSH host keys
#RUN systemd-nspawn -D ./rootfs/ ssh-keygen -q -N "" -t dsa -f /etc/ssh/ssh_host_dsa_key
#RUN systemd-nspawn -D ./rootfs/ ssh-keygen -q -N "" -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key
#RUN systemd-nspawn -D ./rootfs/ ssh-keygen -q -N "" -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key
#RUN systemd-nspawn -D ./rootfs/ ssh-keygen -q -N "" -t ed25519 -f /etc/ssh/ssh_host_ed25519_key

RUN echo "root:toor" | /usr/sbin/chpasswd

# Set up a login terminal on the serial console (ttyS0):
RUN ln -s agetty /etc/init.d/agetty.ttyS0
RUN echo ttyS0 > /etc/securetty

# Add custom inittab
COPY inittab /etc/inittab

# Reduce size
RUN rm -fr /root/.cache
RUN rm -fr /var/cache
RUN mkdir -p /var/cache/apt/archives/partial
RUN rm -fr /usr/share/doc
RUN rm -fr /usr/share/man
RUN rm -fr /var/lib/apt/lists/

# Add the custom init
COPY init0.sh /sbin/init
COPY init1.py /root/init1.py
RUN chmod +x /sbin/init
RUN chmod +x /root/init1.py
