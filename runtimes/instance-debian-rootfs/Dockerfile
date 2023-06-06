# Pull the minimal Debian image
FROM debian

# Install Nginx
RUN apt-get -y update && apt-get -y install nginx

COPY nginx/index.html /usr/share/nginx/html/index.html
COPY nginx/health-check.conf /etc/nginx/conf.d/health-check.conf

# Install all basic dependencies
RUN apt-get install -y --no-install-recommends --no-install-suggests \
  python3-minimal \
  openssh-server \
  socat libsecp256k1-0

# Install all needed python modules
RUN apt-get install -y --no-install-recommends --no-install-suggests \
  python3-aiohttp python3-msgpack \
  python3-setuptools python3-dev \
  python3-pip python3-cytoolz python3-pydantic

# Install NodeJS and some tools
RUN apt-get install -y --no-install-recommends --no-install-suggests \
  iproute2 unzip nodejs npm build-essential iputils-ping curl

# Install Docker
RUN apt-get install -y --no-install-recommends --no-install-suggests \
  docker.io cgroupfs-mount nftables

# Install Aleph dependencies
RUN pip3 install 'fastapi~=0.71.0'
RUN pip3 install 'aleph-client>=0.4.6' 'coincurve==15.0.0'

# Compile all Python bytecode
RUN python3 -m compileall -f /usr/local/lib/python3.9

# Enable root login by ssh
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Generate SSH host keys
#RUN systemd-nspawn -D ./rootfs/ ssh-keygen -q -N "" -t dsa -f /etc/ssh/ssh_host_dsa_key
#RUN systemd-nspawn -D ./rootfs/ ssh-keygen -q -N "" -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key
#RUN systemd-nspawn -D ./rootfs/ ssh-keygen -q -N "" -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key
#RUN systemd-nspawn -D ./rootfs/ ssh-keygen -q -N "" -t ed25519 -f /etc/ssh/ssh_host_ed25519_key

# Set up a login terminal on the serial console (ttyS0):
RUN ln -s agetty /etc/init.d/agetty.ttyS0
RUN echo ttyS0 > /etc/securetty

# Set root password
RUN echo "root:toor" | /usr/sbin/chpasswd

# Reduce size
RUN rm -fr /root/.cache
RUN rm -fr /var/cache
RUN mkdir -p /var/cache/apt/archives/partial
RUN rm -fr /usr/share/doc
RUN rm -fr /usr/share/man
RUN rm -fr /var/lib/apt/lists/
