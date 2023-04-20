# Pull the minimal Debian image
FROM debian

# Install Nginx
RUN apt-get -y update && apt-get -y install nginx

COPY index.html /usr/share/nginx/html/index.html
