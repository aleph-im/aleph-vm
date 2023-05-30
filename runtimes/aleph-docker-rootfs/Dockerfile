# Pull the minimal Debian image
FROM debian

# Install Nginx
RUN apt-get -y update && apt-get -y install nginx

COPY nginx/index.html /usr/share/nginx/html/index.html
COPY nginx/health-check.conf /etc/nginx/conf.d/health-check.conf
