FROM nginx:alpine

# Create cache directories, certs directory, and snippet directories with proper permissions
RUN mkdir -p /var/cache/nginx/hls \
             /var/cache/nginx/auth \
             /hls \
             /var/www/player \
             /var/www/certbot \
             /etc/nginx/snippets \
             /etc/nginx/certs && \
    chown -R nginx:nginx /var/cache/nginx /hls /var/www/player /var/www/certbot

COPY nginx.conf /etc/nginx/nginx.conf
COPY snippets/ /etc/nginx/snippets/

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
