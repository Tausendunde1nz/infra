server {
    server_name lighting.tu1nz.com;

    root /var/www/lighting.tu1nz.com;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/lighting.tu1nz.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/lighting.tu1nz.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot


}
server {
    if ($host = lighting.tu1nz.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot


    listen 80;
    server_name lighting.tu1nz.com;
    return 404; # managed by Certbot


}
