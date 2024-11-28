FROM php:8.0-apache


COPY ./html /var/www/html

RUN chown -R root:root /var/www/html &&\
    chmod -R 555 /var/www/html

RUN apt-get update && apt-get install -y gcc

RUN ln -sf /dev/stdout /var/log/apache2/access.log && \
    ln -sf /dev/stderr /var/log/apache2/error.log

RUN gcc -o /flag /var/www/html/flag.c && \
    chmod 111 /flag && \
    rm /var/www/html/flag.c


COPY ./config/php.ini /usr/local/etc/php/php.ini

EXPOSE 80

CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
