FROM mysql:8.0

# Copy the initialization SQL script into MySQL's auto-run folder.
# Files here run once on first container start (empty data dir).
COPY docker/lab/mysql-init/01-init.sql /docker-entrypoint-initdb.d/

# Ensure the script is readable inside the image.
# 644 = owner read/write, group+others read.
RUN chmod 644 /docker-entrypoint-initdb.d/01-init.sql
