# Dockerfile
# คอนเทนเนอร์สำหรับฐานข้อมูล PostgreSQL
FROM postgres
# Copy initialization scripts
COPY init.sql /docker-entrypoint-initdb.d/

# Set locale (optional)
ENV LANG en_US.utf8