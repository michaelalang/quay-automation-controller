FROM registry.access.redhat.com/ubi9/ubi-minimal
# Add application sources to a directory that the assemble script expects them
# and set permissions so that the container runs without root access
USER 0
COPY app-src /opt/app-root/src
RUN microdnf install -y python3-pip python3-devel python3 libpq-devel gcc-c++; \
    pip install ConfigParser ; \
    pip install -r /opt/app-root/src/requirements.txt ; \
    rm -fR /var/cache/yum
COPY oc /usr/bin/oc
USER 1001

# Set the default command for the resulting image
CMD /opt/app-root/src/reconciler.py
