FROM dtagdevsec/heralding:24.04.2
USER 0:0
# Strip security.capability xattr (cp without --preserve=xattr drops xattrs) so execve
# succeeds under CapDrop=ALL + no-new-privileges:true when binding unprivileged ports >1024.
RUN cp /usr/local/bin/python3.14 /usr/local/bin/python3.14.nocap && \
    chmod 0755 /usr/local/bin/python3.14.nocap && \
    mv /usr/local/bin/python3.14.nocap /usr/local/bin/python3.14 && \
    mkdir -p /tmp/heralding /var/log/heralding && \
    chown -R 2000:2000 /tmp/heralding /var/log/heralding
USER 2000:2000
