FROM cowrie/cowrie:latest
COPY --chmod=0755 honeypot_boot.py /cowrie/cowrie-git/bin/honeypot_boot.py
USER 1000:1000
ENTRYPOINT ["/cowrie/cowrie-env/bin/python3", "/cowrie/cowrie-git/bin/honeypot_boot.py"]
