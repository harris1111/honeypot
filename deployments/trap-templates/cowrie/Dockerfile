FROM cowrie/cowrie:latest
USER 0
COPY --chmod=0755 honeypot_boot.py /cowrie/cowrie-git/bin/honeypot_boot.py
COPY --chmod=0644 deception_cmds.py /cowrie/cowrie-git/src/cowrie/commands/deception_cmds.py
RUN ["/cowrie/cowrie-env/bin/python3", "-c", "\
from pathlib import Path;\n\
p = Path('/cowrie/cowrie-git/src/cowrie/commands/__init__.py');\n\
s = p.read_text();\n\
if '\"deception_cmds\"' not in s:\n\
    assert '\"yum\"' in s, s;\n\
    s = s.replace('\"yum\",', '\"yum\",\\n    \"deception_cmds\",', 1);\n\
    p.write_text(s);\n\
from cowrie.shell import protocol;\n\
assert 'ollama' in protocol.HoneyPotBaseProtocol.commands;\n\
assert 'nvidia-smi' in protocol.HoneyPotBaseProtocol.commands;\n\
assert 'docker' in protocol.HoneyPotBaseProtocol.commands;\n\
assert 'jq' in protocol.HoneyPotBaseProtocol.commands;\n\
assert 'systemctl' in protocol.HoneyPotBaseProtocol.commands;\n\
print('Registered Cowrie commands:', len(protocol.HoneyPotBaseProtocol.commands));\n\
"]
USER 1000:1000
ENTRYPOINT ["/cowrie/cowrie-env/bin/python3", "/cowrie/cowrie-git/bin/honeypot_boot.py"]
