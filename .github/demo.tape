# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Rendered by `make demo`, which puts the release build on PATH. A local
# Python web server stands in for the private service; everything runs
# on loopback.
Output .github/demo.gif
Set Shell "bash"
Set FontSize 17
Set Width 1200
Set Height 640
Set Padding 24
Set TypingSpeed 35ms

Hide
Type "cd $(mktemp -d) && echo 'hello from a private service' > index.html" Enter
Type "python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 &" Enter
Type "export PS1='$ '" Enter
Type "clear" Enter
Show

Type "tunnelward --version" Sleep 300ms Enter
Sleep 1s
Type "tunnelward dev --to http://127.0.0.1:8080 --admin 127.0.0.1:9000 &" Sleep 300ms Enter
Sleep 2s
Type "curl -s http://127.0.0.1:8000/" Sleep 300ms Enter
Sleep 1500ms
Type "curl -s http://127.0.0.1:9000/inventory" Sleep 300ms Enter
Sleep 1500ms
Type "curl -s http://127.0.0.1:9000/metrics | grep -v '^#'" Sleep 300ms Enter
Sleep 4s

Hide
Type `printf 'high_impact = ["transfer"]\n\n[[rules]]\neffect = "permit"\nagents = ["claude"]\ntools = ["read_*", "transfer"]\n\n[[rules]]\neffect = "forbid"\nmismatch = true\n' > policy.toml` Enter
Type `printf '[[case]]\nname = "claude reads a balance"\nagent = "claude"\npath = "/mcp"\nmethod = "tools/call"\ntool = "read_balance"\nevidence = "network"\nexpect = "allow"\n\n' >> cases.toml` Enter
Type `printf '[[case]]\nname = "a transfer needs cryptographic evidence"\nagent = "claude"\npath = "/mcp"\nmethod = "tools/call"\ntool = "transfer"\nevidence = "network"\nexpect = "deny"\n\n' >> cases.toml` Enter
Type `printf '[[case]]\nname = "a claimed Claude the gateway did not see is refused"\nagent = "claude"\npath = "/mcp"\nmethod = "tools/call"\ntool = "read_balance"\nevidence = "network"\nmismatch = true\nexpect = "deny"\n\n' >> cases.toml` Enter
Type `printf '[[case]]\nname = "another agent is refused"\nagent = "scraper"\npath = "/mcp"\nmethod = "tools/call"\ntool = "read_balance"\nevidence = "network"\nexpect = "deny"\n\n' >> cases.toml` Enter
Type "clear" Enter
Show

Type "cat policy.toml" Sleep 300ms Enter
Sleep 1500ms
Type "tunnelward policy test --policy policy.toml cases.toml" Sleep 300ms Enter
Sleep 4s

Hide
Type "kill %1 %2" Enter
