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

Type "tunnelward dev --to http://127.0.0.1:8080 --admin 127.0.0.1:9000 &" Sleep 300ms Enter
Sleep 2s
Type "curl -s http://127.0.0.1:8000/" Sleep 300ms Enter
Sleep 1500ms
Type "curl -s http://127.0.0.1:9000/inventory" Sleep 300ms Enter
Sleep 1500ms
Type "curl -s http://127.0.0.1:9000/metrics | grep -v '^#'" Sleep 300ms Enter
Sleep 4s

Hide
Type "kill %1 %2" Enter
