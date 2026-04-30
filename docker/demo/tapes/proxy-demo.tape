Output "/workspaces/childflow/img/childflow.gif"

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 760
Set Framerate 30
Set Padding 24
Set CursorBlink false
Set TypingSpeed 40ms

Type "# 1st step: Confirm connect fail."
Enter
Sleep 500ms
Type "curl --connect-timeout 3 --max-time 5 -fsS http://origin-http.demo:8080/ || true"
Enter
Sleep 3s
Enter
Sleep 1s

Type "# 2nd step: Confirm connect success, and captured packet."
Enter
Sleep 500ms
Type "/tmp/childflow-target/debug/childflow -p http://proxy-http:3128 -U demo -P demo -c /tmp/proxy-demo.pcapng -- curl --connect-timeout 5 --max-time 15 -fsS http://origin-http.demo:8080/"
Enter
Sleep 3s

Type "# 3rd step: Check captured packet."
Enter
Sleep 500ms
Type "ls -lh /tmp/proxy-demo.pcapng"
Enter
Sleep 1500ms

Type "tcpdump -nn -r /tmp/proxy-demo.pcapng | head"
Enter
Sleep 3s
