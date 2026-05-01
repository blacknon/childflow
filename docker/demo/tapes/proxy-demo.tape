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
Sleep 4s
Enter
Sleep 1s

Type "# 2nd step: Confirm connect success with a reusable profile."
Enter
Sleep 500ms
Type "childflow --profile /workspaces/childflow/docker/demo/profiles/http-origin.toml"
Enter
Sleep 3s
Enter
Sleep 1s

Type "# 3rd step: Check captured packet."
Enter
Sleep 500ms
Type "ls -lh /workspaces/childflow/docker/demo/profiles/captures/http-origin.pcapng"
Enter
Sleep 1500ms
Enter
Sleep 1s

Type "tcpdump -nn -r /workspaces/childflow/docker/demo/profiles/captures/http-origin.pcapng | head"
Enter
Sleep 3s
