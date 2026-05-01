Output "/workspaces/childflow/img/childflow-flow-log-demo.gif"

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 760
Set Framerate 30
Set Padding 24
Set CursorBlink false
Set TypingSpeed 40ms

Type "# 1st step: Run with summary and flow logging."
Enter
Sleep 500ms
Type "childflow --profile /workspaces/childflow/docker/demo/profiles/http-origin.toml --summary"
Enter
Sleep 4s
Enter
Sleep 1s

Type "# 2nd step: Confirm the flow log artifact."
Enter
Sleep 500ms
Type "ls -lh /workspaces/childflow/docker/demo/profiles/logs/http-origin.jsonl"
Enter
Sleep 1500ms
Enter
Sleep 1s

Type "# 3rd step: Inspect a few structured events."
Enter
Sleep 500ms
Type "sed -n '1,5p' /workspaces/childflow/docker/demo/profiles/logs/http-origin.jsonl"
Enter
Sleep 3s
