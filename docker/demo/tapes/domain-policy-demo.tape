Output "/workspaces/childflow/img/childflow-domain-policy-demo.gif"

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 760
Set Framerate 30
Set Padding 24
Set CursorBlink false
Set TypingSpeed 40ms

Type "# 1st step: Inspect the reusable deny-domain profile."
Enter
Sleep 500ms
Type "sed -n '1,120p' /workspaces/childflow/docker/demo/profiles/domain-deny-origin.toml"
Enter
Sleep 2500ms
Enter
Sleep 1s

Type "# 2nd step: Run it and confirm the policy violation."
Enter
Sleep 500ms
Type "childflow --profile /workspaces/childflow/docker/demo/profiles/domain-deny-origin.toml || true"
Enter
Sleep 4s
Enter
Sleep 1s

Type "# 3rd step: Render a Markdown report from the saved flow log."
Enter
Sleep 500ms
Type "childflow --report /workspaces/childflow/docker/demo/profiles/logs/domain-deny-origin.jsonl --report-format markdown | sed -n '1,80p'"
Enter
Sleep 4s
