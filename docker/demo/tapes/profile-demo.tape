Output "/workspaces/childflow/img/childflow-profile-demo.gif"

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 760
Set Framerate 30
Set Padding 24
Set CursorBlink false
Set TypingSpeed 40ms

Type "# 1st step: Inspect the reusable profile."
Enter
Sleep 500ms
Type "sed -n '1,120p' /workspaces/childflow/docker/demo/profiles/http-origin.toml"
Enter
Sleep 2500ms
Enter
Sleep 1s

Type "# 2nd step: Dump the merged effective profile."
Enter
Sleep 500ms
Type "childflow --profile /workspaces/childflow/docker/demo/profiles/http-origin.toml --dump-profile"
Enter
Sleep 3s
Enter
Sleep 1s

Type "# 3rd step: Run the command tree from the profile."
Enter
Sleep 500ms
Type "childflow --profile /workspaces/childflow/docker/demo/profiles/http-origin.toml"
Enter
Sleep 3s
