Set shell = CreateObject("WScript.Shell")
appDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
shell.Run """" & appDir & "\dist-portable\HashcatGUI\HashcatGUI.exe" & """", 0, False
