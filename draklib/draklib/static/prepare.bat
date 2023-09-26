rem Guest preparation script
ipconfig /release
ipconfig /renew
w32tm /resync
rem Self-delete
(goto) 2>nul & del "%~f0"
