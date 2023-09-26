rem Guest preparation script
ipconfig /release > nul
ipconfig /renew > nul
w32tm /resync
rem Self-delete
(goto) 2>nul & del "%~f0"
