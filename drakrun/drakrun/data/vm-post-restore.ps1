if ( $DRAKVUF_NET_ENABLE )
{
    ipconfig /release
    ipconfig /renew
}
$scriptBlock = {
  Set-Date -Date $DRAKVUF_DATE
}
Start-Process -Wait -Verb RunAs powershell.exe -ArgumentList (
  '-EncodedCommand', (
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlock))
  )
)