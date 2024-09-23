if ( $DRAKVUF_NET_ENABLE )
{
    ipconfig /release
    ipconfig /renew
}
Set-Date -Date $DRAKVUF_DATE
