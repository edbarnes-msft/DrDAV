$testurl = "http://www.myserver.com"
$outputverbose = $false
$logfile = $env:TEMP+"\_DavTest_"+$env:COMPUTERNAME+"_"+(Get-Date -Format yyddMMhhmm)+".log"


$MethodDefinition = @'
    [DllImport("C:\\Windows\\System32\\wininet.dll", CharSet=CharSet.Auto, SetLastError=true)]
    public static extern bool InternetSetCookie(string lpszUrl, string lpszCookieName, string lpszCookieData);
    [DllImport("C:\\Windows\\System32\\wininet.dll", CharSet=CharSet.Auto, SetLastError=true)]
    public static extern bool InternetGetCookieEx(string pchURL, string pchCookieName, System.Text.StringBuilder pchCookieData, ref System.UInt32 pcchCookieData, int dwFlags, IntPtr lpReserved);
    public static string GetCookieString(string url)
    {
        // Determine the size of the cookie      
        UInt32 datasize = 256*1024;
        System.Text.StringBuilder cookieData = new System.Text.StringBuilder(Convert.ToInt32(datasize));
        if (!InternetGetCookieEx(url, null, cookieData, ref datasize, 0x00002000, IntPtr.Zero))
        {
        if (datasize < 0)
            return null;
        // Allocate stringbuilder large enough to hold the cookie    
        cookieData = new System.Text.StringBuilder(Convert.ToInt32(datasize));
        if (!InternetGetCookieEx(url, null, cookieData, ref datasize, 0x00002000, IntPtr.Zero))
            return null;
        }
        return cookieData.ToString();
    }
'@
$WinInet = Add-Type -MemberDefinition $MethodDefinition -Name 'WinInet' -Namespace 'Win32' -PassThru 
[System.Management.Automation.PSCredential] $altcreds = $null
$auth_ntlm = $false; $auth_nego = $false; $auth_basic =$false; $auth_oauth = $false; $auth_fba = $false


function Test-MsDavConnection {
    [CmdletBinding()] 
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true
            )][uri]$WebAddress 
        )
    begin {
        $os = $(Get-CimInstance Win32_OperatingSystem)
        $osver = [int] ($os.Version.Split('.')[0] + $os.Version.Split('.')[1])
        $defaultNPO = ('RDPNP,LanmanWorkstation,webclient').ToLower()
        $WCfilesize = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").FileSizeLimitInBytes 
        $WCtimeout = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").SendReceiveTimeoutInSec  
        $npo = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order").ProviderOrder
        $hnpo = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder").ProviderOrder
        $WCBasicauth = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").BasicAuthLevel
        $WCAFSL = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").AuthForwardServerList
        $protocols=[enum]::GetNames([System.Security.Authentication.SslProtocols])|?{$_ -notmatch 'none|default|ssl2'} #ssl3|tls|tls11|tls12
        $WCuseragent = "Microsoft-WebDAV-MiniRedir/" + $os.Version
        $SecurityProtocols = "TLS,TLS11,TLS12"
        if ( ($osver -eq 61 ) -or ($osver -eq 62) ) { # https://support.microsoft.com/en-us/help/3140245
            $SecurityProtocols = "SSL3,TLS"
            $dsp = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp").DefaultSecureProtocols 
            $dspwow = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp").DefaultSecureProtocols
            Write-ToLog "WinHttp registry entry" 
            if ($dsp -eq $null ) {Write-ToLog "absent" } else { Write-ToLog $dsp }
            Write-ToLog "WinHttp WOW registry entry" 
            if ($dspwow -eq $null ) {Write-ToLog "absent" } else { Write-ToLog $dspwow }           
            $winhttpminver7 = "6.1.7601.23375"
            $winiominver7 = "6.1.7601.23375"
            $winhttpminver8 = "6.2.9200.21797"
            $winiominver8 = "6.2.9200.21797"
            $wcminver7 = "6.1.7601.23542"
            $wcshellminver7 = "6.1.7601.22498"
            }
    }

    process {
        $MsDavConnection = @{
            ClientName=$os.CSName
            ClientOS = $os.Caption
            ClientOSVersion = $os.Version
            ClientWebIO=$([System.IO.FileInfo] 'C:\Windows\System32\webio.dll').VersionInfo.ProductVersion
            ClientWinHttp=$([System.IO.FileInfo] 'C:\Windows\System32\winhttp.dll').VersionInfo.ProductVersion
            ClientShell32=$([System.IO.FileInfo] 'C:\Windows\System32\shell32.dll').VersionInfo.ProductVersion
            ClientWebclnt=$([System.IO.FileInfo] 'C:\Windows\System32\webclnt.dll').VersionInfo.ProductVersion
            ClientDavclnt=$([System.IO.FileInfo] 'C:\Windows\System32\davclnt.dll').VersionInfo.ProductVersion
            ClientMrxdav=$([System.IO.FileInfo] 'C:\Windows\System32\drivers\mrxdav.sys').VersionInfo.ProductVersion
            ClientNetProviders=$npo
            ServerName=$WebAddress.DnsSafeHost
            ServerPort=$WebAddress.Port
            ServerScheme=$WebAddress.Scheme
            TargetUrl=$WebAddress
            AuthForwardServerList = $WCAFSL
            BasicAuthLevel=$WCBasicauth
            }    

            
            foreach ($i in $MsDavConnection.GetEnumerator()) { Write-ToLog $($i.Key + " : " + $i.Value).ToString() }
            Write-ToLog ("`n======================================================`n")
            

# Fail to Connect
#    1.	WebClient not installed or disabled
            $WCSvc = Get-Service | where { $_.Name -eq 'webclient' }
          if ($WCSvc -ne $null) 
            { 
                $WCStartType = $WCSvc.StartType 
                Write-ToLog ("The WebClient service StartUp type is: " + $WCStartType)
              if ( ($WCStartType -ne [System.ServiceProcess.ServiceStartMode]::Manual ) -and
                    ($WCStartType -ne [System.ServiceProcess.ServiceStartMode]::Automatic ) )
                    { Write-ToLog "WebClient service Start Type should be set to Manual or Automatic." }
                Write-ToLog "Manual is default but Automatic is preferred if the service is used frequently"
            } 
            else
            {
                Write-ToLog "WebClient service is not present"
            }
#    2.	Bad Network Provider order
#        a.	WebClient missing from provider order
            $npomsg = "Network Provider Order check: "
            $npocheck = 'Good'
          if ($npo.ToLower() -ne $hnpo.ToLower()) { 
                $npocheck = 'HwOrder doesn''t match Order' 
                Write-ToLog ($npocheck +"`n`tOrder: " + $npo + "`n`tHwOrder: " + $hnpo)
                }
          if ( !("," + $hnpo +",").ToLower().Contains(",webclient,") -or !("," + $npo +",").ToLower().Contains(",webclient,") ) {
                $npocheck = 'WebClient is missing from provider list' 
                Write-ToLog ($npomsg + $npocheck + "`n`tOrder: " + $npo )
                }
#        b.	Third-party providers interfering
          if ( ($npocheck -eq "Good") -and ($npo.ToLower() -ne $defaultnpo.ToLower()) ) { 
                $npocheck = 'Order doesn''t match Default' 
                Write-ToLog ($npomsg + $npocheck + "`n`tOrder: " + $npo )
                }
          if ( $npocheck -eq "Good") {Write-ToLog ($npomsg + $npocheck)}
#    3.	Port blocked
        $starttime = Get-Date
        if ($osver -eq 61 ) 
        {
            # New-Object System.Net.Sockets.TcpClient($WebAddress.DnsSafeHost,$WebAddress.Port)
            $ns = New-Object system.net.sockets.tcpclient
            try { $ns.Connect($WebAddress.DnsSafeHost, $WebAddress.Port ) } catch {}
            $testtime = (New-TimeSpan $starttime $(Get-Date) ).Seconds
            if( $ns.Connected) {$testconnection = $true; $ns.Close()}
            $davport = "Win7: "
        } 
        else 
        { 
            $testconnection = (Test-NetConnection $WebAddress.DnsSafeHost -Port $WebAddress.Port -InformationLevel Quiet)
            $testtime = (New-TimeSpan $starttime $(Get-Date) ).Seconds
        }
        $davport = $davport + "Connection to " + $WebAddress.DnsSafeHost + " on port " + $WebAddress.Port + " was " 
        if ($testconnection -eq $true ) { $davport = $davport + "successful and took " + $testtime + " seconds" }
        else { $davport = $davport + "not successful"}
        Write-ToLog $davport
#    3.	Version of SSL/TLS not supported by server
#    4.	Certificate is expired or doesn't match
          if ( ($testconnection -eq $true) -and ($WebAddress.Scheme -eq "https") ) {
                $ServerProtocolsAccepted = $null
                $RemoteCertificate = $null
                foreach($protocol in $protocols){   
                   try {
                        $Socket = New-Object System.Net.Sockets.Socket('Internetwork','Stream', 'Tcp')
                        $Socket.Connect($WebAddress.DnsSafeHost, $WebAddress.Port)
                        $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
                        $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true)
                        $SslStream.AuthenticateAsClient($WebAddress.DnsSafeHost,  $null, $protocol, $false )
                      if ($RemoteCertificate -eq $null ) {
                            $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
                            }
                      if ($ServerProtocolsAccepted -eq $null){ $ServerProtocolsAccepted = $protocol}
                        else {$ServerProtocolsAccepted = $ServerProtocolsAccepted + ", " + $protocol}
                        Write-ToLogVerbose ("Protocol: " + $protocol)
                    } 
                    catch {
                        Write-ToLogVerbose ($protocol + " failed")
                    }
                    finally {
                       if ($SslStream -ne $null) { $SslStream.Close()}
                    }
                }
              if ($ServerProtocolsAccepted -eq $null) {Write-ToLog "No attempted protocols succeeded"}
                else { Write-ToLog ("Server supports: " + $ServerProtocolsAccepted.ToUpper() ) }
              if ( $RemoteCertificate -ne $null ) {
                    Write-ToLogVerbose ("Certificate valid: " + $RemoteCertificate.Verify())
                    Write-ToLogVerbose ("Certificate issued to: " + $RemoteCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false))
                    Write-ToLogVerbose ("Certificate not good before: " + $RemoteCertificate.NotBefore )
                    Write-ToLogVerbose ("Certificate not good after: " + $RemoteCertificate.NotAfter )
                    }
                # Optional To-Do - Check cert chain
            }

#    5.	Bad proxy settings
            Write-ToLogVerbose "TODO: Check proxy config"
#        a.	Proxy misdirection
#        b.	Proxy authentication require
#        [net.httpwebRequest]::GetSystemWebProxy
#
# Failure after connect
#    1.	Failing Authentication
          #if (($WebAddress.Scheme -eq "https") -and ($ServerProtocolsAccepted -eq $null)) {$testconnection = $false}
        if ( $testconnection ) {
            $verb = "HEAD"
            $followredirect = $false
            $addcookies = $false
            $credtype = "Anonymous" # 3 choices = "Anonymous", "DefaultCreds", "AlternateCreds"
            $maxtry = 5
            do {
                $responseresult = SendWebRequest -url $WebAddress -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
                Write-ToLog ("`nResult:" + $responseresult)
                switch ($responseresult ) {
                    "SwitchToGET" { $verb = "GET" }
                    "AddCookies"  { $addcookies = $true }
                    "AddFollow302"{ $followredirect = $true }            
                    "AddDefCreds" { $credtype = "DefaultCreds" }
                    "AddAltCreds" { $credtype = "AlternateCreds" }
                    "AuthBasic"   { $authbasic = $true }
                    "AuthWinNego" { $authnego = $true }
                    "AuthWinNTLM" { $authntlm = $true }
                    "AuthFBA"     { $addcookies = $true }
                }
                $maxtry = $maxtry - 1
            } while ( ( $responseresult -notlike "Complete*"  ) -and ($maxtry -gt 0 ) )

            }

#        a.	NTLM or Kerberos - AuthForwardServerList
        if ($global:auth_ntlm -or $global:auth_nego) { 
            Write-ToLogVerbose ("AuthForwardServerList " + $WCAFSL )
                }
#        b.	Basic - not over SSL
          if ($global:auth_basic) { Write-ToLogVerbose ("BasicAuthLevel " + $WCBasicauth ) }

#        c.	Claims/FBA - No persistent cookie passed
            $IEZone = [System.Security.Policy.Zone]::CreateFromUrl($WebAddress).SecurityZone
            $IEZoneNum = $IEZone.value__
            $ProtectMode = $(Get-Item -Path ("HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\" + $IEZoneNum)).GetValue('2500')

            if ($ProtectMode.Length -eq 0) { $ProtectMode = "Default"}
            Write-ToLog ("$WebAddress is in the $IEZone Security Zone and Protect Mode value is " + $ProtectMode)
#            i.	Cookie not created persistent
#            ii.	Cookie not stored in shareable location
            $persistentcookies = [Win32.WinInet]::GetCookieString($WebAddress) 
            Write-ToLogVerbose ("Persistent cookies for " + $WebAddress + " :`n" + $persistentcookies   )

#    2.	OPTIONS and/or PROPFIND verb blocked
            Write-ToLog "`nCheck if OPTIONS or PROPFIND are blocked"
            $verb = "OPTIONS"
            $responseresult = SendWebRequest -url $WebAddress -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
            $verb = "PROPFIND"
            $responseresult = SendWebRequest -url $WebAddress -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
#    3.	PROPFIND returns bad results
            Write-ToLogVerbose "TODO: Validate PROPFIND results`n"
#        a.	XML missing
#        b.	XML malformed/gzipped
#    4.	Custom header name with space 
#        Checked each time headers are read  
#    5.	Root site access
#        a.	No DAV at root
#        b.	No permissions at root
#        c.	Root site missing 
            Write-ToLog "Checking root site access`n"
            $verb = "PROPFIND"
            $rootweb = $WebAddress.Scheme + "://" + $WebAddress.DnsSafeHost
            $responseresult = SendWebRequest -url $rootweb -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype


Exit $LASTEXITCODE
#
# Performance
#    1.	Slow to connect
#        a.	Auto-detect proxy unnecessarily selected
            Write-ToLogVerbose "`nTODO: Auto-detect proxy`n"
#        b.	SMB attempts receive no response before falling through to WebClient
			$start = Get-Date
			$smb = "SMB Connection is " + (Test-NetConnection $WebAddress.DnsSafeHost -Port 139 -InformationLevel Quiet)
			$smb = $smb + " and took " + (New-TimeSpan $start $(Get-Date) ).Seconds + " seconds"
            Write-ToLogVerbose $smb

			$start = Get-Date
			$smb2 = "SMB2 Connection is " + (Test-NetConnection $WebAddress.DnsSafeHost -Port 445 -InformationLevel Quiet)
			$smb2 = $smb2 + " and took " + (New-TimeSpan $start $(Get-Date) ).Seconds + " seconds"
            Write-ToLogVerbose $smb2

#        c.	The WebClient service was not already started
          if ($WCStartType -ne "Automatic") { Write-ToLog "For best performance, set the StartUp Type to 'Automatic'" }

#    2.	Slow to browse
            Write-ToLogVerbose "TODO: Check browsing performance scenarios`n"

#        a.	Read-Only Win32 attribute on SharePoint folders can cause unnecessary PROPFIND on contents.
#        b.	Too many items in the destination folder will result in slow response in Windows Explorer (may appear empty)

#    3.	Uploads fail to complete or are very slow
#        a.	PUT requests are blocked
#        b.	File exceeds file size limit
            Write-ToLog ("Current setting of FileSizeLimitInBytes is: " + $WCfilesize + " bytes")
#        c.	Upload takes longer than the Timeout setting
            Write-ToLog ("Upload throughput is limited to Filesize / 8kb * RTT " )
          if ( $testconnection ) {
              if (!((ping $WebAddress.DnsSafeHost -n 2 | Out-String ).Contains("Received = 0")) ) {
                    $rtt = (Test-Connection -ComputerName $WebAddress.DnsSafeHost | Measure-Object -Property ResponseTime -Average).Average | Out-Null
                  if ($rtt -gt 0 ) {
                        Write-ToLogVerbose ("Current Round Trip Time estimate is: " + $rtt + " milliseconds")
                        $WCesttimeupload = ($WCfilesize / 8192 * $rtt)
                        Write-ToLogVerbose ("Estimated time needed to upload a max file size of " +  $WCfilesize + " bytes: " + ($WCesttimeupload/1000) + " seconds" )
                        }
                    else { Write-ToLogVerbose "Unable to determine RTT. Consider using PsPing from SysInternals to find the RTT" }
                }
                else { Write-ToLogVerbose "Unable to use PING to determine RTT. Consider using PsPing from SysInternals to find the RTT" }
            }
            Write-ToLog ("The current setting for SendReceiveTimeoutInSec is: " + $WCtimeout )


#        return New-Object PsObject -Property $MsDavConnection
     }

}




function SendWebRequest([string] $url, [string] $verb, [string] $useragent, $includecookies = $false, $follow302=$true, [string] $usecreds)
{
    Write-ToLog ("`n======================================================")
    Write-ToLog ($url + " " + $verb + " " + $useragent + " Cookies:" + $includecookies + " Follow302:" + $follow302 + " CredType:" + $usecreds)
    [net.httpWebRequest] $req = [net.webRequest]::Create($url)
	$req.AllowAutoRedirect = $follow302
	$req.Method = $verb
    if ( $useragent -ne $null ) {$req.UserAgent = $useragent}
    if ( $includecookies -eq $true ) {$cookiesread = $([Win32.WinInet]::GetCookieString($url)).Split(";")}

    $jar = New-Object System.Net.CookieContainer
    if ($cookiesread.count -gt 0) {
        $cc = New-Object System.Net.CookieCollection
        foreach ($cookie in $cookiesread) {
            $c = New-Object System.Net.Cookie
            $c.Name = $cookie.Split("=")[0].Trim()
            $c.Value = $cookie.Substring($cookie.IndexOf("=") + 1)
            $cc.Add($c)
        }
        foreach ($c in $cc) { Write-ToLog ($c.tostring()) }
        $jar.Add($url, $cc)
    }
    $req.CookieContainer = $jar

    switch ($usecreds) 
    { 
        "Anonymous" {$req.Credentials = $null }
        "DefaultCreds" {$req.UseDefaultCredentials = $true }
        "AlternateCreds" {
            if ($global:altcreds -eq $null){$global:altcreds = Get-Credential}
            $req.Credentials = $global:altcreds
            }
    }

	#Get Response
	try {
		[net.httpWebResponse]$res = $req.GetResponse()
	}
	catch {
        if ( ($Error[0].Exception.InnerException).Status -eq 'ProtocolError' ) {
            [net.httpWebResponse]$res = $Error[0].Exception.InnerException.Response
        }
        else {
            $res = $null
            Write-ToLog ( ($Error[0].Exception.InnerException).status)
        }
    }

    Write-ToLog ("Request Headers:")
    foreach ($h in $req.Headers) { Write-ToLog ("`t" + $h + ": " + $req.Headers.GetValues($h)) }

    if ($res -ne $null)
    {
        Write-ToLog ("`nResponse:" + $verb + " " + $res.StatusCode.value__)
        Write-ToLog ("Response Cookies: " + $res.Cookies.Count)
        foreach ($c in $res.Cookies) { Write-ToLog ("`t" + $c.Name + " " + $c.Value) }

        Write-ToLog ("Response Headers: " + $res.Headers.Count)
        foreach ($h in $res.Headers)
        {
            
            switch -Wildcard($h){
                "WWW-Authenticate" { 
                    Write-ToLog ("`t" + $h )
                    foreach ($a in $res.Headers.GetValues($h)) {
                        Write-ToLog "`t`t"$a
                        if ($a -like "NTLM*") { $global:auth_ntlm = $true }
                        if ($a -like "Nego*") { $global:auth_nego = $true }
                        if ($a -like "Basic*") { $global:auth_basic = $true }
                        # WWW-Authenticate: IDCRL Type="BPOSIDCRL", EndPoint="/sites/Classic/_vti_bin/idcrl.svc/", RootDomain="sharepoint.com", Policy="MBI"
                        if ($a -like "IDCRL*") { $global:auth_oauth = $true }
                        }
                    Break
                    }
                "MicrosoftSharePointTeamServices" { Write-ToLog ("`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Set-Cookie" { 
                    Write-ToLog ("`t" + $h)
                    foreach ($c in $res.Headers.GetValues($h)) {
                        Write-ToLog ("`t`t" + $c)
                        }
                    Break
                    }
                "Allow" { Write-ToLog ("`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Date" { Write-ToLog ("`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Location" { Write-ToLog ("`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Content-Type" { Write-ToLog ("`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Content-Encoding" { Write-ToLog ("`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "request-id" { Write-ToLog ("`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                # X-MSDAVEXT_Error: 917656; Access+denied.+Before+opening+files+in+this+location%2c+you+must+first+browse+to+the+web+site+and+select+the+option+to+login+automatically.
                "X-MSDAVEXT_Error" { $global:auth_fba = $true ; Write-ToLog ("`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "X-FORMS_BASED_AUTH_REQUIRED" { $global:auth_fba = $true ; Write-ToLog ("`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "FORMS_BASED_AUTH_RETURN_URL" { $global:auth_fba = $true ; Write-ToLog ("`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "*" { Write-ToLogVerbose ("`t? " + $h + ": " + $res.Headers.GetValues($h))}
            }
        }
        $statcode = $res.StatusCode.value__ 
        if ( ($verb -eq "PROPFIND") -and (($statcode -eq 200) -or ($statcode -eq 207) ) ) { ReturnBody($res) }

        $res.Close()
    }
    #Set StatusCheck
    $statuscheck = $null
    if ($statcode -eq 404 ) {
        if ($verb = "HEAD") {$statuscheck = "SwitchToGET" }
        else {$statuscheck = "Complete-404" }
    }
    elseif ($statcode -eq 403 ) {
        if ($includecookies -eq $false ) {$statuscheck = "AddCookies" }
        else {$statuscheck = "Complete-403" }
    }
    elseif ($statcode -eq 401 ) {
        if ($usecreds -eq "Anonymous") {$statuscheck = "AddDefCreds" }
        elseif ($usecreds -eq "DefaultCreds") {$statuscheck = "AddAltCreds" }
        else {$statuscheck = "Complete-401" }
    }
    elseif ($statcode -eq 302 ) { 
        if ($follow302 -eq $false ) {$statuscheck = "AddFollow302" }
        else {$statuscheck = "Complete-302" }
    }
    elseif ($statcode -eq 200 ) {$statuscheck = "Complete-200" }
    elseif ($statcode -eq 207 ) {$statuscheck = "Complete-207" }
    else {$statuscheck = $("Complete-Unexpected-" + $statcode) }

    return $statuscheck
}



function ReturnBody($response)
{
  if ($response.ContentLength -ge 0) {
        $responsestream = $response.getResponseStream() 
        $streamreader = New-Object IO.StreamReader($responsestream) 
        $body = $streamreader.ReadToEnd() 
        Add-Content $logfile -Value $body
    }

}

function Write-ToLog ()
{   param( $msg = "`n" )
    write-host $msg
    Add-Content $logfile -Value $msg
}
function Write-ToLogVerbose ()
{   param( $msg = "`n" )
    if ($global:outputverbose ) { Write-Verbose $msg}
    Add-Content $logfile -Value ("VERBOSE:`t"+$msg)
}

cls

if ($outputverbose) {
    Test-MsDavConnection -WebAddress $testurl -Verbose }
else { Test-MsDavConnection -WebAddress $testurl }


Start-Process $env:windir + "\explorer.exe"  -ArgumentList $((Get-ChildItem $logfile).DirectoryName) 
