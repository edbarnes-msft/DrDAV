
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
        $WCuseragent = "Microsoft-WebDAV-MiniRedir/" + $OS.Version
        $SecurityProtocols = "TLS,TLS11,TLS12"
        If ( ($osver -eq 7 ) -or ($osver -eq 8) ) { # https://support.microsoft.com/en-us/help/3140245
            $SecurityProtocols = "SSL3,TLS"
            $dsp = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp").DefaultSecureProtocols 
            $dspwow = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp").DefaultSecureProtocols 
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

            (New-Object PsObject -Property $MsDavConnection) | Format-List 
# Fail to Connect
#    1.	WebClient not installed or disabled
            $WCSvc = Get-Service | where { $_.Name -eq 'webclient' }
            If ($WCSvc -ne $null) 
            { 
                $WCStartType = $WCSvc.StartType 
                Write-Host ("The WebClient service StartUp type is: " + $WCStartType)
                If ( ($WCStartType -ne [System.ServiceProcess.ServiceStartMode]::Manual ) -and
                    ($WCStartType -ne [System.ServiceProcess.ServiceStartMode]::Automatic ) )
                    { Write-Host "WebClient service Start Type should be set to Manual or Automatic." }
                Write-Host "Manual is default but Automatic is preferred if the service is used frequently"
            } 
            else
            {
                Write-Host "WebClient service is not present"
            }
#    2.	Bad Network Provider order
#        a.	WebClient missing from provider order
            $npomsg = "Network Provider Order check: "
            $npocheck = 'Good'
            If ($npo.ToLower() -ne $hnpo.ToLower()) { 
                $npocheck = 'HwOrder doesn''t match Order' 
                Write-Host ($npocheck +"`n`tOrder: " + $npo + "`n`tHwOrder: " + $hnpo)
                }
            If ( !("," + $hnpo +",").ToLower().Contains(",webclient,") -or !("," + $npo +",").ToLower().Contains(",webclient,") ) {
                $npocheck = 'WebClient is missing from provider list' 
                Write-Host ($npomsg + $npocheck + "`n`tOrder: " + $npo )
                }
#        b.	Third-party providers interfering
            If ( ($npocheck -eq "Good") -and ($npo.ToLower() -ne $defaultnpo.ToLower()) ) { 
                $npocheck = 'Order doesn''t match Default' 
                Write-Host ($npomsg + $npocheck + "`n`tOrder: " + $npo )
                }
            If ( $npocheck -eq "Good") {Write-Host ($npomsg + $npocheck)}
#    3.	Port blocked
        $start = Get-Date
        $testconnection = (Test-NetConnection $WebAddress.DnsSafeHost -Port $WebAddress.Port -InformationLevel Quiet)
		$davport = "Connection to " + $WebAddress.DnsSafeHost + " on port " + $WebAddress.Port + " was " 
        If ($testconnection ) { $davport = $davport + "successful and took " + (New-TimeSpan $start $(Get-Date) ).Seconds + " seconds" }
        else { $davport = $davport + "not successful"}
        Write-Host $davport
#    3.	Version of SSL/TLS not supported by server
#    4.	Certificate is expired or doesn't match
            If ( $testconnection -and ($WebAddress.Scheme -eq "https") ) {
                $ServerProtocolsAccepted = $null
                $RemoteCertificate = $null
                foreach($protocol in $protocols){   
                   try {
                        $Socket = New-Object System.Net.Sockets.Socket('Internetwork','Stream', 'Tcp')
                        $Socket.Connect($WebAddress.DnsSafeHost, $WebAddress.Port)
                        $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
                        $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true)
                        $SslStream.AuthenticateAsClient($WebAddress.DnsSafeHost,  $null, $protocol, $false )
                        If ($RemoteCertificate -eq $null ) {
                            $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
                            }
                        If ($ServerProtocolsAccepted -eq $null){ $ServerProtocolsAccepted = $protocol}
                        else {$ServerProtocolsAccepted = $ServerProtocolsAccepted + ", " + $protocol}
                        Write-Verbose ("Protocol: " + $protocol)
                    } 
                    catch {
                        Write-Verbose ($protocol + " failed")
                    }
                    finally {
                         If ($SslStream -ne $null) { $SslStream.Close()}
                    }
                }
                If ($ServerProtocolsAccepted -eq $null) {Write-Host "No attempted protocols succeeded"}
                Else { Write-Host ("Server supports: " + $ServerProtocolsAccepted.ToUpper() ) }
                If ( $RemoteCertificate -ne $null ) {
                    Write-Verbose ("Certificate valid: " + $RemoteCertificate.Verify())
                    Write-Verbose ("Certificate issued to: " + $RemoteCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false))
                    Write-Verbose ("Certificate not good before: " + $RemoteCertificate.NotBefore )
                    Write-Verbose ("Certificate not good after: " + $RemoteCertificate.NotAfter )
                    }
                # Optional To-Do - Check cert chain
            }

#    5.	Bad proxy settings
            Write-Verbose "`nTODO: Check proxy config`n"
#        a.	Proxy misdirection
#        b.	Proxy authentication require
#        [net.httpwebRequest]::GetSystemWebProxy
#
# Failure after connect
#    1.	Failing Authentication
            If (($WebAddress.Scheme -eq "https") -and ($ServerProtocolsAccepted -eq $null)) {$testconnection = $false}
            If ( $testconnection ) {
                [net.httpWebResponse] $webresponse = SendWebRequest -url $WebAddress -verb "GET" -useragent $WCuseragent -cookiearray $null 
                $scnum = $webresponse.StatusCode.value__
                Write-Host ("Response: " + $scnum + " " + $webresponse.StatusDescription)
                If ($scnum -eq 401 ) {
                    If ($webresponse.Headers.count -gt 0) {
                        foreach ($headername in $webresponse.Headers) { 
                            If ($headername -eq "WWW-Authenticate" ) {
                                $headervalue = $webresponse.Headers.Get($headername) 
                                If ($headervalue -eq "NTLM"){$authntlm = $true}
                                ElseIf ($headervalue -eq "Negotiate") {$authnego = $true}
                                ElseIf ($headervalue -eq "Basic") {$authbasic = $true}
                                ElseIf ($headervalue -eq "Digest") {$authdigest = $true}
                                Write-Verbose ($headername +":" + $webresponse.Headers.Get($headername) )
                                
                            }
                            ElseIf ($headername.Contains(" ") ) { 
                                $spacedheader = $headername
                                Write-Verbose ($headername + ":" + $webresponse.Headers.Get($headername)) 
                                }
                            Else { Write-Verbose ($headername + ":" + $webresponse.Headers.Get($headername)) }
                            }
                        }
                    }
                Write-Verbose $webresponse.StatusCode.value__
            }

#        a.	NTLM or Kerberos - AuthForwardServerList
            If ($authntlm -or $authnego) { 
                Write-Verbose "`nTODO: Check AuthForwardServerList`n"
                $WCAFSL
                }
#        b.	Basic - not over SSL
            If ($authbasic) { Write-Verbose "`nTODO: Check BasicAuthLevel`n"
                $WCBasicauth
                }
#        c.	Claims/FBA - No persistent cookie passed
# WWW-Authenticate: IDCRL Type="BPOSIDCRL", EndPoint="/sites/Classic/_vti_bin/idcrl.svc/", RootDomain="sharepoint.com", Policy="MBI"
# X-MSDAVEXT_Error: 917656; Access+denied.+Before+opening+files+in+this+location%2c+you+must+first+browse+to+the+web+site+and+select+the+option+to+login+automatically.

            Write-Verbose "`nTODO: Add cookies to test FBA`n"
#            i.	Cookie not created persistent
#            ii.	Cookie not stored in shareable location
            $cookiesread = [Win32.WinInet]::GetCookieString($WebAddress) 
            Write-Verbose ("`nPersistent cookies for " + $WebAddress + " :`n" + $cookiesread )
#    2.	OPTIONS and/or PROPFIND verb blocked
            Write-Verbose "`nTODO: Check if OPTIONS or PROPFIND are blocked`n"
#    3.	PROPFIND returns bad results
            Write-Verbose "`nTODO: Validate PROPFIND results`n"
#        a.	XML missing
#        b.	XML malformed/gzipped
#    4.	Custom header name with space 
            If ($spacedheader.Length -gt 0) { Write-Verbose "`nHeader found that contains a space: " + $spacedheader + "`n"}
#    5.	Root site access
            Write-Verbose "`nTODO: Check root site access`n"
#        a.	No DAV at root
#        b.	No permissions at root
#        c.	Root site missing 

Exit $LASTEXITCODE
#
# Performance
#    1.	Slow to connect
#        a.	Auto-detect proxy unnecessarily selected
            Write-Verbose "`nTODO: Auto-detect proxy`n"
#        b.	SMB attempts receive no response before falling through to WebClient
			$start = Get-Date
			$smb = "SMB Connection is " + (Test-NetConnection $WebAddress.DnsSafeHost -Port 139 -InformationLevel Quiet)
			$smb = $smb + " and took " + (New-TimeSpan $start $(Get-Date) ).Seconds + " seconds"
            Write-Verbose $smb

			$start = Get-Date
			$smb2 = "SMB2 Connection is " + (Test-NetConnection $WebAddress.DnsSafeHost -Port 445 -InformationLevel Quiet)
			$smb2 = $smb2 + " and took " + (New-TimeSpan $start $(Get-Date) ).Seconds + " seconds"
            Write-Verbose $smb2

#        c.	The WebClient service was not already started
            If ($WCStartType -ne "Automatic") { Write-Host "For best performance, set the StartUp Type to 'Automatic'" }

#    2.	Slow to browse
            Write-Verbose "`nTODO: Check browsing scenarios`n"

#        a.	Read-Only Win32 attribute on SharePoint folders can cause unnecessary PROPFIND on contents.
#        b.	Too many items in the destination folder will result in slow response in Windows Explorer (may appear empty)

#    3.	Uploads fail to complete or are very slow
#        a.	PUT requests are blocked
#        b.	File exceeds file size limit
            Write-Host ("Current setting of FileSizeLimitInBytes is: " + $WCfilesize + " bytes")
#        c.	Upload takes longer than the Timeout setting
            Write-Host ("Upload throughput is limited to Filesize / 8kb * RTT " )
            If ( $testconnection ) {
                If (!((ping $WebAddress.DnsSafeHost -n 2 | Out-String ).Contains("Received = 0")) ) {
                    $rtt = (Test-Connection -ComputerName $WebAddress.DnsSafeHost | Measure-Object -Property ResponseTime -Average).Average | Out-Null
                    If ($rtt -gt 0 ) {
                        Write-Verbose ("Current Round Trip Time estimate is: " + $rtt + " milliseconds")
                        $WCesttimeupload = ($WCfilesize / 8192 * $rtt)
                        Write-Verbose ("Estimated time needed to upload a max file size of " +  $WCfilesize + " bytes: " + ($WCesttimeupload/1000) + " seconds" )
                        }
                    Else { Write-Verbose "Unable to determine RTT. Consider using PsPing from SysInternals to find the RTT" }
                }
                Else { Write-Verbose "Unable to use PING to determine RTT. Consider using PsPing from SysInternals to find the RTT" }
            }
            Write-Host ("The current setting for SendReceiveTimeoutInSec is: " + $WCtimeout )


#        return New-Object PsObject -Property $MsDavConnection
     }

}


function SendWebRequest([string] $url, [string] $verb, [string] $useragent, [string] $cookiearray = $null, [switch] $follow302=$true, [switch] $addcreds=$false, [switch] $showrequestheaders=$false, [switch] $NoFBA=$false)
{

	[net.httpWebRequest] $req = [net.webRequest]::create($url)
	$req.AllowAutoRedirect = $follow302
	$req.Method = $verb
    $req.UseDefaultCredentials = $addcreds
    If ($NoFBA){$req.Headers.Add("X-FORMS_BASED_AUTH_ACCEPTED","f") }
    If ( $useragent -ne $null ) {$req.UserAgent = $useragent}
    If ( $cookiearray.Length -gt 0) {
        $requestcookies = New-Object System.Net.CookieContainer
        foreach ($cookie in $cookiearray.Split(";") ) {
            $cookiename = $cookie.Split("=")[0]
            $cookievalue = $cookie.Substring($cookie.IndexOf("=") + 1)
            Write-Verbose ($cookiename + ", " +$cookievalue )
#            $requestcookies.Add($cookiename, $cookievalue)
        }
        $req.CookieContainer = $requestcookies
    }

	#Get Response
	try {
		[net.httpWebResponse] $res = $req.getResponse()
	}
	catch {
	  $res = $Error[0].Exception.InnerException.Response;
	  }
      
    Write-Host ("Request Method: $verb")
    #If ($showrequestheaders) {
        Write-Verbose ("Request Headers:")
	    foreach ($header in $req.Headers) { Write-Verbose ("`t" + $header + ":" + $req.Headers.Get($header)) }
        Write-Verbose ("`n")
	#    }

    return ($res)
}

function ReturnBody($response)
{
    if ($response.ContentLength -ge 0) {
        $responsestream = $response.getResponseStream() 
        $streamreader = New-Object IO.StreamReader($responsestream) 
        $body = $streamreader.ReadToEnd() 
    }

    return ($body)
}

cls

#Test-MsDavConnection -WebAddress http://yosaffbridge -Verbose
#Test-MsDavConnection -WebAddress https://silo-sps2013 -Verbose
Test-MsDavConnection -WebAddress http://www.bing.com -Verbose
#Test-MsDavConnection -WebAddress "https://onedrive.live.com/?id=root&cid=1B05166BD924884F" -Verbose
