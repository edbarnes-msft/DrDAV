﻿$deftesturl =  'https://www.myserver.com'

[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
[uri] $testurl = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the target web folder", "Web Address", $deftesturl)

$logpath = $env:TEMP+"\_DavTest"
New-Item -ItemType Directory -Force -Path $logpath > $null
$logfile = $logpath +"\"+$env:COMPUTERNAME+"_"+(Get-Date -Format yyddMMhhmm)+".log"
#$logfile = [Microsoft.VisualBasic.Interaction]::InputBox("Specify the logging file", "Log File", $logfile)

$outputverbose = $false

$WebClientTestSrc = @'
    [DllImport("ieframe.dll", CharSet = CharSet.Auto)]
    static extern int IEIsProtectedModeURL(string pszUrl);   
    public static int GetProtectedMode(string url)
    {
        return IEIsProtectedModeURL(url);
    }
    [DllImport("C:\\Windows\\System32\\wininet.dll", CharSet=CharSet.Auto, SetLastError=true)]
    static extern bool InternetSetCookie(string lpszUrl, string lpszCookieName, string lpszCookieData);
    public static bool SetCookieString(string url, string name, string value)
    {
        if (!InternetSetCookie(url, name, value)) { Console.Write( "Failed to set cookie. Error code: {0}. ", Marshal.GetLastWin32Error()); return false; }
        return true;
    }

    [DllImport("C:\\Windows\\System32\\wininet.dll", CharSet=CharSet.Auto, SetLastError=true)]
    static extern bool InternetGetCookieEx(string pchURL, string pchCookieName, System.Text.StringBuilder pchCookieData, ref System.UInt32 pcchCookieData, int dwFlags, IntPtr lpReserved);
    const int ERROR_NO_MORE_ITEMS = 259;
    const int flags = 0x00003000; // INTERNET_COOKIE_NON_SCRIPT  0x00001000, INTERNET_COOKIE_HTTPONLY 0x00002000
    public static string GetCookieString(string url)
    {
        // Determine the size of the cookie      
        UInt32 datasize = 256*1024; int iResult = 0; 
        System.Text.StringBuilder cookieData = new System.Text.StringBuilder(Convert.ToInt32(datasize));
        if (!InternetGetCookieEx(url, null, cookieData, ref datasize, flags, IntPtr.Zero)) {
            iResult = Marshal.GetLastWin32Error(); // Console.Write( "The request returned error {0}. ", iResult);
            if ((ERROR_NO_MORE_ITEMS == iResult) | (datasize < 0)) return null; // Console.Write( "Datasize {0}. ", datasize);
            // Allocate stringbuilder large enough to hold the cookie    
            cookieData = new System.Text.StringBuilder(Convert.ToInt32(datasize));
            if (!InternetGetCookieEx(url, null, cookieData, ref datasize, flags, IntPtr.Zero)) { Console.Write( "GetCookie request returned error {0}. ", iResult);return null;}
        }
        return cookieData.ToString();
    }

// referencing values from https://github.com/libgit2/libgit2/blob/master/deps/winhttp/winhttp.h
    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern IntPtr WinHttpOpen( [MarshalAs(UnmanagedType.LPWStr)] string pwszAgent, int   dwAccessType,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszProxy, [MarshalAs(UnmanagedType.LPWStr)] string pwszProxyBypass, int dwFlags );

    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern IntPtr WinHttpOpenRequest( IntPtr hConnect, [MarshalAs(UnmanagedType.LPWStr)] string pwszVerb, [MarshalAs(UnmanagedType.LPWStr)] string pwszObjectName,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszVersion, [MarshalAs(UnmanagedType.LPWStr)] string pwszReferrer, ref byte[] ppwszAcceptTypes, int dwFlags);

    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern IntPtr WinHttpConnect(IntPtr hSession, [MarshalAs(UnmanagedType.LPWStr)] string pswzServerName, short nServerPort, int dwReserved);

    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool WinHttpSetOption( IntPtr hInternet, int dwOption, byte[] lpBuffer, int dwBufferLength );

    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool WinHttpSendRequest( IntPtr hRequest, string pwszHeaders, int dwHeadersLength, string lpOptional, uint dwOptionalLength, uint dwTotalLength, int dwContext );

    [DllImport("winhttp.dll", SetLastError=true)]
    static extern bool WinHttpReceiveResponse(IntPtr hRequest, int lpReserved);

    [DllImport("winhttp.dll", SetLastError=true)]
    static extern bool WinHttpCloseHandle(IntPtr hInternet);

    static int WINHTTP_FLAG_SECURE = 0x00800000;
    static int WINHTTP_OPTION_SECURE_PROTOCOLS = 84;
    public static int WINHTTP_FLAG_SECURE_PROTOCOL_SSL3 = 0x00000020;    // decimal 32
    public static int WINHTTP_FLAG_SECURE_PROTOCOL_TLS1 = 0x00000080;    // decimal 128
    public static int WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 = 0x00000200;  // decimal 512
    public static int WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 = 0x00000800;  // decimal 2048

    static int WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0;
    //static int WINHTTP_ACCESS_TYPE_NO_PROXY = 1;
    //static int WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3;

    static int WINHTTP_OPTION_SECURITY_FLAGS = 31;
    static int SECURITY_FLAG_IGNORE_UNKNOWN_CA = 0x00000100;
    static int SECURITY_FLAG_IGNORE_CERT_DATE_INVALID = 0x00002000;
    static int SECURITY_FLAG_IGNORE_CERT_CN_INVALID = 0x00001000;
    static int SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE = 0x00000200;
    static int SECURITY_FLAG_IGNORE_ALL = SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_CERT_DATE_INVALID|SECURITY_FLAG_IGNORE_CERT_CN_INVALID|SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

    static byte[] WINHTTP_DEFAULT_ACCEPT_TYPES = null;
    static string WINHTTP_NO_ADDITIONAL_HEADERS = null;
    static string WINHTTP_NO_REQUEST_DATA = null;
    static string WINHTTP_NO_REFERER = null;
    static string WINHTTP_NO_PROXY_NAME = null;
    static string WINHTTP_NO_PROXY_BYPASS = null;

    public static int TestSsl(string url, short port, int ssl, bool bIgnoreBadCert)
    {
        int iResult = 0;
        IntPtr hSession = WinHttpOpen("WinHTTP SSL Test", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if( hSession != null ) {
            IntPtr hConnect = WinHttpConnect( hSession, url, port, 0 );
            if( hConnect != null ) {
                IntPtr hRequest = WinHttpOpenRequest( hConnect, "GET", "/", null, WINHTTP_NO_REFERER, ref WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                if (!WinHttpSetOption( hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, BitConverter.GetBytes(ssl), sizeof(int) )) Console.WriteLine( "Failed to set SSL");
                if ( bIgnoreBadCert ) {
                    if (!WinHttpSetOption( hRequest, WINHTTP_OPTION_SECURITY_FLAGS, BitConverter.GetBytes(SECURITY_FLAG_IGNORE_ALL), sizeof(int) )) Console.WriteLine( "Failed to set Ignore Bad Cert");
                    };
                if (!WinHttpSendRequest( hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 ) ){
                    iResult = Marshal.GetLastWin32Error();
                    Console.Write( "The request returned error {0}. ", iResult);
                    };
                if( hRequest != null ) WinHttpCloseHandle( hRequest );
                };
            if( hConnect != null ) WinHttpCloseHandle( hConnect );
            if( hSession != null ) WinHttpCloseHandle( hSession );
        };
        return iResult;
    }
'@ 

Add-Type -MemberDefinition $WebClientTestSrc  -Namespace WebClientTest -Name WinAPI 

[System.Management.Automation.PSCredential] $altcreds = $null
$auth_ntlm = $false; $auth_nego = $false; $auth_basic =$false; $auth_oauth = $false; $auth_fba = $false
$dblbar = "======================================================"
$wcshellminver7 = "6.1.7601.22498"; $wcminver7 = "6.1.7601.23542"; $winhttpminver7 = "6.1.7601.23375"
$wcminver8GDR = "6.2.9200.17428"; $wcminver8LDR = "6.2.9200.21538"; $winhttpminver8 = "6.2.9200.21797"
$wcminver81 = "6.3.9600.17923"; $wcrecver10 = "10.0.16299.334"
$newlocation = ""
$persistentcookies = ""
$propfindnodecount = 0

function Test-MsDavConnection {
    [CmdletBinding()] 
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true
            )][uri]$WebAddress 
        )
    begin {
        $ProgressPreference = 'SilentlyContinue'
        if ($PSVersionTable.PSVersion.Major -eq 2){ $osverstring = [environment]::OSVersion.Version.ToString() } 
        else { $osverstring = $(Get-CimInstance Win32_OperatingSystem).Version }
        $osver = [int] ([convert]::ToInt32($osverstring.Split('.')[0], 10) + [convert]::ToInt32($osverstring.Split('.')[1], 10))
        $osname = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
        if ($osver -eq 10) { $osname = $osname + " " + (Get-ComputerInfo).WindowsVersion }
        $defaultNPO = ('RDPNP,LanmanWorkstation,webclient')
        $WCfilesize = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").FileSizeLimitInBytes 
        $WCattribsize = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").FileAttributesLimitInBytes 
        $WCtimeout = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").SendReceiveTimeoutInSec  
        $npo = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order").ProviderOrder
        $hnpo = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder").ProviderOrder
        $WCBasicauth = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").BasicAuthLevel
        $WCAFSL = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").AuthForwardServerList
        if ($WCAFSL.length -eq 0 ) {$WCAFSLOut = "Not configured or empty" } else { $WCAFSLOut = $WCAFSL } 
        $sslprotocols=[string]::Join(" ",([enum]::GetNames([System.Security.Authentication.SslProtocols])|?{$_ -notmatch 'none|default|ssl2'} ) ) #ssl3|tls|tls11|tls12(|tls13)
        $IgnoreBadCert = $true
        $WCuseragent = "Microsoft-WebDAV-MiniRedir/" + $osverstring
        $fso = New-Object -comobject Scripting.FileSystemObject
        $Webclntdll = $fso.GetFileVersion('C:\Windows\System32\webclnt.dll')
        $Davclntdll = $fso.GetFileVersion('C:\Windows\System32\davclnt.dll')
        $Mrxdavsys = $fso.GetFileVersion('C:\Windows\System32\drivers\mrxdav.sys')
        $Shell32dll = $fso.GetFileVersion('C:\Windows\System32\shell32.dll')
        $WinHttpdll = $fso.GetFileVersion('C:\Windows\System32\winhttp.dll')
        $WebIOdll =  $fso.GetFileVersion('C:\Windows\System32\webio.dll')
        $ProgressPreference = 'Continue'
    }

    process {
        $MsDavConnection = @{
            ClientName=[environment]::MachineName
            ClientOS = $osname
            ClientOSVersion = $osverstring
            ClientWebIO=$WebIOdll
            ClientWinHttp=$WinHttpdll
            ClientShell32=$Shell32dll
            ClientWebclnt=$Webclntdll
            ClientDavclnt=$Davclntdll
            ClientMrxdav=$Mrxdavsys
            ClientNetProviders=$npo
            ServerName=$WebAddress.DnsSafeHost
            ServerPort=$WebAddress.Port
            ServerScheme=$WebAddress.Scheme
            TargetUrl=$WebAddress
            AuthForwardServerList = $WCAFSLOut
            BasicAuthLevel=$WCBasicauth
            FileSizeLimitInBytes = $WCfilesize.ToString("N0")
            FileAttributesLimitInBytes = $WCattribsize.ToString("N0")
            SendReceiveTimeoutInSec = $WCtimeout.ToString("N0")
            Currentuser=$([environment]::UserDomainName + "\" + [environment]::UserName)
            }    

            
            foreach ($i in $MsDavConnection.GetEnumerator()) { Write-ToLogVerbose $($i.Key + " : " + $i.Value).ToString() }
            Write-Host "Microsoft WebClient Service Diagnostic check" -ForegroundColor Yellow -BackgroundColor DarkBlue
            Write-Host ("Client Name =         " + [environment]::MachineName)
            Write-Host ("OS =                  " + $osname)
            Write-Host ("OS version =          " + $osverstring )
            Write-Host "Webclnt.dll version ="$Webclntdll
            Write-Host "Davclnt.dll version ="$Davclntdll
            Write-Host "Mrxdav.sys version = "$Mrxdavsys
            Write-Host "Shell32.dll version ="$Shell32dll
            Write-Host "WinHttp.dll version ="$WinHttpdll
            Write-Host "WebIO.dll version =  "$WebIOdll

            Write-Host
            if ($WebAddress.Host.Length -gt 0) {
                Write-Host "TargetUrl ="$WebAddress
                Write-Host "ServerName ="$WebAddress.DnsSafeHost
                Write-Host "ServerPort ="$WebAddress.Port
                Write-Host "ServerScheme ="$WebAddress.Scheme
                Write-Host
            }
            Write-Host "Network Provider Order =`n`t"$npo
            Write-Host "`nWebClient Parameters:`n`tBasicAuthLevel ="$WCBasicauth
            Write-Host "`tAuthForwardServerList ="$WCAFSL
 

            Write-ToLog ("`n" + $dblbar + "`n")
            

# Fail to Connect
#    1.	WebClient not installed or disabled
        $WCSvc = Get-Service | where { $_.Name -eq 'webclient' }
        if ($WCSvc -ne $null) 
            { 
                $WCStartNum = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\WebClient").Start 
                switch ($WCStartNum) {
                "2"  { $WCStartType = "Automatic" }
                "3"  { $WCStartType = "Manual" }
                "4"  { $WCStartType = "Disabled" }
                }
                Write-ToLog ("The WebClient service StartUp type is: " + $WCStartType)
                if ( ($WCStartType -ne "Manual" ) -and
                    ($WCStartType -ne "Automatic" ) )
                    { Write-ToLogWarning "WebClient service Start Type should be set to Manual or Automatic." }
                Write-ToLog "Manual is default but Automatic is preferred if the service is used frequently"
            } 
            else
            {
                Write-ToLogWarning "WebClient service is not present"
            }
# File version check
        if ( ($WebAddress.Scheme -eq "https") -and (($osver -eq 7) -or ($osver -eq 8)) ){ # https://support.microsoft.com/en-us/help/3140245
            if ($osver -eq 7) { 
                if ( !((Check-Version $WinHttpdll $winhttpminver7 ) -and (Check-Version $WinHttpdll $winhttpminver7 )) ){ 
                    Write-ToLogWarning ("WinHttp.Dll and WebIO.Dll should be updated to allow highest Secure Protocol versions - https://support.microsoft.com/en-us/help/3140245") 
                    }
                if ( !(Check-Version $Shell32dll $wcshellminver7 ) ){ Write-ToLogWarning ("Shell32.dll should be updated to address a known issue") }
                if ( !((Check-Version $Webclntdll $wcminver7 ) -and (Check-Version $Davclntdll $wcminver7 ) -and (Check-Version $Mrxdavsys $wcminver7 )) ){ 
                    Write-ToLogWarning ("The WebClient files should be updated to allow highest Secure Protocol versions") 
                    }
                }
            if ($osver -eq 8) { 
                if ( !((Check-Version $WinHttpdll $winhttpminver8 ) -and (Check-Version $WinHttpdll $winhttpminver8 )) ){ 
                    Write-ToLogWarning ("WinHttp.Dll and WebIO.Dll should be updated to allow highest Secure Protocol versions - https://support.microsoft.com/en-us/help/3140245") 
                    }
                if ( [convert]::ToInt32($Webclntdll.Split('.')[0], 10) -lt 20000 ) {
                    if ( !((Check-Version $Webclntdll $wcminver8GDR ) -and (Check-Version $Davclntdll $wcminver8GDR )) ){ 
                        Write-ToLogWarning ("The WebClient files should be updated to allow highest Secure Protocol versions") 
                        }
                    } 
                    else {
                        if ( !((Check-Version $Webclntdll $wcminver8LDR ) -and (Check-Version $Davclntdll $wcminver8LDR )) ){ 
                            Write-ToLogWarning ("The WebClient files should be updated to allow highest Secure Protocol versions") 
                        }
                    }
                }
            if ($osver -eq 9) { 
                if ( !((Check-Version $Webclntdll $wcminver81 ) -and (Check-Version $Davclntdll $wcminver81 )) ){ 
                            Write-ToLogWarning ("The WebClient files should be updated to allow highest Secure Protocol versions") 
                    }
                }
    
            }

        if (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" | Select-Object -ExpandProperty DefaultSecureProtocols -ErrorAction SilentlyContinue | Out-Null){
            $dsp = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp").DefaultSecureProtocols 
            if ($osver -eq 10) {
                if ($dsp -ne $null ) {Write-ToLogWarning "WinHttp registry entry is: " + $dsp.ToString('x2').ToUpper() }
            } else {
                if ($dsp -eq $null ) {Write-ToLogWarning "WinHttp registry entry is absent" } else { Write-ToLog ("WinHttp registry entry is: " + $dsp.ToString('x2').ToUpper() ) }
            }
        }
        if ([environment]::GetEnvironmentVariable("ProgramFiles(x86)").Length -gt 0){
            if (Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"){
                if (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" | Select-Object -ExpandProperty DefaultSecureProtocols -ErrorAction SilentlyContinue | Out-Null){
                    $dspwow = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp").DefaultSecureProtocols
                }
            }
            if ($osver -eq 10) {
                if ($dspwow -ne $null ) {Write-ToLogWarning "WinHttp WOW6432 registry entry is: " + $dspwow.ToString('x2').ToUpper() }
            } else {
                if ($dspwow -eq $null ) {Write-ToLogWarning "WinHttp WOW6432 registry entry is absent" } else { Write-ToLog ("WinHttp WOW6432 registry entry is: " + $dspwow.ToString('x2').ToUpper() ) }
            }
        }  
        
                                   
        $strongcrypt = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319").SchUseStrongCrypto
        if ($strongcrypt -eq $null ) {Write-ToLogVerbose "SchUseStrongCrypto registry entry is absent" } else { Write-ToLogVerbose ("SchUseStrongCrypto registry entry for v4 is: " + $strongcrypt) }
        if ([environment]::GetEnvironmentVariable("ProgramFiles(x86)").Length -gt 0){
            $strongcryptwow = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319").SchUseStrongCrypto
            if ($strongcryptwow -eq $null ) {Write-ToLogVerbose "SchUseStrongCrypto WOW6432 registry entry is absent" } else { Write-ToLogVerbose ("SchUseStrongCrypto WOW6432 registry entry for v4 is: " + $strongcryptwow) }
        }     
           
        $strongcrypt2 = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727").SchUseStrongCrypto
        if ($strongcrypt2 -eq $null ) {Write-ToLogVerbose "SchUseStrongCrypto registry entry is absent" } else { Write-ToLogVerbose ("SchUseStrongCrypto registry entry for v2 is: " + $strongcrypt2) }
        if ([environment]::GetEnvironmentVariable("ProgramFiles(x86)").Length -gt 0){
            $strongcryptwow2 = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727").SchUseStrongCrypto
            if ($strongcryptwow2 -eq $null ) {Write-ToLogVerbose "SchUseStrongCrypto WOW6432 registry entry is absent" } else { Write-ToLogVerbose ("SchUseStrongCrypto WOW6432 registry entry for v2 is: " + $strongcryptwow2) }
        }        
              
        $sysdeftlsver = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727").SystemDefaultTlsVersions
        if ($sysdeftlsver -eq $null ) {Write-ToLogVerbose "SystemDefaultTlsVersions registry entry is absent" } else { Write-ToLogVerbose ("SystemDefaultTlsVersions registry entry is: " + $sysdeftlsver) }
        if ([environment]::GetEnvironmentVariable("ProgramFiles(x86)").Length -gt 0){
            $sysdeftlsverwow = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727").SystemDefaultTlsVersions
            if ($sysdeftlsverwow -eq $null ) {Write-ToLogVerbose "SystemDefaultTlsVersions WOW6432 registry entry is absent" } else { Write-ToLogVerbose ("SystemDefaultTlsVersions WOW6432 registry entry is: " + $sysdeftlsverwow) }
        }          

        Write-ToLog ("Client Secure Protocols enabled for .Net: " + $sslprotocols.ToUpper() ) 
      
#    2.	Bad Network Provider order
#       a.	WebClient missing from provider order
        $npomsg = "`r`nNetwork Provider Order check: "
        $npocheck = 'Good'
        if ($npo.ToLower() -ne $hnpo.ToLower()) { 
            $npocheck = 'HwOrder doesn''t match Order' 
            Write-ToLogWarning ($npocheck +"`r`n`tOrder: " + $npo + "`r`n`tHwOrder: " + $hnpo)
            }
        if ( !("," + $hnpo +",").ToLower().Contains(",webclient,") -or !("," + $npo +",").ToLower().Contains(",webclient,") ) {
            $npocheck = 'WebClient is missing from provider list' 
            Write-ToLogWarning ($npomsg + $npocheck + "`r`n`tOrder: " + $npo )
            }
#       b.	Third-party providers interfering
        if ( ($npocheck -eq "Good") -and ($npo.ToLower() -ne $defaultnpo.ToLower()) ) { 
            $npocheck = 'Order doesn''t match Default' 
            Write-ToLog ($npomsg + $npocheck + "`r`n`tOrder: " + $npo + "`r`n`tDefault order: $defaultnpo")
            }
        if ( $npocheck -eq "Good") { Write-ToLog ($npomsg + $npocheck) }


        if ($WebAddress.Host.Length -eq 0) {Start-Process ($env:windir + "\explorer.exe")  -ArgumentList $((Get-ChildItem $logfile).DirectoryName) ;Exit}
#==========================================================================
#    Only test below if WebAddress is passed

        $rootweb = $WebAddress.Scheme + "://" + $WebAddress.DnsSafeHost; $matchfound = $false
            
#    3.	Port blocked
        $starttime = Get-Date
        # New-Object System.Net.Sockets.TcpClient($WebAddress.DnsSafeHost,$WebAddress.Port)
        $ns = New-Object System.Net.Sockets.TcpClient
        try { $ns.Connect($WebAddress.DnsSafeHost, $WebAddress.Port ) } catch {}
        $rtt = (New-TimeSpan $starttime $(Get-Date) ).Milliseconds
        if( $ns.Connected) {$testconnection = $true; $ns.Close()}
        $davport = $davport + "Connection to " + $WebAddress.DnsSafeHost + " on port " + $WebAddress.Port + " was " 
        if ($testconnection -eq $true ) { $davport = $davport + "successful and took " + $rtt + " milliseconds" }
        else { $davport = $davport + "not successful"; $rtt=0}
        Write-ToLog $davport

# Internet Settings Security Zone information
# https://support.microsoft.com/en-us/help/182569/internet-explorer-security-zones-registry-entries-for-advanced-users
        $IEZone = [System.Security.Policy.Zone]::CreateFromUrl($WebAddress).SecurityZone
        $IEPMode = [WebClientTest.WinAPI]::GetProtectedMode($WebAddress)
        if ( $IEPMode -eq 0 ) {$ProtectMode = "Enabled"}
        elseif ( $IEPMode -eq 1 ) {$ProtectMode = "Not Enabled"}
        else {$ProtectMode = "Unknown"}

        Write-ToLog ("$WebAddress is in the $IEZone Security Zone and Protect Mode value is " + $ProtectMode + "`r`n")

        $internettestzone = "http://doesntexist.edbarnes.net"
        if([System.Security.Policy.Zone]::CreateFromUrl($internettestzone).SecurityZone -eq "Internet"){
            if ( [WebClientTest.WinAPI]::GetProtectedMode($internettestzone) -ne 0 ) {
            Write-ToLogWarning ("The Internet Security Zone is not enabled for Protect Mode. This is a security risk!`r`n") }
        }
        
        $ActiveXCheck = $(Get-Item -Path ("HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\" + $IEZone.value__)).GetValue('2000')
        if ( $ActiveXCheck -eq 0 ) {$ActiveXEnabled = "Enabled"}
        elseif ( $ActiveXCheck -eq 1 ) {$ActiveXEnabled = "Prompt"}
        elseif ( $ActiveXCheck -eq 3 ) {$ActiveXEnabled = "Disabled"}
        else {$ActiveXEnabled = "Unknown"}
        Write-ToLogVerbose ("Checking if ActiveX is enabled. Value identified: " + $ActiveXEnabled)

        if ((Test-Path ("HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\" + $IEZone.value__)) -eq $false){
            Write-ToLogVerbose ("No ActiveX Policy found`n")
            }
            else {
            $ActiveXPolicyCheck = $(Get-Item -Path ("HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\" + $IEZone.value__)).GetValue('2000')
            if ( $ActiveXPolicyCheck -eq 0 ) {$ActiveXPolicyEnabled = "Enabled"}
            elseif ( $ActiveXPolicyCheck -eq 1 ) {$ActiveXPolicyEnabled = "Prompt"}
            elseif ( $ActiveXPolicyCheck -eq 3 ) {$ActiveXPolicyEnabled = "Disabled"}
            else {$ActiveXPolicyCheck = "Unknown"}
            Write-ToLogVerbose ("Checking if ActiveX Policy is enabled. Value identified: " + $ActiveXPolicyEnabled +"`n")
            }
      
#    3.	Version of SSL/TLS not supported by destination server
        if ( ($testconnection -eq $true) -and ($WebAddress.Scheme -eq "https") ) {
            $ServerProtocolsAccepted = $null; [int] $iBestSsl = 0;
            if ([WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, 32, $IgnoreBadCert ) -eq 0 ) 
                { Write-ToLogVerbose "The server supports SSL3"; $ServerProtocolsAccepted = $ServerProtocolsAccepted + " SSL3" ; $iBestSsl = 32 ; $sBestSsl = "SSL3" } 
            else { Write-ToLog "The server does not support SSL3" }

            if ([WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, 128, $IgnoreBadCert ) -eq 0 ) 
                { Write-ToLogVerbose "The server supports TLS 1.0"; $ServerProtocolsAccepted = $ServerProtocolsAccepted + " TLS1" ; $iBestSsl = 128 ; $sBestSsl = "TLS1" } 
            else { Write-ToLog "The server does not support TLS 1.0" }

            if ([WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, 512, $IgnoreBadCert ) -eq 0 ) 
                { Write-ToLogVerbose "The server supports TLS 1.1"; $ServerProtocolsAccepted = $ServerProtocolsAccepted + " TLS11" ; $iBestSsl = 512 ; $sBestSsl = "TLS11" } 
            else { Write-ToLog "The server does not support TLS 1.1" }

            if ([WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, 2048, $IgnoreBadCert ) -eq 0 ) 
                { Write-ToLogVerbose "The server supports TLS 1.2"; $ServerProtocolsAccepted = $ServerProtocolsAccepted + " TLS12" ; $iBestSsl = 2048 ; $sBestSsl = "TLS12" } 
            else { Write-ToLog "The server does not support TLS 1.2" }

            if ($ServerProtocolsAccepted -eq $null) {Write-ToLog "No attempted protocols succeeded"}
            else {$ServerProtocolsAccepted = $ServerProtocolsAccepted.Substring(1); Write-ToLog ( "Server supports: " + $ServerProtocolsAccepted.ToUpper() ) }


#    4.	Certificate is expired or doesn't match
            $certcheck = [WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, $iBestSsl, $false )
            if ($certcheck -eq 0 ) 
                { Write-ToLogVerbose "No certificate problem observed"} 
            else { 
                switch ($certcheck ) {
                    "12037"  { Write-ToLog "Certificate Error Invalid Date" }
                    "12038"  { Write-ToLog "Certificate Error Invalid Common Name" }
                    "12044"  { Write-ToLog "Client Authentication Certificate Needed" }
                    "12045"  { Write-ToLog "Certificate CA is Invalid" }
                    "12169"  { Write-ToLog "Invalid Certificate" }      
                    "12179"  { Write-ToLog "Invalid Usage for Certificate" }  
                    default  { Write-ToLog "Certificate failure: $certcheck`r`n"}                 
                    }
                }
            Test-SslCert $WebAddress.DnsSafeHost $WebAddress.Port $sBestSsl
            # Optional ToDo - Check cert chain
            }


#    5.	Bad proxy settings
            Write-ToLogVerbose "TODO: Check proxy config"
#        a.	Proxy misdirection
#        b.	Proxy authentication require
#        [net.httpwebRequest]::GetSystemWebProxy
#
# Failure after connect
#    1.	Failing Authentication
        if ( $testconnection ) {
            Write-ToLog ("`n`n" + $dblbar + "`r`n** Determining authentication mode **")
            $global:newlocation = $WebAddress
            $verb = "HEAD"
            $followredirect = $false
            $addcookies = $false
            $credtype = "Anonymous" # 3 choices = "Anonymous", "DefaultCreds", "AlternateCreds"
            $maxtry = 5
            do {
                $responseresult = SendWebRequest -url $global:newlocation -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
                Write-ToLogVerbose ("Result: $responseresult `r`n")
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
            if (($global:auth_ntlm -or $global:auth_nego) -and ($rootweb.Contains("."))) { 
            Write-ToLog ("`n`n" + $dblbar + "`r`nWindows Authentication accepted with FQDN url : Testing AuthForwardServerList")
                # Validate target url against AuthForwardServerList
                if ($WCAFSL.length -eq 0 ) {Write-ToLogWarning ("AuthForwardServerList registry value is not configured or empty") }
                    else { 
                        $WCAFSL | ForEach-Object -Process {
                                     if ( $rootweb -like $_ ) {
                                        $matchfound = $true
                                        Write-ToLog ("The path $rootweb was matched to " + $_ )
                                        }
                                     }
                        if ( $matchfound -eq $false ) { Write-ToLogWarning ("The path $rootweb was not matched in AuthForwardServerList.") }
                }
                Write-ToLog ($dblbar + "`r`n`n")
            }
#        b.	Basic - not over SSL
            if ($global:auth_basic) { 
                Write-ToLog ("`n`n" + $dblbar + "`r`nBasic Authentication accepted : Testing BasicAuthLevel`r`n")                
                switch ($WCBasicauth) {
                "0"  {Write-ToLogWarning ("BasicAuthLevel is 0; use of Basic Authentication is disabled" ) }
                "1"  {
                        if ($WebAddress.Scheme -eq "http") {
                            Write-ToLogWarning ("BasicAuthLevel is 1; use of Basic Authentication over HTTP is disabled" ) }
                            else { Write-ToLog ("BasicAuthLevel is 1; use of Basic Authentication over HTTPS is enabled" ) }
                        }
                "2"  {Write-ToLogWarning ("BasicAuthLevel is 2; use of Basic Authentication is enabled for both HTTP and HTTPS - This could be a security risk" ) }
                }
                Write-ToLog ("Note: If Basic Authentication is allowed and used, there will always be a credential prompt`r`n" + $dblbar + "`r`n") 
            }

#        c.	Claims/FBA - No persistent cookie passed
            if ($global:auth_fba) { 
                Write-ToLog ("`n`n" + $dblbar + "`r`nFBA or SAML Claims Authentication accepted : Testing Persistent cookies`r`n") 
                Write-ToLog ("This authentication mode requires a persistent, sharable authentication cookie be available") 
#            i.	Cookie not created persistent
#            ii.	Cookie not stored in shareable location
                if ( $IEPMode -eq 0 ) {Write-ToLogWarning ("Protect Mode is enabled for the $IEZone Security Zone so Persistent cookies cannot be shared.")}
                elseif ( $IEPMode -eq 1 )  {Write-ToLog ("Protect Mode is not enabled for the $IEZone Security Zone so Persistent cookies can be shared.")}
                $global:persistentcookies = [WebClientTest.WinAPI]::GetCookieString($WebAddress) 
                if ($global:persistentcookies.length ) {
                    Write-ToLog ("`r`nPersistent Cookies:`n===================")
                    $global:persistentcookies.split("; ") | ForEach-Object{ 
                         $cookie = $_
                         #if ($cookie.Length -gt 7){ if ($cookie.Substring(0,7) -eq "FedAuth") {$fedauth = $cookie.Substring(8)}  }
                         Write-ToLog "`t$cookie"
                    }
                } else { Write-ToLog "`tNo persistent cookies found" }
                Write-ToLog ( $dblbar + "`r`n")
            }

#    2.	OPTIONS and/or PROPFIND verb blocked
        if ( $testconnection ) {
            Write-ToLog ("`n`n" + $dblbar + "`r`n** Check if OPTIONS or PROPFIND are blocked **")
            $verb = "OPTIONS"
            $responseresult = SendWebRequest -url $WebAddress -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
            $verb = "PROPFIND"
            $responseresult = SendWebRequest -url $WebAddress -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
#    3.	PROPFIND returns bad results
#        a.	XML missing
#        b.	XML malformed/gzipped
#        Checked on every PROPFIND response    
#    4.	Custom header name with space 
#        Checked each time headers are read  
#    5.	Root site access
#        a.	No DAV at root
#        b.	No permissions at root
#        c.	Root site missing 
            if ($rootweb -ne $WebAddress ){
                Write-ToLog ("`n`r`n" + $dblbar + "`r`n** Checking root site access **")
                $verb = "PROPFIND"
                $responseresult = SendWebRequest -url $rootweb -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
            }
        }


#
# Performance
            Write-ToLog ("`r`n" + $dblbar + "`r`n** Performance considerations **")
#    1.	Slow to browse
            $verb = "PROPFIND"
            $responseresult = SendWebRequest -url $WebAddress -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect -usecreds $credtype -depth 1
            Write-ToLog "Check browsing performance scenarios (by testing number of discovered items)"

#        a.	Read-Only Win32 attribute on SharePoint folders can cause unnecessary PROPFIND on contents.
#        b.	Too many items in the destination folder will result in slow response in Windows Explorer (may appear empty)
            Write-ToLog "`tNumber of items queried: $global:propfindnodecount `r`n"
            if ($global:propfindnodecount -gt 1000) {
                Write-ToLogWarning ("`tA high number of items in the folder have been detected")
                if (($global:propfindnodecount*1000) -gt $WCattribsize){Write-ToLogWarning ("`tIncrease the FileAttributesLimitInBytes value. See KB 912152")}
            Write-ToLog ("Current setting of FileAttributesLimitInBytes is: " + $WCattribsize.ToString("N0") + " bytes`r`n")
            }

#    2.	Uploads fail to complete or are very slow
#        a.	PUT requests are blocked
            # TODO Test PUT
#        b.	File exceeds file size limit
            Write-ToLog ("Current setting of FileSizeLimitInBytes is: " + $WCfilesize.ToString("N0") + " bytes")
#        c.	Upload takes longer than the Timeout setting
            Write-ToLog ("`tUpload throughput is limited to approximately (Filesize / 8kb * RTT)" )
            if ($rtt -gt 0 ) {
                Write-ToLog ("`tCurrent Round Trip Time estimate is: " + $rtt + " milliseconds")
                $WCesttimeupload = ($WCfilesize / 8192 * $rtt)
                Write-ToLog ("`tEstimated time needed to upload a max file size of " +  $WCfilesize.ToString("N0") + " bytes: " + ($WCesttimeupload/1000).ToString("N0") + " seconds" )
            }
            else { Write-ToLog "`tUnable to determine RTT. Consider using PsPing from SysInternals to find the RTT" }

            Write-ToLog ("The current client setting for SendReceiveTimeoutInSec is: " + $WCtimeout )
#        d.	Number of file causes total attribute to exceeds attribute size limit
#        	See 2b below

#    3.	Slow to connect
#        a.	The WebClient service was not already started
          if ($WCStartType -ne "Automatic") { Write-ToLog "For best performance, set the StartUp Type to 'Automatic'" }
#        b.	SMB attempts receive no response before falling through to WebClient
            Write-ToLog "`nTesting SMB and SMB2 connectivity - using UNC will try SMB before using WebDAV and can cause a delay if blocked improperly"

            # New-Object System.Net.Sockets.TcpClient($WebAddress.DnsSafeHost,$WebAddress.Port)
            $ns = New-Object system.net.sockets.tcpclient

			$starttime = Get-Date
            try { $ns.Connect($WebAddress.DnsSafeHost, 139 ) } catch {}
            $smbresponsetime = (New-TimeSpan $starttime $(Get-Date) ).Seconds
            $ns.Close()

            $smb = "`tSMB test connection took " + $smbresponsetime + " seconds"
			if ($smbresponsetime -gt 30) {Write-ToLogWarning ($smb) }
            else { Write-ToLog ($smb) }

            $ns2 = New-Object system.net.sockets.tcpclient
			$starttime2 = Get-Date
            try { $ns2.Connect($WebAddress.DnsSafeHost, 445 ) } catch {}
            $smb2responsetime = (New-TimeSpan $starttime2 $(Get-Date) ).Seconds
            $ns2.Close()

            $smb2 = "`tSMB2 test connection took " + $smb2responsetime + " seconds"
			if ($smb2responsetime -gt 30) {Write-ToLogWarning ($smb2) }
            else { Write-ToLog ($smb2) }


#        c.	Auto-detect proxy unnecessarily selected
            Write-ToLogVerbose "`nTODO: Auto-detect proxy`n"

#        return New-Object PsObject -Property $MsDavConnection
     }

}


function SendWebRequest([uri] $url, [string] $verb, [string] $useragent, $includecookies = $false, $follow302=$true, [string] $usecreds, $depth=0)
{
    if ($depth){$depthnotice = " with Depth of 1"} else { $depthnotice = ""}
    Write-ToLog ($dblbar + "`r`n`r`n" + $verb + " test to $url" + $depthnotice)
    Write-ToLogVerbose ("`tUserAgent: " + $useragent + " Cookies:" + $includecookies + " Follow302:" + $follow302 + " CredType:" + $usecreds)

    [net.httpWebRequest] $req = [net.webRequest]::Create($url)

    $req.CookieContainer = New-Object System.Net.CookieContainer
    if ( $includecookies -eq $true ) {
        $gcresult = [WebClientTest.WinAPI]::GetCookieString($url); 
        if ($gcresult.Length ){ 
            $cookiesread = $gcresult.Split(";")
            $cookiesread | ForEach-Object { $req.CookieContainer.SetCookies($url,$_.Trim()) }
        }
    }

    switch ($usecreds) 
    { 
        "Anonymous" {$req.Credentials = $null }
        "DefaultCreds" {$req.UseDefaultCredentials = $true }
        "AlternateCreds" {
            if ($global:altcreds -eq $null){$global:altcreds = Get-Credential }

            $req.Credentials = $global:altcreds
            }
    }

	$req.AllowAutoRedirect = $follow302
	$req.Method = $verb
    if ( $useragent -ne $null ) {$req.UserAgent = $useragent}
    if ( $req.Method -eq "PROPFIND" ) { $req.Headers["Depth"] = $depth }

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
            Write-ToLogWarning ( ($Error[0].Exception.InnerException).status)
        }
    }

    Write-ToLogVerbose ("Request Headers:")
    foreach ($h in $req.Headers) { Write-ToLogVerbose ("`t" + $h + ": " + $req.Headers.GetValues($h)) }

    if ($res -ne $null)
    {
        Write-ToLog ("`tResponse Status Code: " + $res.StatusCode.value__ + " " + $res.StatusCode)
        Write-ToLogVerbose ("`tResponse Cookies: " + $res.Cookies.Count)
        foreach ($c in $res.Cookies) { Write-ToLogVerbose ("`t`t" + $c.Name + " " + $c.Value) }

        Write-ToLogVerbose ("`tResponse Headers: " + $res.Headers.Count)
        foreach ($h in $res.Headers)
        {
            
            switch -Wildcard($h){
                "WWW-Authenticate" { 
                    Write-ToLogVerbose ("`t`t" + $h )
                    foreach ($a in $res.Headers.GetValues($h)) {
                        Write-ToLogVerbose "`t`t`t"$a
                        if ($a -like "NTLM*") { $global:auth_ntlm = $true }
                        if ($a -like "Nego*") { $global:auth_nego = $true }
                        if ($a -like "Basic*") { $global:auth_basic = $true }
                        # WWW-Authenticate: IDCRL Type="BPOSIDCRL", EndPoint="/sites/Classic/_vti_bin/idcrl.svc/", RootDomain="sharepoint.com", Policy="MBI"
                        if ($a -like "IDCRL*") { $global:auth_oauth = $true }
                        }
                    Break
                    }
                "MicrosoftSharePointTeamServices" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Set-Cookie" { 
                    Write-ToLogVerbose ("`t`t" + $h)
                    foreach ($c in $res.Headers.GetValues($h)) {
                        Write-ToLogVerbose ("`t`t`t" + $c)
                        }
                    Break
                    }
                "Allow" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Date" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Location" { $newlocation = $res.Headers.GetValues($h) ;Write-ToLogVerbose ("`t`t" + $h + ":`t" + $newlocation) ; Break }
                "Content-Type" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Content-Encoding" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "request-id" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                # X-MSDAVEXT_Error: 917656; Access+denied.+Before+opening+files+in+this+location%2c+you+must+first+browse+to+the+web+site+and+select+the+option+to+login+automatically.
                "X-MSDAVEXT_Error" { 
                    $global:auth_fba = $true ; 
                    if ($includecookies){
                        Write-ToLogWarning ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h))
                    }
                        Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h))
                    Break 
                    }
                "X-FORMS_BASED_AUTH_REQUIRED" { $global:auth_fba = $true ; Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "FORMS_BASED_AUTH_RETURN_URL" { $global:auth_fba = $true ; Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "*" { Write-ToLogVerbose ("`t`t? " + $h + ": " + $res.Headers.GetValues($h))}
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
        if ($follow302 -eq $false ) {$statuscheck = "AddFollow302" ; Write-ToLog ("Redirected to $newlocation")}
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
        Add-Content $($logpath + "\Response_" + (Get-Date -Format hhmmss) + ".txt")  -Value $body
    }
    # Test if body is valid XML

    # Check for Load or Parse errors when loading the XML file
    $xml = New-Object System.Xml.XmlDocument
    try {
        $xml.LoadXml($body)
        Write-ToLog "`tPROPFIND response is valid XML"
        $nodecnt = $xml.ChildNodes.response.Count - 1
        if ($nodecnt -gt $global:propfindnodecount){
            $global:propfindnodecount = $nodecnt
            Write-ToLogVerbose "`tNumber of items: $nodecnt"
        }
    }
    catch [System.Xml.XmlException] {
        Write-ToLogWarning "PROPFIND response is not valid XML: $($_.toString())"
    }

}

function Check-Version($tval, $bval)
{  $t = $tval.Split("."); $b = $bval.Split(".")
    if ($t[0] -ge $b[0]){
        if ($t[1] -ge $b[1]){
            if ($t[2] -ge $b[2]){
                if ($t[3] -ge $b[3]){ return $true }
            }
        }
    }
    return $false
}

function Test-SslCert {
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            ValueFromPipeline=$true
        )]$destHostName,
        [Parameter(
            ValueFromPipelineByPropertyName=$true
        )][int]$destPort,
        [ValidateSet("SSL3", "TLS", "TLS11", "TLS12", IgnoreCase = $true)]
        [Parameter(
            ValueFromPipelineByPropertyName=$true
        )]$destProtocol 
    )

    $Callback = { param($sender, $cert, $chain, $errors) return $true }
    $Socket = New-Object System.Net.Sockets.Socket('Internetwork','Stream', 'Tcp')
    $Socket.Connect($destHostName, $destPort)
    try {
        $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
        $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true, $Callback)
        $SslStream.AuthenticateAsClient($destHostName,  $null, $destProtocol, $false )
        $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
        Write-ToLog  ('Cert info - Host name(s): ' + $RemoteCertificate.DnsNameList)
        Write-ToLog  ('Cert info - Not Before: ' + $RemoteCertificate.NotBefore )
        Write-ToLog  ('Cert info - Not After: ' + $RemoteCertificate.NotAfter )
        Write-ToLog  ('Cert info - Subject: ' + $RemoteCertificate.GetNameInfo(3,$false) )
        #Write-ToLog  ('Cert info - Distinguished Name: ' + $RemoteCertificate.SubjectName.Name )
        Write-ToLog  ('Cert info - Issuer: ' + $RemoteCertificate.GetNameInfo(3,$true) )
        Write-ToLog  ('Cert info - Issuer Distinguished Name: ' + $RemoteCertificate.IssuerName.Name )
        Write-ToLog  ('Cert info - Usage: ' + $RemoteCertificate.EnhancedKeyUsageList )
    } 
    catch {
        $_.Exception
    }
    finally {
        $SslStream.Close()
        $NetStream.Close()
    }
    
}

function Write-ToLog()
{   param( $msg = "`n" )
    Write-Host $msg
    Add-Content $logfile -Value $msg
}
function Write-ToLogVerbose()
{   param( $msg = "`n" )
    if ($global:outputverbose ) { Write-Verbose $msg}
    Add-Content $logfile -Value ("VERBOSE:`t"+$msg)
}
function Write-ToLogWarning()
{   param( $msg = "`n" )
    Write-Warning $msg
    Add-Content $logfile -Value ($global:dblbar)
    Add-Content $logfile -Value ("WARNING:`n`t"+$msg)
    Add-Content $logfile -Value ($global:dblbar)
}

cls

if ($outputverbose) {
    Test-MsDavConnection -WebAddress $testurl -Verbose }
else { Test-MsDavConnection -WebAddress $testurl }


Start-Process ($env:windir + "\explorer.exe")  -ArgumentList $((Get-ChildItem $logfile).DirectoryName) 
