function Test-SslProtocol {
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            ValueFromPipeline=$true
        )]$ComputerName,
        [Parameter(
            ValueFromPipelineByPropertyName=$true
        )][int]$Port = 443,
        [ValidateSet("SSL3", "TLS", "TLS11", "TLS12", IgnoreCase = $true)]
        [Parameter(
            ValueFromPipelineByPropertyName=$true
        )]$Protocol = 'TLS12'
    )

    $bProtocolSupported = $false
    $Socket = New-Object System.Net.Sockets.Socket('Internetwork','Stream', 'Tcp')
    $Socket.Connect($ComputerName, $Port)
    try {
        $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
        $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true)
        $SslStream.AuthenticateAsClient($ComputerName,  $null, $Protocol, $false )
        $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
        $bProtocolSupported = $true
        Write-Host $ComputerName" supports "$Protocol
        Write-Host $RemoteCertificate.Verify()
    } 
    catch {
        Write-Host $ComputerName" does not support "$Protocol
    }
    finally {
        $SslStream.Close()
    }
    
    return $bProtocolSupported
}

Test-SslProtocol -ComputerName www.bing.com 

