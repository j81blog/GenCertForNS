

#(Main) domain name of the certificate (this domain name wil also be the first entry for a san certificate)
$domain = "domain.com"

#For SAN certificate add the subjectalternatename dns record names, comma seperated.
#Leave altdomain empty for a single domain certificate.
$altdomains=""

#$altdomains = "test1.domain.com","test2.domain.com","test3.domain.com","test4.domain.com"
#This password will be used for encryption of the pfx certificate file.
$pfxPassword = "P@ssw0rd"

#This email wil be used for the certificate request.
$email = "admin@ domain.com"

#The follwing location will be used to store the certificates
$CertificateVault = "D:\CertVault"

#The name of the NetScaler (HTTP) Content Switch used to verify the certificates ("show cs vserver -summary")
$ContentSwitchVipName = "<CSVSERVER>"

# Certificate server that will sign your certificate.
# Please try first the staging server to check if everything works!

# Demo/test server : 
$ACMEServer = "https://acme-staging.api.letsencrypt.org/directory"

# Production (publicly trusted): 
#$ACMEServer = "https://acme-v01.api.letsencrypt.org/"


# Beginning of script

$module = "ACMESharp"
if(-not(Get-Module -name $module)) {
    if(Get-Module -ListAvailable | Where-Object { $_.name -eq $module }) {
        Import-Module -Name $module
    } else {
        Write-Host -NoNewline -ForegroundColor Red "ERROR: "
        Write-Host "module `"$module`" is not available or is not installed."
        Write-Host "Please install ACMESharp, https://github.com/ebekker/ACMESharp/"
        Write-Host "You can also use chocolatey to install ACMESharp"
        Write-Host ""
        Write-Host -ForegroundColor Green "choco install acmesharp-posh-all"
        Write-Host ""
    }
}

Write-Host "Before continuing make sure that:"
Write-Host -NoNewLine -ForeGroundColor Yellow "1: "
Write-Host "All your domain names end on the NetScaler Content Switch vServer (TCP:80, HTTP), else domain validation will fail!"
Write-Host "   => $domain"
if (!($altdomains -eq "")) {
    ForEach ($DNS in $altdomains) {
        Write-Host "   => $DNS"
    }
}
$Config = @"
add responder action rsa_letsencrypt respondwith q{`"HTTP/1.0 200 OK`" +`"\r\n\r\n`" + `"XXXX`"}
add responder policy rsp_letsencrypt `"HTTP.REQ.URL.CONTAINS(\`"well-known/acme-challenge/XXXX\`")`" rsa_letsencrypt
bind cs vserver $ContentSwitchVipName -policyName rsp_letsencrypt -priority 50 -gotoPriorityExpression END -type REQUEST
"@
$Config | & clip.exe
Write-Host ""
Write-Host -NoNewLine -ForeGroundColor Yellow "2: "
Write-Host "Add the following responder Action/Policy to the NetScaler (HTTP Content Switch) config (Content is copied to Clipboard):"
Write-Host ""
Write-Host -ForeGroundColor Green $Config
Write-Host ""
& pause

$alias = $domain
$StartTimeDate = Get-Date
$CertVault = "$CertificateVault\{0}\{1}" -f $domain, $StartTimeDate.ToString("yyyyMMddHHmm")
if (!(Test-Path -Path $CertVault)) {
    try {
        $CreatedDirectory = new-item $CertVault -itemtype directory
    } catch {
        Write-Host -NoNewline -ForegroundColor Red "ERROR: "
        Write-Host "Failed to create directory `" $CreatedDirectory`""
        exit (1)
    } finally {
        if ($CreatedDirectory -eq $null) {
            Write-Host -NoNewline -ForegroundColor Red "ERROR: "
            Write-Host "Failed to create directory `"$CertVault`""
            exit (1)
        }
    Write-Host "Directory `"$CertVault`" created successfully"
    }
}

cd $CertVault


function VerifyDNS{
    [CmdletBinding()] 
    Param ( 
		[Parameter(Mandatory=$false)][string]$DNS
    )
    Write-Host "Check if verifying `"$DNS`" is necessary"
    $update = $null
    try {
        $update = Get-ACMEIdentifier $DNS
    } catch {
        $update = $null
    }
    $update
    if (!($update -eq $null)) {
        if (!($Update.Status.ToLower() -eq "invalid")) {
            try {
                $TimeDiff = (Get-ACMEIdentifier -IdentifierRef $DNS).Expires - $StartTimeDate
                if ($TimeDiff.Days -ge 1) {
                    Write-Host "The domain verification for `"$DNS`" is `"$($Update.Status)`""
                    Return $update
                    Break
                }
            } catch {}
        }
    }
    Write-Host "Start verifying `"$DNS`""
	$Identifier = New-ACMEIdentifier -Dns $DNS -Alias $DNS
	
	$CompletedChallenge = Complete-ACMEChallenge $DNS -ChallengeType http-01 -Handler manual
	
	$Challenge = ($completedChallenge.Challenges | Where-Object { $_.Type -eq "http-01" }).Challenge
	
    $Config = @"
set responder action rsa_letsencrypt -target q{`"HTTP/1.0 200 OK`" +`"\r\n\r\n`" + `"$($Challenge.FileContent)`"}
set responder policy rsp_letsencrypt -Rule `"HTTP.REQ.URL.CONTAINS(\`"$($Challenge.FilePath)\`")`"
"@
    $Config | & clip.exe
	Write-Host "Configure the NetScaler Content Switch Action & Policy (Content is copied to Clipboard)"
	Write-Host ""
	Write-Host -ForeGroundColor Green $Config
	Write-Host ""
	Write-Host -ForeGroundColor Yellow "NOTE: Only continue when configured!"
	Write-Host ""
	#Write-Host -ForeGroundColor Yellow "Press any key to continue ..."
	#$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	& pause
	
	$SubmittedChallenge = Submit-ACMEChallenge $DNS -ChallengeType http-01
	
	$Update = (Update-ACMEIdentifier $DNS -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}
	$i = 0
	
	while(!($Update.Status.ToLower() -eq "valid")) {
		$i++
		Start-Sleep -Seconds 2
		$Update = (Update-ACMEIdentifier $DNS -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}
		if ($i -ge 120) {
			Write-Host "Verification failed, current status: `"$($Update.Status)`""
		} elseif ($Update.Status.ToLower() -eq "invalid") {
			Break
		} elseif (!($Update.Status.ToLower() -eq "valid")) {
			Write-Host "Trying again, new status: `"$($Update.Status)`""
		}
	}
	
	$Update = $null
	$update = Update-ACMEIdentifier $DNS
    try {
    	switch ($update.Status.ToLower()) {
    		"pending" {
    			Write-Host -NoNewLine -ForeGroundColor Yellow "Warning: "
    			Write-Host "Verification for `"$($update.Identifier)`" is still pending..."
    			Write-Host "Taken to long, exiting now."
    		}
    		"invalid" {
    			Write-Host -NoNewLine -ForeGroundColor Red "Error: "
    			Write-Host "Verification for `"$($update.Identifier)`" is invalid! Exiting now."
    		}
    		"valid" {
    			Write-Host -NoNewLine -ForeGroundColor Green "Done: "
    			Write-Host "Verification for `"$($update.Identifier)`" was valid, continuing"
    		}
    		default {
    			Write-Host -NoNewLine -ForeGroundColor Red "Error: "
    			Unexpected status for `"$($update.Identifier)`" is `"$($update.Status)`", exiting now.
    		}
    	}
    } catch {
    	Write-Host -NoNewLine -ForeGroundColor Red "Error: "
    	Write-Host "Error unknown status!"
    }
    $update
	Return $update
}

#if ((Get-ACMEVault) -eq $null) {
#    Initialize-ACMEVault -BaseURI https://acme-staging.api.letsencrypt.org/directory -force
#    $Registration = New-ACMERegistration -Contacts mailto:$email -AcceptTos
#} else {
#    try {
#        $Registration = Get-ACMERegistration
#    } catch {}
#    if ($Registration -eq $null) {
#        $Registration = New-ACMERegistration -Contacts mailto:$email -AcceptTos
#    }
#}
Initialize-ACMEVault -BaseURI $ACMEServer -force
$Registration = New-ACMERegistration -Contacts mailto:$email -AcceptTos


$CertAlias = "Certificate"

if ((!($altdomains -eq "")) -and (!($altdomains -eq $null))) {
    Write-Host "Verifying main domain"
    $VerifyDomain = VerifyDNS -DNS $domain
     if (!($VerifyDomain.Status.ToLower() -eq "valid")) {
         exit (1)
    }
    Write-Host "Verifying (sub)domains"
    ForEach ($subdomain in $altdomains) {
        $VerifyDomain = VerifyDNS -DNS $subdomain
        if (!($VerifyDomain.Status.ToLower() -eq "valid")) {
            exit (1)
        }
    }
    New-ACMECertificate $domain -Generate -AlternativeIdentifierRefs $altdomains -Alias $CertAlias
} else {
    Write-Host "Verifying a single domain"
    $VerifyDomain = VerifyDNS -DNS $domain
     if (!($VerifyDomain.Status.ToLower() -eq "valid")) {
         exit (1)
     }
     $NewCertificate = New-ACMECertificate $alias -Generate -Alias $CertAlias
}

$NewCertificate = Submit-ACMECertificate $CertAlias

$NewCertificate = Update-ACMECertificate $CertAlias

$i = 0
while ((!(Update-ACMECertificate $CertAlias).SerialNumber -ne "")) {
	if ($i -ge 120) {
		Write-Host -NoNewLine -ForeGroundColor Red "Error: "
		Write-Host "Certificate submitting failed, took to long to complete."
		Exit (1)
	}
	Write-Host "Waiting for certificate to come available..."
	Start-Sleep -seconds 2
}

#Export Private Key
Get-ACMECertificate $CertAlias -ExportKeyPEM "$CertVault\$alias.key.pem"
#Export CSR
Get-ACMECertificate $CertAlias -ExportCsrPEM "$CertVault\$alias.csr.pem"
#PEM: Unencrypted
#DER: Encrypted
#Export Certificate Issued By LE
Get-ACMECertificate $CertAlias -ExportCertificatePEM "$CertVault\$alias.crt.pem" -ExportCertificateDER "$CertVault\$alias.crt"
#Export Issuer Certificate
Get-ACMECertificate $CertAlias -ExportIssuerPEM "$CertVault\$alias-issuer.crt.pem" -ExportIssuerDER "$CertVault\$alias-issuer.crt"
#Export PFX
Get-ACMECertificate $CertAlias -ExportPkcs12 "$CertVault\$alias.pfx" -CertificatePassword $pfxPassword
$Config = @"
unbind cs vserver $ContentSwitchVipName -policyName rsp_letsencrypt
remove responder policy rsp_letsencrypt
remove responder action rsa_letsencrypt
"@
$Config | & clip.exe
Write-Host -NoNewLine "Certificates written to: "
Write-Host -ForegroundColor Yellow "$CertVault"
Write-Host ""
Write-Host "To cleanup, you can remove the Responder Action/Policy NetScaler with the following commands"
Write-Host "(Content is copied to Clipboard):"
Write-Host ""
Write-Host -ForeGroundColor Green $Config
Write-Host ""
Write-Host -ForegroundColor Green "Finished!"
exit (0)
