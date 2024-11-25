


$LASTEXITCODE = 0
function GenerateCertificate {
    <#
    This function generates a certificate used for mock testing

    :param KeyLength: The size in bits of the length of the key (ex 2048)
    :param CommonName: Common name field of the certificate
    :param Variable Name: Name of the variable (Not important for the certificate but used to track which pfx is tied to which signed data)
    :param VariablePrefix: Prefix to append to the beginning of the certificate for tracking (Not Important)
    :param Signer: Signing certificate object from the Certificate Store

    :return: HashTable Object
        {
            .Cert           # Path to Certificate in the Certificate Store
            .CertPath       # Path to the der encoded certificate
            .PfxCertPath    # Path to the pfx file generated
        }
    #>

    # Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object Thumbprint -EQ 4EFF6B1A0F61B4BF692C77F09889AD151EE8BB58 | Select-Object *

    param (
        $CertificateParams,
        $VariableName,
        $VariablePrefix
    )

    # Return object on success
    $PfxCertFilePath = Join-Path -Path $Globals.Layout.CertificateFolder -ChildPath "${VariablePrefix}${VariableName}.pfx"
    $CertFilePath = Join-Path -Path $Globals.Layout.CertificateFolder -ChildPath "${VariablePrefix}${VariableName}.cer"
    $P7bCertFilePath = Join-Path -Path $Globals.Layout.CertificateFolder -ChildPath "${VariablePrefix}${VariableName}.p7b"

    Write-Host "$> New-SelfSignedCertificate " @CertificateParams

    # Generate the new certifcate with the chosen params
    $Output = New-SelfSignedCertificate @CertificateParams
    if ($LASTEXITCODE -ne 0) {
        Write-Host "New-SelfSignedCertificate Failed"
        Write-Host "Error Code: $LASTEXITCODE"
        Write-Host "Output: $Output"
        return $null
    }

    # The path of the certificate in the store
    $MockCert = $Globals.Certificate.Store + $Output.Thumbprint

    # Print all the details from the certificate
    # Get-ChildItem -Path $Globals.Certificate.Store | Where-Object Thumbprint -EQ $Output.Thumbprint  | Select-Object * | Write-Host

    # export the certificate as a PFX
    Export-PfxCertificate -Cert $MockCert -FilePath $PfxCertFilePath -Password $Globals.Certificate.SecurePassword | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Export-PfxCertificate Failed"
        return $null
    }

    Export-Certificate -Cert $MockCert -FilePath $CertFilePath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Export-Certificate Failed"
        return $null
    }

    $ReturnObject = @{
        Cert = $MockCert
        CertPath = $CertFilePath
        PfxCertPath = $PfxCertFilePath
        CertInfo = "${PfxCertFilePath};password" # path to the pfx certificate and the password
    }

    return $ReturnObject
}

$Organization = "Project MU"
$Unit = "TEST"
$CommonName = "DO NOT TRUST - DO NOT USE - WHY DO YOU EVEN HAVE THIS"
$KeyLength = 2048

$Password = "password"
$DataFolder = "./Test"
$TestDataName = "TestData"
$CertName = "Certs"

# Global Variables used throughout the script
$Globals = @{
    Certificate = @{
        Store = "Cert:\LocalMachine\My\"
        Organization = "ProjectMu"
        Password = $Password
        SecurePassword = ConvertTo-SecureString $Password -Force -AsPlainText
        LifeYears = 10 # How long in the future should the Certificate be valid
    }
    Layout = @{
        DataFolder = $DataFolder
        CertName = $CertName
        CertificateFolder = "$DataFolder/$CertName"
        TestDataName = $TestDataName
        TestDataFolder = "$DataFolder/$TestDataName"
    }
}

# Create the Certificate Folder
if (-not (Test-Path -Path $Globals.Layout.CertificateFolder)) {
    New-Item -Path $Globals.Layout.CertificateFolder -ItemType Directory | Out-Null
}

$CertificateParams = @{
    DnsName = "www.$Organization.com"
    CertStoreLocation = $Globals.Certificate.Store
    KeyAlgorithm = "RSA"
    KeyLength = $KeyLength
    Subject = "CN=$CommonName O=$Organization OU=$Unit"
    NotAfter = (Get-Date).AddYears($Globals.Certificate.LifeYears)
    KeyUsage = @("CertSign", "CRLSign", "DigitalSignature")
    # Basic Constraint :
    #   CA: A CA certificate, by definition, must have a basic constraints extension with this `CA` boolean value set to "true" in order to be a CA.
    #   pathlength: Limits the number of intermediate certificates allowed by the next certificates
    TextExtension = @("2.5.29.19={text}CA=1")
}

GenerateCertificate -CertificateParams $CertificateParams -VariableName "TestCert" -VariablePrefix "Test"
