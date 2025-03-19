<#
.SYNOPSIS
    Generates an MFA (Multi-Factor Authentication) status report for Office 365 users and exports the data to a CSV file.

.DESCRIPTION
    This script connects to the MSOnline service to retrieve Office 365 user information, including MFA status, sign-in status, license status, and admin roles.
    The script supports various parameters to filter users based on specific criteria such as sign-in status, license status, admin roles, and more.
    The generated report is saved as a CSV file, and the user is given the option to open the file upon completion.

.PARAMETERS
    -DisabledOnly
        Filters the report to include only users with MFA disabled.
    
    -EnabledOnly
        Filters the report to include only users with MFA enabled.

    -EnforcedOnly
        Filters the report to include only users with MFA enforced.

    -AdminOnly
        Filters the report to include only users with admin roles.

    -LicensedUserOnly
        Filters the report to include only licensed users.

    -SignInAllowed
        Filters the report based on whether sign-in is allowed (True) or denied (False).

    -UserName
        Specifies the username for authentication when scheduling the script.

    -Password
        Specifies the password for authentication when scheduling the script.

.NOTES
    - This script requires the MSOnline module to be installed.
    - The script can be run interactively or scheduled with credentials passed as parameters.
    - The generated report includes details such as display name, user principal name, MFA status, activation status, default MFA method, all MFA methods, MFA phone, MFA email, license status, admin roles, and sign-in status.

.EXAMPLE
    .\MFAStatusReport.ps1 -LicensedUserOnly -AdminOnly
        Generates a report for licensed users with admin roles and saves it to a CSV file.

    .\MFAStatusReport.ps1 -SignInAllowed $True
        Generates a report for users with sign-in allowed and saves it to a CSV file.

#>


Param
(
    [Parameter(Mandatory = $false)]
    [switch]$DisabledOnly,
    [switch]$EnabledOnly,
    [switch]$EnforcedOnly,
    [switch]$AdminOnly,
    [switch]$LicensedUserOnly,
    [Nullable[boolean]]$SignInAllowed = $null,
    [string]$UserName,
    [string]$Password
)
#Check for MSOnline module
$Modules=Get-Module -Name MSOnline -ListAvailable
if($Modules.count -eq 0)
{
  Write-Host  Please install MSOnline module using below command: `nInstall-Module MSOnline  -ForegroundColor yellow
  Exit
}

#Storing credential in script for scheduling purpose/ Passing credential as parameter
if(($UserName -ne "") -and ($Password -ne ""))
{
 $SecuredPassword = ConvertTo-SecureString -AsPlainText $Password -Force
 $Credential  = New-Object System.Management.Automation.PSCredential $UserName,$SecuredPassword
 Connect-MsolService -Credential $credential
}
else
{
 Connect-MsolService | Out-Null
}
$Result=""
$Results=@()
$UserCount=0

#Output file declaration
$ExportCSV="C:\MFAStatusReport_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv"

#Loop through each user
Get-MsolUser -All | foreach {
    $UserCount++
    $DisplayName = $_.DisplayName
    $Upn = $_.UserPrincipalName
    $MFAStatus = $_.StrongAuthenticationRequirements.State
    $MethodTypes = $_.StrongAuthenticationMethods
    $RolesAssigned = ""
    Write-Progress -Activity "`n     Processed user count: $UserCount "`n"  Currently Processing: $DisplayName"
    if ($_.BlockCredential -eq "True") {
        $SignInStatus = "False"
        $SignInStat = "Denied"
    } else {
        $SignInStatus = "True"
        $SignInStat = "Allowed"
    }

    #Filter result based on SignIn status
    if (($SignInAllowed -ne $null) -and ([string]$SignInAllowed -ne [string]$SignInStatus)) {
        return
    }

    #Filter result based on License status
    if (($LicensedUserOnly.IsPresent) -and ($_.IsLicensed -eq $False)) {
        return
    }

    if ($_.IsLicensed -eq $true) {
        $LicenseStat = "Licensed"
    } else {
        $LicenseStat = "Unlicensed"
    }

    #Check for user's Admin role
    $Roles = (Get-MsolUserRole -UserPrincipalName $upn).Name
    if ($Roles.count -eq 0) {
        $RolesAssigned = "No roles"
        $IsAdmin = "False"
    } else {
        $IsAdmin = "True"
        foreach ($Role in $Roles) {
            $RolesAssigned = $RolesAssigned + $Role
            if ($Roles.IndexOf($Role) -lt (($Roles.count) - 1)) {
                $RolesAssigned = $RolesAssigned + ","
            }
        }
    }

    $Methods = ""
    $MethodTypes = ""
    $MethodTypes = $_.StrongAuthenticationMethods.MethodType
    $DefaultMFAMethod = ($_.StrongAuthenticationMethods | Where-Object { $_.IsDefault -eq "True" }).MethodType
    $MFAPhone = $_.StrongAuthenticationUserDetails.PhoneNumber
    $MFAEmail = $_.StrongAuthenticationUserDetails.Email

    if ($MFAPhone -eq $Null) { $MFAPhone = "-" }
    if ($MFAEmail -eq $Null) { $MFAEmail = "-" }

    if ($MethodTypes -ne $Null) {
        $ActivationStatus = "Yes"
        foreach ($MethodType in $MethodTypes) {
            if ($Methods -ne "") {
                $Methods = $Methods + ","
            }
            $Methods = $Methods + $MethodType
        }
    } else {
        $ActivationStatus = "No"
        $Methods = "-"
        $DefaultMFAMethod = "-"
        $MFAPhone = "-"
        $MFAEmail = "-"
    }

    #Determine MFA Status
    if ($MFAStatus -eq $Null) {
        $MFAStatus = "Disabled"
    } elseif ($MFAStatus -eq "Enabled") {
        $MFAStatus = "Enabled"
    } elseif ($MFAStatus -eq "Enforced") {
        $MFAStatus = "Enforced"
    }

    #Print to MFA Status Report
    $Result = @{
        'DisplayName' = $DisplayName
        'UserPrincipalName' = $Upn
        'MFAStatus' = $MFAStatus
        'ActivationStatus' = $ActivationStatus
        'DefaultMFAMethod' = $DefaultMFAMethod
        'AllMFAMethods' = $Methods
        'MFAPhone' = $MFAPhone
        'MFAEmail' = $MFAEmail
        'LicenseStatus' = $LicenseStat
        'IsAdmin' = $IsAdmin
        'AdminRoles' = $RolesAssigned
        'SignInStatus' = $SignInStat
    }
    $Results = New-Object PSObject -Property $Result
    $Results | Select-Object DisplayName, UserPrincipalName, MFAStatus, ActivationStatus, DefaultMFAMethod, AllMFAMethods, MFAPhone, MFAEmail, LicenseStatus, IsAdmin, AdminRoles, SignInStatus | Export-Csv -Path $ExportCSV -NoTypeInformation -Append
}

#Open output file after execution
Write-Host `nScript executed successfully

if ((Test-Path -Path $ExportCSV) -eq "True") {
    Write-Host " MFA status report available in:" -NoNewline -ForegroundColor Yellow
    Write-Host $ExportCSV `n
    $Prompt = New-Object -ComObject wscript.shell
    $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    If ($UserInput -eq 6) {
        Invoke-Item "$ExportCSV"
    }
    Write-Host Exported report has $UserCount users
} else {
    Write-Host No user found that matches your criteria.
}

#Clean up session
Get-PSSession | Remove-PSSession
