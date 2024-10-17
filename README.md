# MFAStatusReportGenerator

This PowerShell script generates a Multi-Factor Authentication (MFA) status report for Office 365 users and exports the data to a CSV file. It retrieves user information, including MFA status, sign-in status, license status, and admin roles, allowing administrators to manage MFA effectively.

## Features

- Connects to the MSOnline service to retrieve user information.
- Supports filtering users based on MFA status, sign-in status, license status, and admin roles.
- Exports the generated report to a CSV file.
- Provides the option to open the report upon completion.

## Prerequisites

- PowerShell installed on your machine.
- MSOnline module must be installed. You can install it using:
  ```powershell
  Install-Module MSOnline
- Appropriate permissions to access user information in Office 365.

## Parameters

- `-DisabledOnly`: Filters the report to include only users with MFA disabled.
- `-EnabledOnly`: Filters the report to include only users with MFA enabled.
- `-EnforcedOnly`: Filters the report to include only users with MFA enforced.
- `-AdminOnly`: Filters the report to include only users with admin roles.
- `-LicensedUserOnly`: Filters the report to include only licensed users.
- `-SignInAllowed`: Filters the report based on whether sign-in is allowed (True) or denied (False).
- `-UserName`: Specifies the username for authentication when scheduling the script.
- `-Password`: Specifies the password for authentication when scheduling the script.

## Usage

1. Clone this repository:
   ```bash
   git clone https://github.com/RapidScripter/MFAStatusReportGenerator.git
   cd MFAStatusReportGenerator
2. Open PowerShell and run the script:
   ```powershell
   .\MFAStatusReport.ps1
3. Use the available parameters as needed. For example:
   ```powershell
   .\MFAStatusReport.ps1 -LicensedUserOnly -AdminOnly
4. Example
   ```powershell
   # Example command to generate a report for licensed users with admin roles
   .\MFAStatusReport.ps1 -LicensedUserOnly -AdminOnly

   # Example command to generate a report for users with sign-in allowed
   .\MFAStatusReport.ps1 -SignInAllowed $True

## Notes
- The generated report includes details such as display name, user principal name, MFA status, activation status, default MFA method, all MFA methods, MFA phone, MFA email, license status, admin roles, and sign-in status.
- The output file is saved with a timestamp in the specified directory.
