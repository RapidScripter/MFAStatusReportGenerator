$TenantUrl = Read-Host "Enter the SharePoint admin center URL (e.g., https://example.sharepoint.com)"
Connect-SPOService -Url $TenantUrl

# Retrieve OneDrive URLs
$OneDriveUrls = Get-SPOSite -IncludePersonalSite $true -Limit all -Filter "Url -like '-my.sharepoint.com/personal/'" | Select -ExpandProperty Url

# Print each URL to the console
$OneDriveUrls | ForEach-Object { Write-Host $_ }

# Prompt for storage quota and warning level
$OneDriveStorageQuota = Read-Host "Enter the OneDrive Storage Quota in MB"
$OneDriveStorageQuotaWarningLevel = Read-Host "Enter the OneDrive Storage Quota Warning Level in MB"

# Update each OneDrive site
foreach ($OneDriveSite in $OneDriveUrls) {
    Set-SPOSite -Identity $OneDriveSite -StorageQuota $OneDriveStorageQuota -StorageQuotaWarningLevel $OneDriveStorageQuotaWarningLevel
    Write-Host "Updated $OneDriveSite"
}

Write-Host "Done updating OneDrive sites."
