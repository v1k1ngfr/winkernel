# Set French keyboard
$LanguageList = Get-WinUserLanguageList
$LanguageList.Add("fr-FR")
Set-WinUserLanguageList $LanguageList -Force
Set-WinUserLanguageList -LanguageList fr-FR, en-US -Force
#
# Run script in Powershell command prompt as administrator
#
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
. { Invoke-WebRequest -useb https://boxstarter.org/bootstrapper.ps1 } | iex; Get-Boxstarter -Force

#
# Once the installation has completed, a Boxstarter Shell icon will appear on your desktop.  
# Launch the Boxstarter Shell and enter the following command:

Install-BoxstarterPackage -PackageName https://raw.githubusercontent.com/v1k1ngfr/winkernel/master/build_win10_VBox.choco

