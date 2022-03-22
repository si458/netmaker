new-module -name netclient-install -scriptblock {
    $ErrorActionPreference = "Stop"
    function Quit {
        param(
            $Text
        )
        Write-Host "Exiting: " $Text
        Break Script
    }
    Function Netclient-Install() {
        param ($version='latest', $token)
            if($token -eq $null -or $token -eq ""){
                Quit "-token required"
            }
            $software = "WireGuard";
            $installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $software }) -ne $null
            If(-Not $installed) {
                Write-Host "'$software' is NOT installed. installing...";
                $url = "https://download.wireguard.com/windows-client/wireguard-installer.exe"
                Invoke-WebRequest -Uri $url -OutFile "$env:userprofile\Downloads\wireguard-installer.exe"
                $args = @("Comma","Separated","Arguments")
                Start-Process -Filepath "$env:userprofile\Downloads\wireguard-installer.exe" -ArgumentList $args -Wait
                $software = "WireGuard";
                $installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $software }) -ne $null
                If(-Not $installed) {
                    Quit "Could not install WireGuard"
                } else {
                    $env:Path +=  (";" + $env:ProgramFiles + "\WireGuard")
                    Write-Host "'$software' is installed."
                }
            } else {
                Write-Host "'$software' is installed."
            }
            if (Test-Path -Path "C:\ProgramData\Netclient\netclient.exe") {
                Write-Host "'netclient' is already installed."
            } else {
                Write-Host "'netclient.exe' is NOT installed. installing...";
                Write-Host "https://github.com/gravitl/netmaker/releases/download/$version/netclient.exe";
                $url = "https://github.com/gravitl/netmaker/releases/download/$version/netclient.exe"
                Invoke-WebRequest -Uri $url -OutFile "$env:userprofile\Downloads\netclient.exe"
                New-Item -Path "C:\ProgramData\" -Name "Netclient" -ItemType "directory"
                Move-Item -Path "$env:userprofile\Downloads\netclient.exe" -Destination "C:\ProgramData\Netclient\netclient.exe"
                $oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
                $newpath = "$oldpath;C:\ProgramData\Netclient"
                Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath
                $env:Path += ";C:\ProgramData\Netclient"
                Write-Host "'netclient' is installed."
            }
            $NetArgs = @("join","-t",$token)
            Start-Process -Filepath "C:\ProgramData\Netclient\netclient.exe" -ArgumentList $NetArgs -Wait
            Start-Sleep -s 5
            Write-Host "'netclient' has been setup."
    }
}
