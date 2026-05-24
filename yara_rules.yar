rule Command_and_Control_HTTP_Indicators
{
    meta:
        author = "AI Assistant"
        description = "Detects common HTTP C2 communication strings (User-Agent and POST data)."
        type = "C2"
        severity = "High"
    strings:
        // Common User-Agents used by malware to blend in
        $ua1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" ascii nocase
        $ua2 = "Mellon" ascii wide
        
        // Common C2 request/response indicators
        $post_data = "Content-Type: application/x-www-form-urlencoded" ascii nocase
        $ok_resp = "HTTP/1.1 200 OK" ascii
        $c2_header = "Host:" ascii
        $c2_url_path = "/submit.php" ascii

    condition:
        // Requires a combination of two elements to confirm C2 activity
        (1 of ($ua*)) and (2 of ($post_data, $ok_resp, $c2_header, $c2_url_path))
}

rule Rootkit_Stealth_and_Hooking
{
    meta:
        author = "AI Assistant"
        description = "Detects API calls associated with stealth techniques and system hooking often used by rootkits and loaders."
        type = "Rootkit/Loader"
        severity = "Critical"
    strings:
        // API calls for manipulating the system's execution tables (often used for hooking)
        $hook1 = "NtQuerySystemInformation" ascii
        $hook2 = "SetWindowsHookExA" ascii
        
        // API calls related to loading or unloading drivers/modules (common rootkit mechanism)
        $driver1 = "ZwLoadDriver" ascii
        $driver2 = "ZwUnloadDriver" ascii
        
        // Common file path for dropping hidden configuration files
        $hidden_cfg = "AppData\\Local\\Temp\\" ascii nocase
        $hidden_file = ".sys" ascii wide

    condition:
        // Presence of at least three indicators, focusing on drivers and hooking
        3 of ($hook*, $driver*, $hidden_cfg, $hidden_file)
}