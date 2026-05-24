import os
import re
import time
import json
import requests
import ipaddress
import threading
import subprocess
from tkinter import *
from tkinter import messagebox, filedialog, ttk
import yara 

# Initialize window
root = Tk()
root.title("Memory Forensics Tool")
root.geometry("750x700")
root.configure(bg="#f0f0f0")

# 🟢 YARA Configuration - AUTOMATIC PATH DETERMINATION
# This ensures the tool finds yara_rules.yar in the same directory as the script.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
YARA_RULES_PATH = os.path.join(BASE_DIR, "yara_rules.yar")
# ----------------------------------------------------

#------------------------------------------- Main Page -------------------------------------------#

notebook = ttk.Notebook(root)
notebook.pack(fill=BOTH, expand=True)

main_page = Frame(notebook)
notebook.add(main_page, text="Main")
main_frame = Frame(main_page, bg="#f0f0f0")
main_frame.pack(pady=10, padx=20, fill=X)

# Browse for image file
def browse_image():
    filepath = filedialog.askopenfilename(title="Select Memory Image File")
    if filepath:
        imagepath.delete(0, END)
        imagepath.insert(0, filepath)

# Browse for output directory
def browse_output():
    folderpath = filedialog.askdirectory(title="Select Output Folder")
    if folderpath:
        outputpath.delete(0, END)
        outputpath.insert(0, folderpath)

# Main UI Layout
Label(main_frame, text="Enter the memory image path:", font=("Arial", 12), bg="#f0f0f0").grid(row=0, column=0, pady=5, sticky=W)
imagepath = Entry(main_frame, width=50)
imagepath.grid(row=0, column=1, padx=10)
Button(main_frame, text="Browse", command=browse_image, bg="#dddddd").grid(row=0, column=2)

Label(main_frame, text="Select output directory:", font=("Arial", 12), bg="#f0f0f0").grid(row=1, column=0, pady=5, sticky=W)
outputpath = Entry(main_frame, width=50)
outputpath.grid(row=1, column=1, padx=10)
Button(main_frame, text="Browse", command=browse_output, bg="#dddddd").grid(row=1, column=2)

Label(main_frame, text="Select a command:", font=("Arial", 12), bg="#f0f0f0").grid(row=2, column=0, pady=5, sticky=W)

# Output Frame with Scrollbars
output_frame = Frame(main_page)
output_frame.pack(pady=10, fill=BOTH, expand=True)

output_box = Text(output_frame, height=30, width=110, wrap=NONE, bg="white", undo=True)
output_box.pack(side=LEFT, fill=BOTH, expand=True)

# Scrollbars
y_scroll = Scrollbar(output_frame, orient=VERTICAL, command=output_box.yview)
y_scroll.pack(side=RIGHT, fill=Y)
x_scroll = Scrollbar(main_page, orient=HORIZONTAL, command=output_box.xview)
x_scroll.pack(fill=X)

output_box.config(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

# Function to search output
def search_output():
    output_box.tag_remove("highlight", "1.0", END)
    keyword = search_entry.get()
    content = output_box.get("1.0", END)

    if not keyword:
        return

    matches = []
    idx = 0
    while True:
        idx = content.lower().find(keyword.lower(), idx)
        if idx == -1:
            break
        matches.append((idx, idx + len(keyword)))
        idx += len(keyword)

    for start, end in matches:
        start_index = f"1.0 + {start} chars"
        end_index = f"1.0 + {end} chars"
        output_box.tag_add("highlight", start_index, end_index)

    output_box.tag_config("highlight", background="yellow", foreground="black")

# Search Frame
search_frame = Frame(main_page, bg="#f0f0f0")
search_frame.pack(pady=5)

Label(search_frame, text="Search Output:", bg="#f0f0f0").pack(side=LEFT, padx=5)
search_entry = Entry(search_frame, width=30)
search_entry.pack(side=LEFT, padx=5)
Button(search_frame, text="Search", command=search_output, bg="#525453", fg="white").pack(side=LEFT, padx=5)

commands = {
    "Windows: Process List": "windows.pslist",
    "Windows: Process Scan": "windows.psscan",
    "Windows: Process Tree": "windows.pstree",
    "Windows: DLL List": "windows.dlllist",
    "Windows: Handles": "windows.handles",
    "Windows: Network Scan": "windows.netscan.NetScan",
    "Windows: Dump Processes": "windows.procdump",
    "Windows: Command Line": "windows.cmdline",
    "Windows: Environment Variables": "windows.environ",
    "Windows: Malfind": "windows.malfind",
    "Windows: Hashdump": "windows.hashdump",
    "Windows: Cachedump": "windows.cachedump",
    "Windows: SAM Registry": "windows.sam",
    "Windows: Userassist": "windows.userassist",
    "Windows: Shellbags": "windows.shellbags",
    "Windows: Registry Hives": "windows.registry.hivelist",
    "Windows: Shimcache": "windows.shimcache",
    "Windows: Filescan": "windows.filescan",
    "Windows: Getsids": "windows.getsids",
    "Windows: Service Scan": "windows.services",
    "Windows: Scheduled Tasks": "windows.schtasks",
    "Windows: Mutants": "windows.mutantscan",
    "Windows: Drivers": "windows.driverscan",
    "Windows: Print Key": "windows.registry.printkey",
    "Windows: User Sessions": "windows.getusersids",
    "Windows: Timezone": "windows.timezone",
}

selected_command = StringVar()
selected_command.set(list(commands.keys())[0])
command_combobox = ttk.Combobox(main_frame, textvariable=selected_command, width=60)
command_combobox['values'] = list(commands.keys())
command_combobox.grid(row=2, column=1, padx=10)
command_combobox.current(0)

# YARA Scan Function
def run_yara_scan(image_file):
    if not os.path.exists(YARA_RULES_PATH):
        return f"[!] YARA Error: Rules file not found at {YARA_RULES_PATH}"

    try:
        rules = yara.compile(filepath=YARA_RULES_PATH)
    except yara.Error as e:
        return f"[!] YARA Compilation Error: {e}"

    try:
        # Scanning the dump file directly (efficient for large files)
        matches = rules.match(filepath=image_file, timeout=120) 
        
        yara_output = "\n" + "="*50 + "\n"
        yara_output += "         ⚡ YARA SCAN RESULTS (AUTO-TRIGGERED) ⚡\n"
        yara_output += "="*50 + "\n"
        
        if matches:
            yara_output += f"[!!!] FOUND {len(matches)} MATCHES IN MEMORY DUMP!\n"
            for match in matches:
                yara_output += f"    -> Rule Name: {match.rule}\n"
                yara_output += f"       Description: {match.meta.get('description', 'N/A')}\n"
        else:
            yara_output += "[OK] YARA Scan: No suspicious patterns detected.\n"
            
        return yara_output

    except Exception as e:
        return f"[!] YARA Runtime Error: {e}"

def run_command():
    def task():
        command = selected_command.get()
        image_file = imagepath.get().strip()
        output_folder = outputpath.get().strip()

        if not image_file:
            messagebox.showerror("Error", "Please enter a valid memory image path.")
            return
        if not output_folder:
            messagebox.showerror("Error", "Please select an output folder.")
            return

        # YARA AUTO-TRIGGER POINT
        try:
            # 1. Run YARA scan
            yara_results = run_yara_scan(image_file)
            
            # 2. Display results in output box (Clear previous output first)
            output_box.delete(1.0, END)
            output_box.insert(END, yara_results)
            output_box.see(END)
            
            # 3. Separate results from Volatility output
            output_box.insert(END, "\n" + "="*50 + "\n\n")

        except Exception as e:
             output_box.insert(END, f"\n[!] YARA Integration Error: {e}\n\n")

        output_filename = os.path.join(output_folder, f"{commands[command]}.txt")
        # Ensure vol.py is called correctly based on BASE_DIR
        vol_path = os.path.join(BASE_DIR, 'vol.py')
        full_command = f'python "{vol_path}" -f "{image_file}" {commands[command]}'
    
        try:
            output_box.insert(END, f"[+] Running Volatility Command: {full_command}\n\n")
            output_box.see(END)

            result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
            output = result.stdout
            
            #  Improve output display: capture messages even if they are written to stderr
            if not output.strip():
                # If stdout is truly empty, check stderr (where Volatility sometimes puts output or errors)
                output = result.stderr if result.stderr else "No visible output received from Volatility. Check the output file."
            
            # Write the captured output (whether stdout or stderr) to the file
            with open(output_filename, "w", encoding='utf-8') as log_file:
                log_file.write(output)

            output_box.insert(END, output)
            output_box.insert(END, f"\n\n[+] Output saved to: {output_filename}")
            output_box.see(END)
            
            if commands[command] == "windows.cmdline":
                extracted = extract_cmdline_info_only(output)
                show_cmdline_popup(extracted)

            if commands[command] in ["linux.netstat", "windows.netscan.NetScan", "windows.netscan.NetScan"]:
                ip_set = extract_ips_from_netstat(output)
                show_ips_popup(ip_set)

        except Exception as e:
            messagebox.showerror("Error", f"Command execution failed:\n{e}")

    threading.Thread(target=task).start()

Button(main_page, text="Run Selected Command", command=run_command,
        bg="#525453", fg="white", padx=10, pady=5).pack(pady=10)

#------------------------------------------- Help Page -------------------------------------------#

help_page = Frame(notebook)
notebook.add(help_page, text="Help")

# === Investigation Logic Steps ===
investigation_steps = {
    "Step 1: List Running Processes": (
        "Use the 'pslist' plugin to list all active processes.\n"
        "It helps identify what was running at the time of memory capture."
    ),
    "Step 2: Detect Hidden Processes": (
        "Use 'psscan' to find terminated or hidden processes.\n"
        "Useful for spotting stealth malware."
    ),
    "Step 3: Analyze Network Connections": (
        "Use 'netscan' or 'netstat' to view network connections.\n"
        "Analyze IPs for communication with external servers."
    ),
    "Step 4: Dump Suspicious Memory": (
        "Use 'procdump' to dump memory from selected processes for external analysis."
    ),
    "Step 5: Identify Injected Code": (
        "Use 'malfind' to detect memory regions with suspicious injected code."
    ),
    "Step 6: DLLs and Handles": (
        "Use 'dlllist' and 'handles' to see libraries and objects accessed by processes."
    ),
    "Step 7: Extract Command Line Arguments": (
        "Use 'cmdline' to review how processes were launched."
    ),
    "Step 8: Registry Hive Extraction": (
        "Use 'sam', 'system', and 'security' to retrieve Windows registry hives."
    ),
    "Step 9: Timeline and Activity": (
        "Use 'shellbags', 'userassist', or 'timeline' to build a history of user activity."
    ),
    "Step 10: VirusTotal IP Lookup": (
        "Extract IPs using 'netscan', then scan with VirusTotal to detect threats."
    ),
    "Step 11: MalwareBazaar Reputation Check": (
        "Use MalwareBazaar tab to check if a process/file is abnormal or rarely seen."
    ),
    "Step 12: Save and Report Findings": (
        "Export output, highlight suspicious items, and document your findings."
    )
}

# === How to Use the Tool (UI Guide) ===
tool_usage_steps = {
    "Step 1: Browse for Memory Image": (
        "In the Main tab, click 'Browse' next to 'Enter the memory image path'.\n"
        "Select your .raw, .vmem, .mem, or .bin file."
    ),
    "Step 2: Choose Output Folder": (
        "Click 'Browse' next to 'Select output directory'.\n"
        "This folder will contain all command results."
    ),
    "Step 3: Select Plugin": (
        "Use the dropdown to pick a plugin like 'pslist', 'malfind', etc.\n"
        "This defines what type of analysis will be performed."
    ),
    "Step 4: Run the Command": (
        "Click 'Run Selected Command'.\n"
        "The tool will start the process and display results below."
    ),
    "Step 5: Search Output": (
        "Use the search bar to find keywords in the output text box."
    ),
    "Step 6: Extract and Scan IPs": (
        "After 'netscan' or 'netstat', IPs will appear in a popup.\n"
        "Click 'Check Malicious IPs' to scan them using VirusTotal."
    ),
    "Step 7: Use MalwareBazaar Insights": (
        "Switch to the 'MalwareBazaar Insights' tab.\n"
        "Enter a process name or file/hash and click 'Search' to evaluate its behavior."
    ),
    "Step 8: Use VirusTotal Search Tab": (
        "Manually enter and lookup any IP in the 'VirusTotal Search' tab."
    ),
    "Step 9: Save and Document": (
        "Outputs are saved automatically in your output folder.\n"
        "Use the findings to build a report or case timeline."
    )
}

container = Frame(help_page, bg="#f0f0f0")
container.pack(fill=BOTH, expand=True, padx=10, pady=10)

top_section = Frame(container, bg="#f0f0f0")
top_section.pack(fill=BOTH, expand=True)

button_frame = Frame(top_section, bg="#f0f0f0")
button_frame.pack(side=LEFT, fill=Y, padx=(0, 10))

Label(button_frame, text="Investigation Steps", font=("Arial", 12, "bold"), bg="#f0f0f0").pack(pady=(0, 5))

def show_explanation(title):
    explanation_text.config(state=NORMAL)
    explanation_text.delete(1.0, END)
    if title in investigation_steps:
        explanation_text.insert(END, investigation_steps[title])
    elif title in tool_usage_steps:
        explanation_text.insert(END, tool_usage_steps[title])
    explanation_text.config(state=DISABLED)

for step in investigation_steps:
    Button(button_frame, text=step, command=lambda s=step: show_explanation(s),
            width=35, anchor="w", bg="#525453", fg="white", padx=5, pady=4).pack(pady=1)

Label(button_frame, text="Tool Usage Guide", font=("Arial", 12, "bold"), bg="#f0f0f0").pack(pady=(10, 5))

for step in tool_usage_steps:
    Button(button_frame, text=step, command=lambda s=step: show_explanation(s),
            width=35, anchor="w", bg="#3b6e77", fg="white", padx=5, pady=5).pack(pady=1)

explanation_frame = Frame(top_section, bg="#f0f0f0")
explanation_frame.pack(side=LEFT, fill=BOTH, expand=True)

explanation_text = Text(explanation_frame, height=15, wrap=WORD, bg="white", font=("Arial", 11))
explanation_text.pack(fill=BOTH, expand=True)

scrollbar = Scrollbar(explanation_text)
scrollbar.pack(side=RIGHT, fill=Y)
scrollbar.config(command=explanation_text.yview)

first_key = list(investigation_steps.keys())[0]
show_explanation(first_key)

# === Guided Assistant Section ===
assistant_frame = LabelFrame(top_section, text="Guided Investigation Assistant", bg="#f0f0f0", padx=10, pady=10)
assistant_frame.pack(side=RIGHT, fill=Y, padx=10, pady=10)

Label(assistant_frame, text="What are you investigating?", bg="#f0f0f0", font=("Arial", 11)).pack(anchor="w", pady=(0, 5))

investigation_type = StringVar()
investigation_dropdown = ttk.Combobox(assistant_frame, textvariable=investigation_type, width=25, state="readonly")
investigation_dropdown['values'] = ["Malware", "Insider Threat", "Stolen Data"]
investigation_dropdown.current(0)
investigation_dropdown.pack(anchor="w", pady=(0, 5))

Button(assistant_frame, text="Get Suggestions", bg="#525453", fg="white",
        command=lambda: show_suggestions(investigation_type.get())).pack(anchor="w", pady=(0, 10))

suggestion_box = Text(assistant_frame, height=16, wrap=WORD, bg="white", font=("Arial", 10))
suggestion_box.pack(fill=BOTH, expand=True)

def show_suggestions(selected_case):
    suggestions = {
        "Malware": [
            "- malfind: Detect injected malware memory",
            "- pslist: View active processes",
            "- dlllist: Loaded libraries in memory",
            "- procdump: Dump process memory",
            "- netscan: Network activity from malware"
        ],
        "Insider Threat": [
            "- cmdline: Track how programs were launched",
            "- userassist: Apps used by the user",
            "- filescan: Accessed or exfiltrated files",
            "- handles: Objects opened by processes",
            "- sam: User account data & password hashes"
        ],
        "Stolen Data": [
            "- filescan: Opened or exfiltrated files",
            "- shellbags: Folder access history",
            "- schtasks: Scheduled data exfil tasks",
            "- usbdevs: Connected USB storage devices",
            "- timeline: Build timeline of activity"
        ]
    }
    suggestion_box.config(state=NORMAL)
    suggestion_box.delete(1.0, END)
    suggestion_box.insert(END, f"Recommended Commands for '{selected_case}':\n\n")
    for cmd in suggestions.get(selected_case, ["No suggestions available."]):
        suggestion_box.insert(END, cmd + "\n")
    suggestion_box.config(state=DISABLED)

show_suggestions("Malware")



def extract_cmdline_info_only(output_text):
    results = []
    lines = output_text.strip().split("\n")

    for line in lines:
        line = line.strip()
        if not line or line.startswith("Volatility") or line.startswith("PID") or line.startswith("[+]"):
            continue

        # Example: "1456    explorer.exe    C:\Windows\Explorer.EXE"
        parts = line.split("\t")
        if len(parts) >= 3:
            pid, proc_name, cmd = parts[0], parts[1], "\t".join(parts[2:])
            results.append((proc_name, cmd))

    return results


def show_cmdline_popup(results):
    popup = Toplevel(root)
    popup.title("Parsed Command Line Output")
    popup.geometry("700x400")

    text_frame = Frame(popup)
    text_frame.pack(fill=BOTH, expand=True)

    scrollbar = Scrollbar(text_frame)
    scrollbar.pack(side=RIGHT, fill=Y)

    text_widget = Text(text_frame, wrap=WORD, font=("Courier", 10), yscrollcommand=scrollbar.set)
    text_widget.pack(side=LEFT, fill=BOTH, expand=True)
    scrollbar.config(command=text_widget.yview)

    if not results:
        text_widget.insert(END, "No extracted process/command line pairs found.")
    else:
        for proc, cmd in results:
            text_widget.insert(END, f"Process: {proc}\nCommand: {cmd}\n{'-'*60}\n")
    text_widget.config(state=NORMAL)


def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast)
    except ValueError:
        return False

def extract_ips_from_netstat(output):
    # Regex for IPv4 and IPv6 addresses
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[a-fA-F0-9]{0,4}:){2,7}[a-fA-F0-9]{0,4}\b"
    return set(re.findall(ip_pattern, output))
def show_ips_popup(ip_set):
    if not ip_set:
        messagebox.showinfo("No IPs Found", "No IP addresses were found in the output.")
        return

    popup = Toplevel(root)
    popup.title("Extracted IP Addresses")
    popup.geometry("350x400")
    Label(popup, text="Unique IP Addresses:", font=("Arial", 12)).pack(pady=10)
    ip_listbox = Listbox(popup, width=40, height=20)
    for ip in sorted(ip_set):
        ip_listbox.insert(END, ip)
    ip_listbox.pack(padx=10, pady=10)

    # --- Button to check VirusTotal for public IPs ---
    def run_virustotal_check():
        check_ips_on_virustotal_and_show(ip_set)

    Button(popup, text="Check Malicious IPs", command=run_virustotal_check, bg="#e06666", fg="white").pack(pady=8)
    Button(popup, text="Close", command=popup.destroy).pack(pady=5)

                        #------------------------------------------- VirusTotal Page -------------------------------------------#


vt_page = Frame(notebook)
notebook.add(vt_page, text="VirusTotal Search")


# VirusTotal search function
def search_virustotal():
    url = "https://www.virustotal.com/api/v3/ip_addresses/"
    api_key = "364284237315dc04a8dbbfe2a649a7bdcfcd576313336d035e123d09cf44d8bb"
    search_term = vt_search_entry.get()

    headers = {
        "x-apikey": api_key
    }

    response = requests.get(f"{url}{search_term}", headers=headers)
    if response.status_code == 200:
        parsed_data = parse_virustotal_response(response.text)
        vt_result_box.delete(1.0, END)
        vt_result_box.insert(END, parsed_data)
    else:
        vt_result_box.delete(1.0, END)
        vt_result_box.insert(END, f"Error retrieving data from VirusTotal{response.text}")
# Function to parse and sort VirusTotal API response
def parse_virustotal_response(response_data):
    try:
        data = json.loads(response_data)
    except json.JSONDecodeError:
        print("Invalid JSON response.")
        return
    
    result_display = []

    def format_whois_info(attributes):
        whois_info = ""
        if 'whois' in attributes:
            whois_info += f"WHOIS: {attributes['whois']}\n"
        if 'organisation' in attributes:
            whois_info += f"Organisation: {attributes['organisation']}\n"
        if 'country' in attributes:
            whois_info += f"Country: {attributes['country']}\n"
        if 'address' in attributes:
            whois_info += f"Address: {', '.join(attributes['address'])}\n"
        if 'phone' in attributes:
            whois_info += f"Phone: {attributes['phone']}\n"
        if 'created' in attributes:
            whois_info += f"Created: {attributes['created']}\n"
        if 'last-modified' in attributes:
            whois_info += f"Last Modified: {attributes['last-modified']}\n"
        return whois_info

    def format_network_info(network_data):
        network_info = ""
        if 'network' in network_data:
            network_info += f"Network: {network_data['network']}\n"
        if 'asn' in network_data:
            network_info += f"ASN: {network_data['asn']}\n"
        if 'as_owner' in network_data:
            network_info += f"AS Owner: {network_data['as_owner']}\n"
        if 'regional_internet_registry' in network_data:
            network_info += f"Regional Internet Registry: {network_data['regional_internet_registry']}\n"
        return network_info

    def format_last_analysis_stats(stats):
        stats_info = ""
        if 'malicious' in stats:
            stats_info += f"Malicious: {stats['malicious']}\n"
        if 'suspicious' in stats:
            stats_info += f"Suspicious: {stats['suspicious']}\n"
        if 'undetected' in stats:
            stats_info += f"Undetected: {stats['undetected']}\n"
        if 'harmless' in stats:
            stats_info += f"Harmless: {stats['harmless']}\n"
        if 'timeout' in stats:
            stats_info += f"Timeout: {stats['timeout']}\n"
        return stats_info

    def format_last_analysis_results(results):
        # Sort results so that 'malicious' appears first
        sorted_results = sorted(results.items(), key=lambda x: x[1]['category'] == 'malicious', reverse=True)
        analysis_results = ""
        for engine, result in sorted_results:
            analysis_results += f"{engine}: {result['result']} - {result['category']}\n"
        return analysis_results


    # Gather WHOIS info
    if 'data' in data and 'attributes' in data['data']:
        result_display.append(format_whois_info(data['data']['attributes']))

    # Gather Network info
    if 'data' in data and 'relationships' in data['data']:
        network_data = data['data']['relationships']
        result_display.append(format_network_info(network_data))

    # Gather Last Analysis Stats
    if 'data' in data and 'attributes' in data['data']:
        stats = data['data']['attributes'].get('last_analysis_stats', {})
        result_display.append(format_last_analysis_stats(stats))

    # Gather Last Analysis Results and sort them (malicious first)
    if 'data' in data and 'attributes' in data['data']:
        results = data['data']['attributes'].get('last_analysis_results', {})
        result_display.append(format_last_analysis_results(results))


    return "\n".join(result_display)

def is_ip_malicious(ip_address):
    url = "https://www.virustotal.com/api/v3/ip_addresses/"
    api_key = "364284237315dc04a8dbbfe2a649a7bdcfcd576313336d035e123d09cf44d8bb" 
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(f"{url}{ip_address}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            # If 'malicious' count > 0, it's considered malicious
            is_mal = stats.get('malicious', 0) > 0
            return (is_mal, data if is_mal else None)
        else:
            print(f"VirusTotal lookup failed for {ip_address}: {response.status_code}")
            return (False, None)
    except Exception as e:
        print(f"Exception while looking up {ip_address}: {e}")
        return (False, None)
def scan_output_ips_for_threats():
    output = output_box.get("1.0", END)
    ip_set = extract_ips_from_netstat(output)
    check_ips_on_virustotal_and_show(ip_set)
def show_malicious_ips_details_popup(malicious_ips_data):
    popup = Toplevel(root)
    popup.title("Malicious IPs Details (VirusTotal)")
    popup.geometry("650x400")

    if not malicious_ips_data:
        Label(popup, text="No malicious IPs found.", font=("Arial", 12)).pack(pady=20)
        Button(popup, text="Close", command=popup.destroy).pack(pady=10)
        return

    frame = Frame(popup)
    frame.pack(fill=BOTH, expand=True)

    scrollbar = Scrollbar(frame)
    scrollbar.pack(side=RIGHT, fill=Y)

    listbox = Text(frame, wrap=WORD, yscrollcommand=scrollbar.set, width=80, height=20)
    listbox.pack(side=LEFT, fill=BOTH, expand=True)
    scrollbar.config(command=listbox.yview)

    for ip, data in malicious_ips_data:
        vt_attr = data.get('data', {}).get('attributes', {})
        stats = vt_attr.get('last_analysis_stats', {})
        engines = vt_attr.get('last_analysis_results', {})
        num_malicious = stats.get('malicious', 0)
        vt_url = f"https://www.virustotal.com/gui/ip-address/{ip}"
        # List engines that flagged as malicious
        mal_engines = [engine for engine, result in engines.items() if result.get('category') == 'malicious']

        listbox.insert(END, f"IP: {ip}\n")
        listbox.insert(END, f"Malicious Detections: {num_malicious}\n")
        listbox.insert(END, f"Flagged by engines: {', '.join(mal_engines) if mal_engines else 'N/A'}\n")
        listbox.insert(END, f"VirusTotal Link: {vt_url}\n")
        listbox.insert(END, "-"*65 + "\n")

    Button(popup, text="Close", command=popup.destroy).pack(pady=10)


def check_ips_on_virustotal_and_show(ip_set):
    malicious_ips_data = []  # Will hold (ip, vt_data) tuples
    public_ips = [ip for ip in ip_set if is_public_ip(ip)]

    def check_all():
        for idx, ip in enumerate(public_ips):
            is_malicious, vt_data = is_ip_malicious(ip)
            if is_malicious and vt_data:
                malicious_ips_data.append((ip, vt_data))
            time.sleep(15)  # Avoid API rate limit
        show_malicious_ips_details_popup(malicious_ips_data)

    threading.Thread(target=check_all).start()


# VirusTotal Search Page Layout
Label(vt_page, text="Enter IP Address: ").pack(pady=15)
vt_search_entry = Entry(vt_page, width=50)
vt_search_entry.pack(pady=20)

vt_search_button = Button(vt_page, text="Search", command=search_virustotal, bg="#525453", fg="white")
vt_search_button.pack(pady=10)

vt_result_box = Text(vt_page, height=15, width=100, wrap=WORD, bg="white")
vt_result_box.pack(padx=10, pady=10)
Label(vt_page, text="Warning, Please do not share your API key.").pack(pady=15)

                        #------------------------------------------- MalwareBazaar Page -------------------------------------------#

malwarebazaar_page = Frame(notebook)
notebook.add(malwarebazaar_page, text="MalwareBazaar Search")
Label(malwarebazaar_page, text="Enter Process name:").pack(pady=10)
malwarebazaar_entry = Entry(malwarebazaar_page, width=60)
malwarebazaar_entry.pack()

def search_malwarebazaar():
    process_name = malwarebazaar_entry.get().strip()

    if not process_name:
        messagebox.showerror("Error", "Please enter a valid process name.")
        return

    url = "https://mb-api.abuse.ch/api/v1/"

    payload = {
        "query": "get_siginfo",
        "signature": process_name
    }

    headers = {
        "Auth-Key": "c7ac8cc312e9e4786067002fef0fed3df24e40d4305ed651"
    }

    try:
        resp = requests.post(
            url,
            data=payload,
            headers=headers,
            timeout=20
        )

        malwarebazaar_result_box.delete(1.0, END)

        if resp.status_code != 200:
            malwarebazaar_result_box.insert(
                END,
                f"[HTTP ERROR {resp.status_code}]\n\n{resp.text}"
            )
            return

        data = resp.json()

        malwarebazaar_result_box.insert(
            END,
            json.dumps(data, indent=4)
        )

    except Exception as e:
        malwarebazaar_result_box.delete(1.0, END)
        malwarebazaar_result_box.insert(
            END,
            f"[EXCEPTION]\n{str(e)}"
        )

Button(malwarebazaar_page, text="Search", command=search_malwarebazaar, bg="#525453", fg="white").pack(pady=10)

malwarebazaar_result_box = Text(malwarebazaar_page, height=20, width=100, wrap=WORD, bg="white")
malwarebazaar_result_box.pack(padx=10, pady=10)

Label(malwarebazaar_page, text="Warning, Please do not share your API key.").pack(pady=10)

# MalwareBazaar API Key 
MALWAREBAZAAR_API_KEY = "c7ac8cc312e9e4786067002fef0fed3df24e40d4305ed651"
def open_malwarebazaar_docs():
    import webbrowser
    webbrowser.open("https://bazaar.abuse.ch/api/")

link_label = Label(
    malwarebazaar_page,
    text="🔗 Learn how MalwareBazaar scores processes",
    fg="blue",
    cursor="hand2",
    bg="#f0f0f0",
    font=("Arial", 10, "underline")
)
link_label.pack(pady=(5, 15))
link_label.bind("<Button-1>", lambda e: open_malwarebazaar_docs())

root.mainloop()