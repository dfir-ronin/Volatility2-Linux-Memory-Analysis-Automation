from __future__ import print_function
import os
import subprocess
import io

# ========== CONFIGURATION ==========
MEMORY_IMAGE = r"C:\Analysis\dump.mem"
PROFILE = "LinuxUbuntux64"
VOL_PATH = r"C:\Users\shinichi\Downloads\volatility\vol.py"
OUTPUT_DIR = r"C:\Analysis\fastest_to_slowest_4\volatility_output"
PYTHON_EXECUTABLE = "python"
# ===================================

plugin_categories = {
    "process_analysis": [
        "linux_pslist", "linux_psaux", "linux_pstree", "linux_threads",
        "linux_psenv", "linux_pidhashtable", "linux_psscan", "linux_psxview", "linux_pslist_cache"
    ],
    "file_analysis": [
        "linux_getcwd", "linux_mount", "linux_mount_cache", "linux_enumerate_files",
        "linux_dentry_cache", "linux_kernel_opened_files", "linux_lsof", "linux_find_file",
        "linux_recover_filesystem", "linux_tmpfs", "linux_dump_map"
    ],
    "malware_detection": [
        "linux_check_creds", "linux_check_modules", "linux_check_tty", "linux_check_afinfo",
        "linux_check_fop", "linux_check_idt", "linux_check_inline_kernel", "linux_apihooks",
        "linux_hidden_modules", "linux_check_syscall", "linux_check_evt_arm",
        "linux_check_syscall_arm", "linux_malfind", "linux_process_hollow"
    ],
    "memory_analysis": [
        "linux_proc_maps", "linux_proc_maps_rb", "linux_memmap", "linux_vma_cache",
        "linux_aslr_shift", "linux_elfs", "linux_strings", "linux_dynamic_env",
        "linux_procdump", "linux_librarydump", "linux_moddump", "linux_volshell"
    ],
    "network_analysis": [
        "linux_ifconfig", "linux_arp", "linux_route_cache", "linux_netstat",
        "linux_list_raw", "linux_netfilter", "linux_netscan", "linux_pkt_queues", "linux_sk_buff_cache"
    ],
    "bash_user_activity": [
        "linux_bash_env", "linux_bash_hash", "linux_bash", "linux_info_regs", "linux_truecrypt_passphrase"
    ],
    "kernel_system_info": [
        "linux_banner", "linux_cpuinfo", "linux_lsmod", "linux_iomem",
        "linux_library_list", "linux_ldrmodules", "linux_keyboard_notifiers", "linux_slabinfo"
    ],
    "yara_and_shell": [
        "linux_yarascan", "linux_volshell"
    ]
}

# Flatten mapping
plugin_to_category = {}
for category, plugins in plugin_categories.items():
    for plugin in plugins:
        plugin_to_category[plugin] = category

# Ordered from fastest to slowest
# removed linux_memmap  "linux_proc_maps", , "linux_yarascan", "linux_volshell"
plugin_priority = [
    "linux_pslist", "linux_psaux", "linux_pstree", "linux_threads", "linux_psenv",
    "linux_pidhashtable", "linux_getcwd", "linux_mount", "linux_mount_cache",
    "linux_banner", "linux_cpuinfo", "linux_lsmod", "linux_arp", "linux_ifconfig",
    "linux_bash_env", "linux_bash_hash",
    "linux_psscan", "linux_psxview", "linux_pslist_cache", "linux_enumerate_files",
    "linux_dentry_cache", "linux_kernel_opened_files", "linux_lsof",
    "linux_check_creds", "linux_check_modules", "linux_check_tty",
    "linux_check_afinfo", "linux_check_fop", "linux_check_idt", "linux_check_inline_kernel",
    "linux_apihooks", "linux_hidden_modules", "linux_proc_maps_rb",
    "linux_vma_cache", "linux_aslr_shift", "linux_elfs",
    "linux_netstat", "linux_list_raw", "linux_netfilter", "linux_route_cache",
    "linux_bash", "linux_info_regs", "linux_iomem", "linux_library_list",
    "linux_ldrmodules", "linux_keyboard_notifiers", "linux_slabinfo",
    "linux_check_syscall", "linux_check_evt_arm", "linux_check_syscall_arm",
    "linux_malfind", "linux_process_hollow",
    "linux_find_file", "linux_recover_filesystem", "linux_tmpfs", "linux_dump_map",
    "linux_strings", "linux_dynamic_env", "linux_procdump", "linux_librarydump",
    "linux_moddump", "linux_netscan", "linux_pkt_queues", "linux_sk_buff_cache",
    "linux_truecrypt_passphrase"
]

def run_plugin(plugin_name, category):
    output_folder = os.path.join(OUTPUT_DIR, category)
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    output_xlsx = os.path.join(output_folder, plugin_name + ".xlsx")
    output_txt = os.path.join(output_folder, plugin_name + ".txt")

    cmd_xlsx = [
        PYTHON_EXECUTABLE, VOL_PATH,
        "-f", MEMORY_IMAGE,
        "--profile=" + PROFILE,
        plugin_name,
        "--output=xlsx",
        "--output-file=" + output_xlsx
    ]

    print("[*] Running with XLSX output: " + plugin_name)
    try:
        ret = subprocess.call(cmd_xlsx, shell=False)
        if ret == 0 and os.path.exists(output_xlsx) and os.path.getsize(output_xlsx) > 0:
            print("[+] XLSX saved: " + output_xlsx)
            return
        else:
            print("[-] XLSX not supported or failed, falling back to TXT")
    except Exception as e:
        print("[-] Error during XLSX export: " + str(e))

    # Fallback to plain text
    cmd_txt = [
        PYTHON_EXECUTABLE, VOL_PATH,
        "-f", MEMORY_IMAGE,
        "--profile=" + PROFILE,
        plugin_name
    ]
    with io.open(output_txt, "w", encoding="utf-8") as f:
        subprocess.call(cmd_txt, stdout=f, stderr=subprocess.STDOUT, shell=False)
    print("[+] TXT saved: " + output_txt)

def main():
    for plugin in plugin_priority:
        category = plugin_to_category.get(plugin, "uncategorized")
        run_plugin(plugin, category)

    print("\n[+] All plugins completed. Output saved to:\n" + OUTPUT_DIR)

if __name__ == "__main__":
    main()
