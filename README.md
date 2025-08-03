# Volatility2 Linux Memory Analysis Automation

This script automates the execution of multiple **Volatility** plugins on a Linux memory image. It organizes output by category, prioritizes plugin execution order, and attempts to save results in `.xlsx` format, falling back to `.txt` if necessary.

---

## Project Structure

```
project_root/
│
├── volatility_runner.py      # <-- The script provided
├── dump.mem                  # Memory image to be analyzed
├── vol.py                    # Path to the Volatility script
├── /volatility_output        # All plugin results saved here
```

---

## Configuration

Set the following variables at the top of the script:

```python
MEMORY_IMAGE = r"C:\\Analysis\\dump.mem"
PROFILE = "LinuxUbuntux64"
VOL_PATH = r"C:\\Users\\shinichi\\Downloads\\volatility\\vol.py"
OUTPUT_DIR = r"C:\\Analysis\\volatility_output"
PYTHON_EXECUTABLE = "python"
```

---

## Plugin Categories

Plugins are grouped into functional categories like:

- **Process Analysis** – e.g., `linux_pslist`, `linux_psaux`
- **File Analysis** – e.g., `linux_lsof`, `linux_enumerate_files`
- **Malware Detection** – e.g., `linux_malfind`, `linux_check_modules`
- **Network Analysis** – e.g., `linux_netstat`, `linux_ifconfig`
- **Kernel/System Info** – e.g., `linux_banner`, `linux_lsmod`
- **User Activity** – e.g., `linux_bash`, `linux_truecrypt_passphrase`
- **YARA & Shell** – e.g., `linux_yarascan`, `linux_volshell`

> Plugins not mapped to a category default to `uncategorized`.

---

## How It Works

The script:

1. Iterates over a **priority list** of plugins.
2. Attempts to run each plugin with `--output=xlsx`.
3. Falls back to plain text output if `.xlsx` is unsupported.
4. Saves each plugin result in its corresponding category folder.

---

## Example Output Structure

```
volatility_output/
├── process_analysis/
│   ├── linux_pslist.xlsx
│   └── linux_psaux.txt
├── malware_detection/
│   ├── linux_malfind.xlsx
│   └── linux_check_modules.txt
...
```

---

## Usage

Run the script from the command line:

```bash
python volatility_runner.py
```

Make sure:

- You have Python installed and accessible via the configured path.
- Volatility is correctly installed and its dependencies are met.
- The memory image and profile are correct.

---

## Requirements

- Python 2.7 
- Volatility 2.x
- A valid Linux memory image (`.mem`)
- Corresponding Linux profile

---

## Notes

- The script **automatically creates output directories** if they don't exist.
- Output formats default to `.xlsx`, which is more portable for post-analysis. Falls back to `.txt` where needed.
- Plugins known to be slow or unstable can be commented out from the `plugin_priority` list.

---

## License

This script is provided "as-is" under the MIT License.

---

## Author

- **dfir-ronin** – [https://github.com/dfir-ronin/]

---
