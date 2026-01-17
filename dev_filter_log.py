import os

# Kodi Log Path (Windows Store version)
log_path = os.path.expandvars(r"%LOCALAPPDATA%\Packages\XBMCFoundation.Kodi_4n2hpmxwrvr6p\LocalCache\Roaming\Kodi\kodi.log")

if not os.path.exists(log_path):
    # Try standard install path if store version not found
    log_path = os.path.expandvars(r"%APPDATA%\Kodi\kodi.log")

if not os.path.exists(log_path):
    print(f"Log file not found at default locations.")
    exit(1)

print(f"Reading log file: {log_path}")

try:
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    original_count = len(lines)
    filtered_lines = [line for line in lines if "vfs.stream.fast" in line]
    new_count = len(filtered_lines)

    if new_count == 0:
        print("Warning: No lines found containing 'vfs.stream.fast'. File not modified.")
    else:
        with open(log_path, 'w', encoding='utf-8') as f:
            f.writelines(filtered_lines)
        print(f"Done. Filtered {original_count} lines down to {new_count} lines containing 'vfs.stream.fast'.")

except PermissionError:
    print("Error: Permission denied. Please close Kodi (or any program holding the file) and try again.")
except Exception as e:
    print(f"An error occurred: {e}")
