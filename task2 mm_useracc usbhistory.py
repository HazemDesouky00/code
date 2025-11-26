import os
from Registry import Registry
from Evtx.Evtx import Evtx

# === CONFIG ===
REG_PATH = r"D:\cw_milestone2_registry"

SOFTWARE_HIVE = os.path.join(REG_PATH, "SOFTWARE")
SYSTEM_HIVE   = os.path.join(REG_PATH, "SYSTEM")
SAM_HIVE      = os.path.join(REG_PATH, "SAM")
NTUSER_HIVE   = os.path.join(REG_PATH, "NTUSER.DAT")
SECURITY_LOG  = os.path.join(REG_PATH, "Security.evtx")



print(" FORENSIC REGISTRY ANALYZER")
print("==============================\n")


# ------------------------------------------
# 1. INSTALLED APPLICATIONS (from SOFTWARE hive)
# ------------------------------------------
def get_installed_apps():
    print("\n[+] Installed Applications:")
    try:
        reg = Registry.Registry(SOFTWARE_HIVE)
        uninstall = reg.open("Microsoft\\Windows\\CurrentVersion\\Uninstall")

        apps = []
        for sub in uninstall.subkeys():
            values = [v.name() for v in sub.values()]
            if "DisplayName" in values:
                name = sub.value("DisplayName").value()
                apps.append(name)
                print("  -", name)

        print(f"\n[+] Total Installed Applications Found: {len(apps)}")

    except Exception as e:
        print("  Error reading installed apps:", e)



# 2. USER ACCOUNTS (from SAM hive) — MODIFIED

def get_user_accounts():
    print("\n[+] User Accounts:")

    try:
        reg = Registry.Registry(SAM_HIVE)
        names_key = reg.open("SAM\\Domains\\Account\\Users\\Names")

        users = [sub.name() for sub in names_key.subkeys()]

        # Print each username
        for u in users:
            print("  -", u)

        # Print total count
        print(f"\n[+] Total User Accounts Found: {len(users)}")

    except Exception as e:
        print("  Error reading SAM:", e)



# 3. USB DEVICE HISTORY (from SYSTEM hive)

def get_usb_history():
    print("\n[+] USB Device History:")
    try:
        reg = Registry.Registry(SYSTEM_HIVE)
        usb_key = reg.open("Enum\\USBSTOR")

        device_list = []
        for device in usb_key.subkeys():
            device_list.append(device.name())
            print(f"  Device: {device.name()}")
            for instance in device.subkeys():
                print(f"     Instance: {instance.name()}")

        print(f"\n[+] Total USB Devices Found: {len(device_list)}")

    except Exception as e:
        print("  Error reading USBSTOR:", e)


# ------------------------------------------
# 4. COMMAND / RUN HISTORY (from NTUSER.DAT)
# ------------------------------------------
def get_run_history():
    print("\n[+] Run (Command) History:")
    try:
        reg = Registry.Registry(NTUSER_HIVE)
        run_key = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")

        commands = []

        for v in run_key.values():
            if v.name() == "MRUList":
                continue
            commands.append(v.value())
            print(f"  - {v.name()} → {v.value()}")

        print(f"\n[+] Total RunMRU Entries Found: {len(commands)}")

    except Exception as e:
        print("  Error reading RunMRU:", e)



# 5. OPTIONAL: Logon events from Security.evtx

def get_logon_events():
    print("\n[+] Logon/Logoff Events from Security.evtx:")
    try:
        with Evtx(SECURITY_LOG) as log:
            count = 0
            for record in log.records():
                xml = record.xml()
                if "4624" in xml:     # Successful logon
                    print(f"  [LOGON] {record.creation_time}")
                    count += 1
            print(f"\n[+] Total Successful Logon Events Found: {count}")

    except Exception as e:
        print("  Error reading Security.evtx:", e)



# RUN ALL
get_installed_apps()
get_user_accounts()
get_usb_history()
get_run_history()
get_logon_events()

print("\n[+] Script completed.\n")
