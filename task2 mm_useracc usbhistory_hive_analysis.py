import os
from Registry import Registry
from Evtx.Evtx import Evtx


REG_PATH = r"D:\cw_milestone2_registry"

SOFTWARE = os.path.join(REG_PATH, "SOFTWARE")
SYSTEM   = os.path.join(REG_PATH, "SYSTEM")
SAM      = os.path.join(REG_PATH, "SAM")
NTUSER   = os.path.join(REG_PATH, "NTUSER.DAT")
SECURITY = os.path.join(REG_PATH, "Security.evtx")  



print("\n== FORENSIC REGISTRY ANALYZER ===\n")




def installed_apps():
    print("[+] Installed Applications:")
    try:
        reg = Registry.Registry(SOFTWARE)
        key = reg.open("Microsoft\\Windows\\CurrentVersion\\Uninstall")

        count = 0
        for sub in key.subkeys():
            try:
                name = sub.value("DisplayName").value()
                print("  -", name)
                count += 1
            except:
                continue

        print(f"[+] Total found: {count}\n")

    except Exception as e:
        print("  Error:", e, "\n")



# 2. USER ACCOUNTS  (SAM hive)

def user_accounts():
    print("[+] User Accounts:")
    try:
        reg = Registry.Registry(SAM)
        names = reg.open("SAM\\Domains\\Account\\Users\\Names")

        users = [key.name() for key in names.subkeys()]
        for u in users:
            print("  -", u)

        print(f"[+] Total found: {len(users)}\n")

    except Exception as e:
        print("  Error:", e, "\n")



# 3. USB HISTORY  (SYSTEM hive)
def usb_history():
    print("[+] USB Device History:")

    try:
        reg = Registry.Registry(SYSTEM)

        # Get current control set number
        select = reg.open("Select")
        curr = select.value("Current").value()
        control_set = f"ControlSet00{curr}"

        usb_key = reg.open(f"{control_set}\\Enum\\USBSTOR")

        count = 0
        for dev in usb_key.subkeys():
            print("  Device:", dev.name())
            for inst in dev.subkeys():
                print("     Instance:", inst.name())
            count += 1

        print(f"[+] Total USB devices: {count}\n")

    except Exception as e:
        print("  Error:", e, "\n")




# 4. RUN / COMMAND HISTORY (NTUSER.DAT)

def run_history():
    print("[+] Run Command History (RunMRU):")
    try:
        reg = Registry.Registry(NTUSER)
        run_key = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")

        count = 0
        for v in run_key.values():
            if v.name() == "MRUList":
                continue
            print(f"  - {v.name()} = {v.value()}")
            count += 1

        print(f"[+] Total commands: {count}\n")

    except Exception as e:
        print("  Error:", e, "\n")




# 5. OPTIONAL — SECURITY.LOG (Event ID 4624)

def logon_events():
    if not os.path.exists(SECURITY):
        print("[+] No Security.evtx found — skipping.\n")
        return

    print("[+] Successful Logon Events (4624):")
    try:
        count = 0
        with Evtx(SECURITY) as log:
            for record in log.records():
                xml = record.xml()
                if "<EventID>4624</EventID>" in xml:
                    print("  - Logon @", record.creation_time)
                    count += 1

        print(f"[+] Total logons: {count}\n")

    except Exception as e:
        print("  Error:", e, "\n")



#to run everythinh 
installed_apps()
user_accounts()
usb_history()
run_history()
logon_events()