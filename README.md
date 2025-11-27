for first code (partition) 
the script is a small piece of code to help with forensics utility used to parse and interpret the MBR (Master Boot Record) 
It reads the first 512 bytes of the image, extracts the four 16-byte MBR partition entries, and prints human-readable information about each valid partition.


for the second code (analysis)
This Python script is a standalone forensic tool that extracts key investigative artefacts from offline Windows Registry hives and event log files. It is designed for digital forensics coursework,
incident response, and system analysis where you must examine Windows data outside of a live system.

The tool loads exported registry hive files (SOFTWARE, SYSTEM, SAM, NTUSER.DAT) and a Windows event log (Security.evtx) from a specified directory. It then parses and reports on several important categories of forensic evidence.
but for the code to work these files have to be extracted from autopsy.
