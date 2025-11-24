import struct
import os

# Path to your disk image
IMAGE_PATH = r"C:\Users\Aly\Desktop\CW Disk Image\CW Image.dd"
SECTOR_SIZE = 512

def read_mbr(image_path):
    with open(image_path, "rb") as f:
        mbr = f.read(SECTOR_SIZE)  # first 512 bytes
    return mbr

def parse_partitions(mbr_data):
    partitions = []
    # Partition entries are 16 bytes each, starting at offset 446
    for i in range(4):
        offset = 446 + i * 16
        entry = mbr_data[offset:offset + 16]

        status = entry[0]               # 0x80 = bootable, 0x00 = non-bootable
        part_type = entry[4]            # partition type ID
        start_sector = struct.unpack("<I", entry[8:12])[0]
        total_sectors = struct.unpack("<I", entry[12:16])[0]

        if part_type == 0x00 or total_sectors == 0:
            # Empty entry, skip
            continue

        start_offset_bytes = start_sector * SECTOR_SIZE
        size_bytes = total_sectors * SECTOR_SIZE
        size_gb = size_bytes / (1024 ** 3)

        partitions.append({
            "index": i + 1,
            "bootable": (status == 0x80),
            "type_hex": f"0x{part_type:02X}",
            "start_sector": start_sector,
            "total_sectors": total_sectors,
            "start_offset_bytes": start_offset_bytes,
            "size_bytes": size_bytes,
            "size_gb": size_gb
        })
    return partitions

def main():
    if not os.path.exists(IMAGE_PATH):
        print(f"[!] Image not found: {IMAGE_PATH}")
        return

    print(f"[+] Analyzing partition table for: {IMAGE_PATH}\n")

    mbr = read_mbr(IMAGE_PATH)
    partitions = parse_partitions(mbr)

    if not partitions:
        print("[!] No valid partitions found in MBR.")
        return

    for p in partitions:
        print(f"Partition {p['index']}:")
        print(f"  Bootable:        {p['bootable']}")
        print(f"  Type (hex):      {p['type_hex']}")
        print(f"  Start sector:    {p['start_sector']}")
        print(f"  Total sectors:   {p['total_sectors']}")
        print(f"  Start offset:    {p['start_offset_bytes']} bytes")
        print(f"  Approx size:     {p['size_gb']:.2f} GB")
        print()

if __name__ == "__main__":
    main()