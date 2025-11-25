#task2 


import struct
import sys

def read_partition_table(image_path):
    with open(image_path, "rb") as img:
        # Read the first 512 bytes (MBR)
        mbr = img.read(512)

    # Partition entries start at offset 446
    partition_table_offset = 446

    print("Partition Table Analysis")
    print("-----------------------------------")

    for i in range(4):
        entry_offset = partition_table_offset + i * 16
        entry = mbr[entry_offset: entry_offset + 16]
        # Unpack MBR partition entry structure
        (
            status,
            start_head,
            start_sector,
            start_cylinder,
            partition_type,
            end_head,
            end_sector,
            end_cylinder,
            start_lba,
            num_sectors
        ) = struct.unpack("<BBBBBBBBII", entry)

        # Only print valid partitions
        if partition_type != 0x00:
            print(f"Partition {i + 1}:")
            print(f"  Status:               {hex(status)}")
            print(f"  Partition Type:       {hex(partition_type)} {interpret_partition_type(partition_type)}")
            print(f"  Start Of Sector(LBA) :{start_lba}")
            print(f"  Number of Sectors:    {num_sectors}")
            print(f"  Size (approx):        {num_sectors * 512 / (1024**3):.2f} GB")
            print("-----------------------------------")

def interpret_partition_type(ptype):
    types = {
        0x07: "NTFS / exFAT",
        0x0B: "FAT32 (CHS)",
        0x0C: "FAT32 (LBA)",
        0x83: "Linux filesystem",
        0x82: "Linux swap",
        0xAF: "Apple HFS / APFS",
        0xA5: "FreeBSD",
        0xEE: "GPT protective",
    }
    return types.get(ptype, "Unknown / Other")

if __name__ == "__main__":
    # HARD-CODE THE PATH HERE
    image_path = r"D:\CW Disk Image\CW Image.dd"
    
    read_partition_table(image_path)
