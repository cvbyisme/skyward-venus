"""Rewrite a stock boot image so its ramdisk is LZ4 in the legacy framing
that the packer (and the kernel's initramfs unpacker) reads, when the phone's
own recovery ramdisk is gzip, as TWRP builds it.

venus has no recovery partition of its own; its base is the whole boot_a, and
the packer only reads an LZ4-legacy ramdisk.
"""
import struct
import subprocess
import sys

path = sys.argv[1]
data = bytearray(open(path, "rb").read())
if data[:8] != b"ANDROID!":
    sys.exit(f"{path} is not an Android boot image")
kernel_size, ramdisk_size = struct.unpack("<II", data[8:16])
header_version = struct.unpack("<I", data[40:44])[0]
if header_version < 3:
    sys.exit(f"{path} has header version {header_version}, which predates the layout read here")
# The header fills the first 4096 bytes; the kernel follows it, and the
# ramdisk the kernel, at the next 4096 boundary.
off = ((4096 + kernel_size + 4095) // 4096) * 4096
ramdisk = bytes(data[off:off + ramdisk_size])
if ramdisk[:4] == b"\x02\x21\x4c\x18":
    print("the stock ramdisk is already LZ4 legacy")
    sys.exit(0)
if ramdisk[:2] != b"\x1f\x8b":
    sys.exit("the stock ramdisk is neither gzip nor LZ4 legacy")
raw = subprocess.run(["gzip", "-dc"], input=ramdisk, capture_output=True, check=True).stdout
packed = subprocess.run(["lz4", "-l", "-9", "-c"], input=raw, capture_output=True, check=True).stdout
if len(packed) > ramdisk_size:
    sys.exit(f"the LZ4 ramdisk is {len(packed)} bytes, more than the {ramdisk_size} it has")
footer = bytes(data[-64:])
if footer[:4] != b"AVBf":
    sys.exit(f"{path} does not end in an AVB footer")
out = bytearray(data)
out[12:16] = struct.pack("<I", len(packed))
out[off:off + ramdisk_size] = packed + b"\x00" * (ramdisk_size - len(packed))
out[-64:] = footer
open(path, "wb").write(out)
print(f"the stock ramdisk: {ramdisk_size} bytes of gzip, {len(packed)} bytes of LZ4")
