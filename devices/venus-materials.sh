#!/system/bin/sh
# What Skyward needs from a phone whose data partition really is encrypted.
#
# Run it *inside the working system* (not in recovery), as root, on the phone
# that can unlock itself normally. It reads and never writes: no key file is
# printed, only its name and size. The one thing it asks of you is that the
# phone is unlocked and running, so that the successful path is in the logs.
#
#   su -c 'sh /sdcard/skyward-materials.sh'
#
# Everything lands in /sdcard/skyward-materials/ as a handful of text files.
OUT=/sdcard/skyward-materials
mkdir -p "$OUT" 2>/dev/null || OUT=/data/local/tmp/skyward-materials
mkdir -p "$OUT"

say() { echo "$*"; }

# 1. What the phone says about itself. The property service is the one thing a
#    key service reads its patch level from, so the whole list is kept.
getprop | sort > "$OUT/1-props.txt" 2>&1
{
  for k in ro.build.version.release ro.build.version.security_patch \
           ro.vendor.build.security_patch ro.product.vendor.device \
           ro.vndk.version ro.crypto.state ro.crypto.type ro.hardware \
           ro.boot.hardware ro.boot.verifiedbootstate ro.boot.flash.locked; do
    printf '%s = %s\n' "$k" "$(getprop $k)"
  done
} > "$OUT/1-crypto-props.txt" 2>&1

# 2. The phone's own table of where /data and /metadata live, and how they are
#    encrypted. This is the line Skyward has to agree with.
{
  for f in /vendor/etc/fstab.qcom /odm/etc/fstab.qcom \
           /first_stage_ramdisk/fstab.qcom /first_stage_ramdisk/fstab.emmc \
           /vendor/etc/fstab.emmc /system/etc/fstab.qcom; do
    if [ -f "$f" ]; then
      echo "== $f"
      grep -nE 'userdata|metadata|keydirectory|fileencryption|metadata_encryption|inlinecrypt|wrappedkey' "$f"
    fi
  done
  echo '== device tree'
  ls -l /dev/block/by-name/userdata /dev/block/by-name/metadata 2>&1
  cat /proc/cmdline
} > "$OUT/2-fstab.txt" 2>&1

# 3. What the running system did, which is the path that works.
{
  grep -E ' /data | /metadata ' /proc/mounts
  echo '== dm'
  for d in /sys/block/dm-*; do
    [ -e "$d/dm/name" ] || continue
    echo "-- $d $(cat $d/dm/name) uuid=$(cat $d/dm/uuid 2>/dev/null)"
    cat "$d/size"
  done
  echo '== plaintext names survive, ciphertext does not'
  ls /data/media/0 2>&1 | head -5
  ls /data/misc/vold 2>&1 | head -5
} > "$OUT/3-mounts.txt" 2>&1

# 4. Names and sizes only. Never the bytes: the keys belong to the phone.
{
  for d in /metadata/vold/metadata_encryption \
           /data/unencrypted/key \
           /data/misc/vold/user_keys/de/0/current \
           /data/misc/vold/user_keys/ce/0/current \
           /data/system_de/0/spblob; do
    echo "== $d"
    ls -l "$d" 2>&1
  done
  echo '== what the screen lock leaves behind, sizes only'
  ls -l /data/system/gatekeeper.*.key /data/system/locksettings.db 2>&1
} > "$OUT/4-keys.txt" 2>&1

# 5. Which key services this phone really runs, and at which version. Skyward
#    discovers these the same way; this is the answer to compare it against.
{
  which lshal >/dev/null 2>&1 && lshal 2>&1 | grep -iE 'keymaster|keymint|gatekeeper|weaver|boot@' 
  service list 2>&1 | grep -iE 'keymaster|keymint|gatekeeper|weaver' 
  echo '== manifest'
  grep -nE 'keymaster|keymint|gatekeeper|weaver|name=|version=' /vendor/etc/vintf/manifest.xml /odm/etc/vintf/manifest.xml 2>/dev/null | head -80
  echo '== rc files that start them'
  ls /vendor/etc/init 2>&1 | grep -iE 'keymaster|keymint|gatekeeper|weaver|qseecom|qti'
} > "$OUT/5-services.txt" 2>&1

# 6. Whether this kernel speaks hardware-wrapped keys, and whether the crypto
#    engine is inline. This decides which way Skyward unwraps the key.
{
  zcat /proc/config.gz 2>/dev/null | grep -iE 'BLK_INLINE_ENCRYPTION|BLK_DEV_DM|DM_DEFAULT_KEY|FSCRYPT|FS_ENCRYPTION|QCOM_ICE|ICE' 
  echo '== keyslots'
  ls /sys/class/blk_crypto* /sys/kernel/debug/blk_crypto 2>&1
  echo '== dmesg'
  dmesg 2>/dev/null | grep -iE 'blk_crypto|inline_encryption|ice|dm-default-key|fscrypt|hw wrapped' | tail -40
} > "$OUT/6-kernel-crypto.txt" 2>&1

# 7. The system's own successful unlock, for Skyward to imitate.
{
  logcat -d -b all 2>/dev/null | grep -iE 'vold|fscrypt|LockSettings|keymaster|gatekeeper|keystore2' | tail -400
} > "$OUT/7-logs.txt" 2>&1

say "wrote these to $OUT:"
ls -l "$OUT"
say
say "== the three things Skyward needs most =="
say "  2-fstab.txt      the userdata and metadata lines, as the phone writes them"
say "  4-keys.txt       the file names under /metadata/vold and the user_keys"
say "  6-kernel-crypto.txt  whether this kernel has blk-crypto / hardware wrapped keys"
