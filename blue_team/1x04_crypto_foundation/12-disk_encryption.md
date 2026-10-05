# Task 12 — The Disk Encryption Lab

## Evidence and Safety

**Executed on Kali:** cryptsetup 2.8.6, mke2fs 1.47.4, and OpenSSL 3.6.2. The user launched an isolated runner with sudo; only synthetic data and new image files were used. Outputs below are captured results, with terminal progress characters removed. Manual verification and all three manager modes passed.

Commands were run as root, so the equivalent `sudo` prefix is shown below. For readability, `$LAB` denotes the captured directory `/var/tmp/meddefense-luks-lab.z175a46g`; the runner used its absolute paths. Modern cryptsetup handles image files through a loop device automatically ([manual](https://man7.org/linux/man-pages/man8/cryptsetup.8.html)). Never substitute a physical disk or reuse an existing image.

## Part 1 — LUKS Setup

### 1. Create the virtual disk

```bash
dd if=/dev/zero of=encrypted_volume.img bs=1M count=500
```

Captured output:

```text
500+0 records in
500+0 records out
524288000 bytes (524 MB, 500 MiB) copied, 0.168088 s, 3.1 GB/s
```

This is **500 MiB**, not 500 decimal MB. This allocation timing is not encryption throughput or NAS performance.

### 2. Format and unlock

```bash
sudo cryptsetup luksFormat encrypted_volume.img
```

Captured prompts, split onto separate lines for readability:

```text
WARNING!
========
This will overwrite data on encrypted_volume.img irrevocably.

Are you sure? (Type 'yes' in capital letters):
Enter passphrase for encrypted_volume.img:
Verify passphrase:
```

The runner supplied `YES` and a throwaway lab passphrase without echoing input. Exit status: **0**.

```bash
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
```

Captured output: `Enter passphrase for encrypted_volume.img:`. Exit status: **0**; `/dev/mapper/secure_vol` was created.

### 3. Create the filesystem, mount, and write

```bash
sudo mkfs.ext4 /dev/mapper/secure_vol
```

Captured output:

```text
mke2fs 1.47.4 (6-Mar-2025)
Creating filesystem with 123904 4k blocks and 123904 inodes
Filesystem UUID: 19f1e75f-a77c-4a37-ab3a-ff76ef92d943
Superblock backups stored on blocks:
        32768, 98304

Allocating group tables: done
Writing inode tables: done
Creating journal (4096 blocks): done
Writing superblocks and filesystem accounting information: done
```

Exit status: **0**. LUKS metadata occupies part of the image, so filesystem capacity is smaller than 500 MiB.

| Command | Captured Output — All Exit 0 |
|---|---|
| `sudo mkdir -p /mount` | No output. |
| `sudo mount /dev/mapper/secure_vol /mount` | No output. |
| `printf 'MedDefense lab record: synthetic patient MD-LUKS-TEST-001\n' \| sudo tee /mount/patient.txt` | `MedDefense lab record: synthetic patient MD-LUKS-TEST-001` |
| `sudo umount /mount` | No output. |
| `sudo cryptsetup luksClose secure_vol` | No output; removes the mapping and clears its key from kernel memory ([close manual](https://man7.org/linux/man-pages/man8/cryptsetup-close.8.html)). |

Use only synthetic data. Unmount **before** closing; if unmount reports “target is busy,” leave the volume open, stop the processes using it, and retry—do not force it.

## Part 2 — Verification

With the mapping closed:

```bash
strings encrypted_volume.img | head -50
```

Captured output: **50 lines**, including plaintext LUKS metadata and incidental printable ciphertext sequences. Short excerpt:

```text
LUKS
sha256
hn7a868ff3-eaf6-4dd9-95ad-faf4f787922b
```

The patient marker was not visible. Header metadata is not patient data; printable sequences alone do not mean decryption succeeded ([strings manual](https://man7.org/linux/man-pages/man1/strings.1.html)).

The first 50 lines are only a sample. Check the whole image for the known marker:

```bash
strings -a encrypted_volume.img | grep -F 'MD-LUKS-TEST-001'
```

Captured output: **none**, exit status **1** (no match). This supports confidentiality at rest for the known marker; it is not mathematical proof of encryption strength or protection against live-server access.

Reopen and check persistence:

| Command | Captured Output — All Exit 0 |
|---|---|
| `sudo cryptsetup luksOpen encrypted_volume.img secure_vol` | `Enter passphrase for encrypted_volume.img:` |
| `sudo mount /dev/mapper/secure_vol /mount` | No output. |
| `sudo cat /mount/patient.txt` | `MedDefense lab record: synthetic patient MD-LUKS-TEST-001` |
| `sudo umount /mount` | No output. |
| `sudo cryptsetup luksClose secure_vol` | No output. |

**Result:** Readback matched the original data, and the runner confirmed the same SHA-256 digest before and after reopening. While mounted, authorized users and root can read plaintext; normal LUKS disk encryption provides confidentiality, not authenticated tamper protection.

## Part 3 — Automation

[12-luks_manager.sh](12-luks_manager.sh) uses one lab mapping, `secure_vol`:

```bash
sudo ./12-luks_manager.sh create encrypted_volume.img 500
sudo ./12-luks_manager.sh open encrypted_volume.img /mnt/secure_vol
sudo ./12-luks_manager.sh close /mnt/secure_vol
```

- **create:** Uses GNU `dd` with `conv=excl` to refuse existing images, formats LUKS2, opens it, creates ext4, and closes it; cryptsetup prompts for passphrases.
- **open:** Refuses an occupied mapping or nonempty mount directory, then opens and mounts the image.
- **close:** Checks that the mount belongs to `secure_vol`, unmounts, then closes; never forces an unmount.

No passphrase is embedded or logged. Failed creation may leave an incomplete image for inspection; the script will not overwrite it on retry.

**Captured manager results:** A separate 500 MiB `managed_volume.img` was used; the mount directory was `/mnt/manager_mount`.

| Operation | Captured Result |
|---|---|
| `create managed_volume.img 500` | `[INFO] Created and closed: managed_volume.img` — exit 0. |
| `open managed_volume.img <mount_directory>` | `[INFO] Mounted secure_vol at /mnt/manager_mount` — exit 0. |
| `close <mount_directory>` | `[INFO] Unmounted and closed secure_vol.` — exit 0. |
| Reopen and read `patient.txt` | `MedDefense lab record: synthetic patient MD-LUKS-TEST-001` — exit 0; data preserved. |
| Create over the existing image | `[ERROR] Refusing to overwrite: managed_volume.img` — exit 1; image unchanged. |
| Open onto a nonempty directory | `[ERROR] Mount directory must be empty.` — exit 1; mapping stayed closed. |
| `close /` while the lab volume was mounted elsewhere | `[ERROR] Refusing to unmount an unrelated filesystem.` — exit 1; lab mapping remained usable. |

## Part 4 — NAS-01 Backup Encryption Design

The [audit](meddefense-crypto-audit-notes.txt) confirms plaintext backups and warns against storing the only key on NAS-01. [Finding 015](../1x02_the_weak_links/21-vulnerability_assessment.md) and [RISK-007](../1x03_defense_blueprint/10-risk_register.md#risk-007) identify reachable management and correlated recovery loss.

| Decision | MedDefense Recommendation |
|---|---|
| **Encryption level** | **File/backup-set encryption before upload**, consistent with [Task 13](13-encryption_levels.md). A stolen NAS or NAS-only account receives ciphertext. full-disk / volume encryption protects locked media but an unlocked NAS serves readable files; shared-folder encryption is optional defense in depth. The file-level encryption is not recommended because of High overhead, complex key management. |
| **Performance** | Encrypt on the backup server using a supported backup-product feature. T1 measured **1,064 MiB/s CBC** and **1,316 MiB/s GCM** on Kali; the conditional overhead estimate is below. Compress/deduplicate before encryption where supported, and validate both backup and restore windows. |
| **Key location** | Use a separately administered vault/KMS, restricted to the backup service and authorized recovery staff; keep protected offline/offsite escrow outside the production identity failure domain. Never keep the sole recovery key on NAS-01: theft or ransomware could expose or destroy it with the backups. |
| **Key loss** | Losing all usable keys makes local and cloud backups unrecoverable. Retain key versions for the full backup retention period and test escrow-based restoration. LUKS additionally needs a usable header; a header backup alone cannot decrypt data. |
| **Offsite replication** | Replicate already-encrypted backup sets over TLS to the immutable offsite destination in the [1x03 strategy](../1x03_defense_blueprint/17-security_strategy.md). Use **MedDefense-controlled backup keys**; the cloud provider need not receive them. Provider-managed storage encryption is an additional layer. Separate cloud administration and key recovery from production/NAS credentials. |

**T1 measurements:** The existing [Task 1 script](1-symmetric_encrypt.sh) encrypted a synthetic **100 MiB** file:

| Command | Captured Timing | Effective Throughput |
|---|---|---|
| `./1-symmetric_encrypt.sh t1_input.bin t1_cbc.enc cbc` | `Elapsed time: 94 ms` — exit 0 | `100 / 0.094 = 1,064 MiB/s` |
| `./1-symmetric_encrypt.sh t1_input.bin t1_gcm.enc gcm` | `Elapsed time: 76 ms` — exit 0 | `100 / 0.076 = 1,316 MiB/s` |

**[INFERENCE] Planning estimate:** For an assumed unencrypted backup rate of **100 MiB/s**, serial encryption adds `100 × baseline_rate / encryption_rate` percent to elapsed time: approximately **9.4% CBC** or **7.6% GCM**. The baseline is an assumption, not a NAS measurement. These single-run T1 timings include process startup and buffered file I/O but **exclude PBKDF2**, which occurs before the timer. Streaming may overlap encryption with I/O; CPU contention and durable writes may increase costs. Benchmark the real backup/restore path before setting service targets.

**Operational boundary:** Encryption reduces disclosure, not deletion or ransomware damage. Preserve segmentation, separate backup identities, immutable copies, and isolated restore tests. The strategy procures backup controls in Phase 1 and enables immutable/offsite replication in Phase 2; it does not establish completed Phase 1 encryption. Sarah Park owns the backup implementation and recovery evidence.
