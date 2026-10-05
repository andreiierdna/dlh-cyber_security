# Task 22 — Cryptographic Implementation Playbook

## Deployment rules

Use approved change tickets, preserve the last known-good configuration, and stop when a validation gate fails. Never delete the previous certificate, key, backup set, or configuration until the new path has passed recovery testing.

## Action #1 — Renew and harden patient-portal TLS

- **Priority:** Immediate — CRYPTO-002
- **System Affected:** `web-srv-01`
- **Prerequisites:** Valid replacement certificate; approved CA/ACME account; Apache linked to OpenSSL 1.1.1+; exported Apache configuration; portal owner available.

### Steps
1. Run `sudo apachectl -S` to identify the active portal vhost; copy that vhost and the current certificate/key to the protected rollback location.
2. Install the renewed certificate and vault-delivered private key (`root:root`, mode `0400`). Configure automated renewal and an Apache reload hook; run the ACME client's dry-run renewal.
3. In the active vhost, set:
   ```apache
   SSLProtocol -all +TLSv1.2 +TLSv1.3
   SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
   SSLCipherSuite SSL ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256
   SSLCompression Off
   SSLSessionTickets Off
   Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
   ```
4. Run `sudo apachectl configtest`; only if it returns `Syntax OK`, run `sudo systemctl reload apache2`.

### Validation
- `openssl s_client -connect portal.meddefense.local:443 -tls1` must fail; `-tls1_2` and `-tls1_3` must succeed with an approved AEAD cipher and the renewed certificate chain.
- `curl -fsSI https://portal.meddefense.local/` must return the HSTS header. Complete login, patient-record view, and synthetic health checks; confirm no increase in Apache errors.

### Rollback
- Restore the saved vhost and previous still-valid certificate/key, run `apachectl configtest`, then reload Apache. Keep the renewed material for diagnosis.
- Roll back after **5 minutes** of failed TLS handshakes, failed portal health checks, or material patient access errors.

- **Maintenance Window:** Overnight; TLS reload should be graceful.
- **Communication:** Before: Sarah Park, portal/application owner, Helpdesk, Clinical Operations. After: Security and owners receive protocol, certificate, HSTS, and health-check evidence.

## Action #2 — Require TLS for PostgreSQL EHR connections

- **Priority:** Immediate — CRYPTO-002
- **System Affected:** `ehr-db-01` and client `ehr-srv-01`
- **Prerequisites:** CA-issued server certificate matching `ehr-db-01`; protected private key; EHR client trust store; confirmed application source IP; current `postgresql.conf` and `pg_hba.conf` copies; successful database backup.

### Steps
1. Install the server certificate/key with PostgreSQL ownership and mode `0600`. Set `ssl = on`, the certificate/key paths, and `ssl_min_protocol_version = 'TLSv1.2'` in `postgresql.conf`.
2. Configure the EHR connection on `ehr-srv-01` with `sslmode=verify-full` and the approved CA certificate. Test a representative query before enforcement.
3. In `pg_hba.conf`, add a narrow `hostssl` rule for the EHR database/user from the single approved `ehr-srv-01/32` address using `scram-sha-256`; remove the corresponding `hostnossl` and broad `10.10.0.0/16` rules.
4. Run `sudo -u postgres psql -c "SELECT pg_reload_conf();"`. Restart PostgreSQL only if the installed build reports that a changed TLS setting requires it.

### Validation
- From `ehr-srv-01`, connect with `sslmode=verify-full`; query `pg_stat_ssl` and confirm `ssl=true`, TLS 1.2+, and an approved cipher. `sslmode=disable` must be rejected.
- Execute synthetic patient lookup/write/reporting checks and monitor connection failures, latency, and PostgreSQL logs for one clinical cycle.

### Rollback
- Restore the saved PostgreSQL files, reload configuration, and restore the previous EHR connection string. Retain the certificate for troubleshooting.
- Roll back after **5 minutes** of EHR database unavailability or failed clinical transaction checks. If one legacy client fails, isolate it under an approved narrow exception rather than reopening the whole `/16` network.

- **Maintenance Window:** Overnight with Clinical Operations approval.
- **Communication:** Before: Sarah Park, DBA, EHR owner, Clinical Operations, Helpdesk. After: provide encrypted-session, plaintext-rejection, and workflow results.

## Action #3 — Remove weak AD cryptography and require signed LDAP

- **Priority:** Immediate — CRYPTO-010 and CRYPTO-011
- **System Affected:** `ad-dc-01`, `ad-dc-02`
- **Prerequisites:** System-state backup for both DCs; healthy replication; inventory of service/device accounts; LDAP unsigned-bind audit; tested administrative access; approved temporary exception process.

### Steps
1. On both DCs, enable LDAP Interface Events auditing and review Event ID 2889. Reconfigure every identified client for signed LDAP or LDAPS before enforcement.
2. In a staged Domain Controllers GPO, set **Network security: Configure encryption types allowed for Kerberos** to AES128 and AES256 only; remove DES and RC4 after validating service-account and clinical-device compatibility.
3. In the same staged GPO, set **Domain controller: LDAP server signing requirements** to **Require signing**. Apply first to `ad-dc-02`, run `gpupdate /force`, validate, then apply to `ad-dc-01`.
4. Reset/rotate service-account passwords so new AES keys are generated; purge test-client tickets with `klist purge` and obtain fresh tickets.

### Validation
- Unsigned LDAP binds must fail; signed LDAP/LDAPS authentication must succeed for EHR, PACS, billing, VPN, O365 synchronization, and administrator workflows.
- Inspect Kerberos tickets/events and confirm no DES/RC4 tickets. Confirm DC replication, DNS, user login, Group Policy, and privileged administration on both DCs.

### Rollback
- Unlink the staged GPO or restore its prior settings, run `gpupdate /force`, and re-test authentication. Use a source-scoped, time-limited LDAP exception if one critical dependency remains; do not globally retain weak settings without an approved risk exception.
- Roll back after **10 minutes** of widespread authentication failure or any blocked critical clinical workflow.

- **Maintenance Window:** Overnight; stage `ad-dc-02` at least one validation cycle before `ad-dc-01`.
- **Communication:** Before: Sarah Park, Security, all application owners, Biomedical Engineering, Helpdesk. After: publish affected-client results, remaining exceptions, and DES/RC4/unsigned-bind evidence.

## Action #4 — Encrypt backup sets before NAS upload

- **Priority:** Immediate — CRYPTO-013 and CRYPTO-014
- **System Affected:** `backup-srv-01`, `NAS-01`, immutable offsite target
- **Prerequisites:** Backup product/version and AES-256 encryption support verified; independent `meddefense-backup-recovery` KMS/vault project; recovery operators enrolled with MFA; protected job/config export; capacity for parallel pilot and current unencrypted set.

### Steps
1. Create `backup-kek` in the HSM-backed recovery KMS. Grant unwrap only to the backup service and approved recovery role; grant Sarah administration but not routine decrypt use.
2. Clone—not overwrite—the current backup job. Enable **AES-256 authenticated backup-set encryption before upload**, with a new DEK per set wrapped by `backup-kek`; enable TLS 1.2+ for NAS/offsite transfer.
3. Run the cloned job against one non-critical workload, then inspect NAS-01 to confirm stored content is ciphertext. Replicate the encrypted set to the immutable offsite target.
4. Restore the pilot into the isolated recovery network using escrowed credentials, compare application/file integrity, and record duration. Promote the encrypted job only after restore success; retain old key versions for every retained set.

### Validation
- NAS-only credentials cannot read backup contents or unwrap DEKs; KMS logs show only the backup identity and approved recovery operator.
- Complete an isolated restore without production credentials, verify integrity and measured RTO/RPO, then confirm the next scheduled production job succeeds without service impact.

### Rollback
- Re-enable the exported prior job configuration for the next run; preserve both encrypted and last known-good sets. Never delete encrypted sets or KMS versions during rollback.
- Roll back if encryption causes the backup window to overrun by **30 minutes**, the job fails, or the isolated restore fails. No nightly backup may be skipped.

- **Maintenance Window:** Pilot during business hours on synthetic/non-critical data; production cutover overnight before the normal backup window.
- **Communication:** Before: Sarah Park, backup administrator, Security, application owners. After: report job status, ciphertext inspection, KMS audit, offsite replication, and restore proof.

## Action #5 — Require TLS for billing MySQL

- **Priority:** Immediate — CRYPTO-005
- **System Affected:** `billing-srv-01`
- **Prerequisites:** Record `SELECT VERSION();` and verify supported TLS settings; CA-issued server/client certificates; billing application trust store; known client source; current MySQL configuration and database backup.

### Steps
1. Install the MySQL server certificate, private key, and CA chain under the MySQL service account with mode `0600`; configure the installed version's `ssl_ca`, `ssl_cert`, and `ssl_key` settings.
2. Configure the billing application for certificate verification and a client certificate. Test one connection and transaction with TLS before enforcement.
3. Set `require_secure_transport=ON`; set the supported minimum to TLS 1.2 and enable TLS 1.3 only if the installed MySQL/OpenSSL versions support it. Restrict the billing account to its approved source and `REQUIRE X509` after the client test.
4. Validate the configuration using the installed version's check command, then restart MySQL during the window; immediately run the application smoke transaction.

### Validation
- In an application session, `SHOW SESSION STATUS LIKE 'Ssl_version';` and `SHOW SESSION STATUS LIKE 'Ssl_cipher';` must report TLS 1.2+ and an approved AEAD cipher. A connection with `--ssl-mode=DISABLED` must fail.
- Complete synthetic customer lookup, claim creation, report, and application health checks; monitor MySQL errors and transaction latency.

### Rollback
- Restore the saved MySQL configuration and prior account TLS requirement, restart MySQL, and restore the prior application connection configuration. Keep issued certificates protected for diagnosis.
- Roll back after **5 minutes** of billing unavailability, failed transaction checks, or sustained connection errors.

- **Maintenance Window:** Overnight, outside claim-processing hours.
- **Communication:** Before: Sarah Park, billing owner, DBA, Finance, Helpdesk, Security. After: provide TLS-session, plaintext-rejection, application, and error-monitoring results.
