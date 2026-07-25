# GCP security scripts

Incident-response and hardening tooling for GCP projects, written after an
`AbuseEvent` was raised against `adeqo-tools`.

Google writes an `AbuseEvent` log entry when it detects abuse originating from
your project — cryptomining, leaked credentials, malware, phishing, or outbound
port scanning. The event's `detectionCategory` tells you what was found and
`resourceName` tells you where, which together determine how far the response
needs to go.

## Running them

Use [Cloud Shell](https://shell.cloud.google.com/), which has `gcloud` and `jq`
already installed and is authenticated as your console identity:

```bash
git clone <this repo> && cd scripts/gcp-security
chmod +x *.sh
./gcp-audit.sh --project adeqo-tools
```

Running locally works too, given `gcloud auth login` and `jq`.

## Order of use

**1. Audit.** Read-only, changes nothing, safe during an active incident.

```bash
./gcp-audit.sh --project adeqo-tools
```

Pulls the abuse events themselves, the IAM policy, service accounts and their
exported keys, which identity each VM runs as, internet-facing firewall rules,
public buckets, privileged admin activity, and the Policy Intelligence
recommendations behind the "excess permissions" figures in the console. Writes
raw JSON plus a `findings.txt` to a timestamped directory.

**2. Contain**, if the audit names a compromised VM. Snapshots disks before
cutting network access, so evidence survives.

```bash
./gcp-contain.sh --project adeqo-tools --instance VM --zone ZONE          # dry run
./gcp-contain.sh --project adeqo-tools --instance VM --zone ZONE --apply
```

**3. Harden.** Dry-run by default; every fix is opt-in through its own flag.

```bash
./gcp-harden.sh --project adeqo-tools                     # show everything it would do
./gcp-harden.sh --project adeqo-tools --fix-default-sa    # still a dry run
./gcp-harden.sh --project adeqo-tools --fix-default-sa --apply
```

| Flag | What it does |
| --- | --- |
| `--fix-default-sa` | Removes Editor/Owner from default service accounts |
| `--delete-sa-keys` | Deletes user-managed (downloadable) SA keys |
| `--downgrade-humans` | Swaps project Editor/Owner for Viewer on listed members |
| `--fix-firewall` | Disables ingress rules exposing SSH/RDP to `0.0.0.0/0` |
| `--enable-oslogin` | Turns on OS Login project-wide |
| `--org-policies` | Enforces preventative org policies (needs Org Admin) |

Work through the flags one at a time and re-run the audit between steps rather
than using `--all` on a live project.

## Safety

- Nothing mutates without `--apply`.
- `gcp-harden.sh` writes the IAM policy to a timestamped backup before its first
  change. Restore with `gcloud projects set-iam-policy PROJECT backup.json`.
- Both mutating scripts require you to type the project or instance name to
  confirm.
- Firewall rules are disabled, not deleted (`--no-disabled` re-enables them).
- `--downgrade-humans` is a no-op until you populate `DOWNGRADE_MEMBERS` at the
  top of `gcp-harden.sh`, so no one loses access by accident.

## Things to check by hand

Removing Editor from the default compute service account will break anything
that silently relies on it — GKE node pools, Cloud Build, Cloud Run, Cloud
Functions and Dataflow all default to that identity. Inventory first:

```bash
gcloud compute instances list --project=adeqo-tools \
  --format='table(name,serviceAccounts[0].email)'
```

The audit reads the *project* IAM policy. It will not show a principal granted
access only at the resource level (a single bucket, a Pub/Sub topic, an
impersonation binding on another service account), or roles inherited from the
organization. Check organization-level grants separately:

```bash
gcloud projects get-ancestors adeqo-tools
gcloud organizations get-iam-policy ORG_ID \
  --flatten='bindings[].members' --format='table(bindings.role,bindings.members)'
```

## Output

Report directories (`gcp-audit-*`), IAM backups and instance dumps are
gitignored. They contain a full inventory of your project and should not be
committed.
