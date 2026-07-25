#!/usr/bin/env bash
#
# gcp-contain.sh - Isolate a suspected-compromised VM without destroying evidence.
#
# Order matters here: snapshot the disks first, then cut network access, then
# stop the instance. Stopping a VM before snapshotting loses whatever was only
# in memory, and deleting it loses the evidence entirely.
#
# DRY RUN BY DEFAULT. Add --apply to execute.
#
# Usage:
#   ./gcp-contain.sh --project adeqo-tools --instance vm-name --zone us-central1-a
#   ./gcp-contain.sh --project adeqo-tools --instance vm-name --zone us-central1-a --apply
#
# Steps (all on by default, disable individually):
#   --no-snapshot   skip the forensic disk snapshot
#   --no-isolate    skip removing the external IP and applying a deny-all rule
#   --no-stop       leave the instance running (isolated but live)

set -euo pipefail

PROJECT="${CLOUDSDK_CORE_PROJECT:-}"
INSTANCE=""
ZONE=""
APPLY=false
DO_SNAPSHOT=true
DO_ISOLATE=true
DO_STOP=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project)     PROJECT="$2"; shift 2 ;;
    --instance)    INSTANCE="$2"; shift 2 ;;
    --zone)        ZONE="$2"; shift 2 ;;
    --apply)       APPLY=true; shift ;;
    --no-snapshot) DO_SNAPSHOT=false; shift ;;
    --no-isolate)  DO_ISOLATE=false; shift ;;
    --no-stop)     DO_STOP=false; shift ;;
    -h|--help)     sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)             echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v gcloud >/dev/null || { echo "gcloud not found" >&2; exit 1; }
[[ -n "$PROJECT" ]] || PROJECT="$(gcloud config get-value project 2>/dev/null)"

if [[ -z "$INSTANCE" || -z "$ZONE" || -z "$PROJECT" ]]; then
  echo "Need --project, --instance and --zone." >&2
  echo "List candidates with: gcloud compute instances list --project=PROJECT" >&2
  exit 2
fi

BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; DIM=$'\033[2m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
[[ -t 1 ]] || { BOLD=""; RED=""; GREEN=""; DIM=""; YELLOW=""; RESET=""; }

STAMP="$(date -u +%Y%m%d-%H%M%S)"

run() {
  local desc="$1"; shift
  printf '  %s%s%s\n' "$BOLD" "$desc" "$RESET"
  printf '    %s$ %s%s\n' "$DIM" "$*" "$RESET"
  if [[ "$APPLY" == true ]]; then
    if "$@"; then
      printf '    %s-> done%s\n' "$GREEN" "$RESET"
    else
      printf '    %s-> FAILED%s\n' "$RED" "$RESET"
      return 1
    fi
  fi
  return 0
}

printf '%sContainment: %s (zone %s, project %s)%s\n' "$BOLD" "$INSTANCE" "$ZONE" "$PROJECT" "$RESET"
if [[ "$APPLY" == true ]]; then
  printf 'mode: %sAPPLY%s\n' "$RED" "$RESET"
else
  printf 'mode: %sDRY RUN (add --apply to execute)%s\n' "$GREEN" "$RESET"
fi

# Record what the instance looked like before we touch it.
DESC_FILE="instance-${INSTANCE}-${STAMP}.json"
if [[ "$APPLY" == true ]]; then
  gcloud compute instances describe "$INSTANCE" --zone="$ZONE" \
    --project="$PROJECT" --format=json > "$DESC_FILE"
  printf 'pre-change state saved to %s\n' "$DESC_FILE"
fi

RUNS_AS="$(gcloud compute instances describe "$INSTANCE" --zone="$ZONE" \
             --project="$PROJECT" --format='value(serviceAccounts[0].email)' 2>/dev/null || true)"
if [[ -n "$RUNS_AS" ]]; then
  printf '\n  %sThis VM runs as: %s%s\n' "$YELLOW" "$RUNS_AS" "$RESET"
  printf '  Treat every permission that identity holds as compromised.\n'
  printf '  Check with: gcloud projects get-iam-policy %s --flatten="bindings[].members" \\\n' "$PROJECT"
  printf '                --filter="bindings.members:%s"\n' "$RUNS_AS"
fi

if [[ "$APPLY" == true ]]; then
  printf '\n%sContain %s? Type the instance name to continue: %s' "$YELLOW" "$INSTANCE" "$RESET"
  read -r CONFIRM
  [[ "$CONFIRM" == "$INSTANCE" ]] || { echo "Aborted."; exit 1; }
fi

# --- 1. Snapshot before anything else -------------------------------------
if [[ "$DO_SNAPSHOT" == true ]]; then
  printf '\n%s1. Forensic snapshots%s\n' "$BOLD" "$RESET"
  DISKS="$(gcloud compute instances describe "$INSTANCE" --zone="$ZONE" \
             --project="$PROJECT" \
             --format='value(disks[].source)' 2>/dev/null | tr ';' '\n' || true)"
  if [[ -z "$DISKS" ]]; then
    # Every VM has at least a boot disk, so an empty list means the describe
    # failed. Continuing would isolate and stop the instance with no evidence
    # preserved, so stop here instead.
    printf '  %sCould not enumerate disks for %s.%s\n' "$RED" "$INSTANCE" "$RESET"
    printf '  Refusing to continue: containment without a snapshot destroys evidence.\n'
    printf '  Verify access, or pass --no-snapshot to proceed deliberately.\n'
    exit 1
  else
    while read -r disk; do
      [[ -z "$disk" ]] && continue
      DISK_NAME="$(basename "$disk")"
      run "snapshot $DISK_NAME" \
        gcloud compute disks snapshot "$DISK_NAME" \
          --zone="$ZONE" --project="$PROJECT" \
          --snapshot-names="forensic-${DISK_NAME}-${STAMP}" --quiet || true
    done <<< "$DISKS"
  fi
fi

# --- 2. Cut network access -------------------------------------------------
if [[ "$DO_ISOLATE" == true ]]; then
  printf '\n%s2. Network isolation%s\n' "$BOLD" "$RESET"
  printf '  Removing egress stops mining, exfiltration and outbound attacks\n'
  printf '  immediately, even while the VM is still running.\n'

  NIC="$(gcloud compute instances describe "$INSTANCE" --zone="$ZONE" \
           --project="$PROJECT" --format='value(networkInterfaces[0].name)' 2>/dev/null || echo nic0)"
  ACCESS_CONFIG="$(gcloud compute instances describe "$INSTANCE" --zone="$ZONE" \
                     --project="$PROJECT" \
                     --format='value(networkInterfaces[0].accessConfigs[0].name)' 2>/dev/null || true)"

  if [[ -n "$ACCESS_CONFIG" ]]; then
    run "remove the external IP" \
      gcloud compute instances delete-access-config "$INSTANCE" \
        --zone="$ZONE" --project="$PROJECT" \
        --access-config-name="$ACCESS_CONFIG" \
        --network-interface="$NIC" --quiet || true
  else
    printf '  (no external IP to remove)\n'
  fi

  QUARANTINE_TAG="quarantine-${INSTANCE}"
  run "tag the instance for quarantine" \
    gcloud compute instances add-tags "$INSTANCE" \
      --zone="$ZONE" --project="$PROJECT" \
      --tags="$QUARANTINE_TAG" --quiet || true

  NETWORK_URL="$(gcloud compute instances describe "$INSTANCE" --zone="$ZONE" \
                   --project="$PROJECT" \
                   --format='value(networkInterfaces[0].network)' 2>/dev/null || true)"
  NETWORK="${NETWORK_URL##*/}"
  if [[ -z "$NETWORK" ]]; then
    # Guessing "default" here would attach the deny rules to a network the VM
    # is not on. They would apply to nothing while appearing to succeed, which
    # is worse than failing.
    printf '  %sCould not determine the instance network.%s\n' "$RED" "$RESET"
    printf '  Not creating deny rules against a guessed network. Resolve access and retry.\n'
    exit 1
  fi
  printf '  network: %s\n' "$NETWORK"

  run "deny all egress from the quarantined instance" \
    gcloud compute firewall-rules create "deny-egress-${QUARANTINE_TAG}" \
      --project="$PROJECT" --network="$NETWORK" \
      --direction=EGRESS --action=deny --rules=all \
      --destination-ranges=0.0.0.0/0 --priority=100 \
      --target-tags="$QUARANTINE_TAG" --quiet || true

  run "deny all ingress to the quarantined instance" \
    gcloud compute firewall-rules create "deny-ingress-${QUARANTINE_TAG}" \
      --project="$PROJECT" --network="$NETWORK" \
      --direction=INGRESS --action=deny --rules=all \
      --source-ranges=0.0.0.0/0 --priority=100 \
      --target-tags="$QUARANTINE_TAG" --quiet || true
fi

# --- 3. Stop --------------------------------------------------------------
if [[ "$DO_STOP" == true ]]; then
  printf '\n%s3. Stop the instance%s\n' "$BOLD" "$RESET"
  run "stop $INSTANCE" \
    gcloud compute instances stop "$INSTANCE" \
      --zone="$ZONE" --project="$PROJECT" --quiet || true
fi

printf '\n%sNext steps%s\n' "$BOLD" "$RESET"
cat <<EOF
  1. Rotate everything the VM could reach. Anything readable from that box is
     burned: service account keys, SSH keys, app credentials, DB passwords.
  2. Look for attacker-created resources elsewhere in the project, especially
     VMs in regions you do not normally use:
       gcloud compute instances list --project=$PROJECT
  3. Rebuild rather than clean. Miners persist through cron, systemd units and
     modified startup scripts, so a rooted host cannot be trusted again.
     Recreate from a fresh image, redeploy from source, restore data only.
  4. Mount the forensic snapshot on an isolated analysis VM if you want to know
     how they got in, then delete the original instance.
  5. Reply to Google's abuse notice describing what you fixed - suspended
     resources are usually reinstated quickly once remediation is described.
EOF

if [[ "$APPLY" != true ]]; then
  printf '\n  %sDry run - nothing was changed. Add --apply to execute.%s\n\n' "$GREEN" "$RESET"
fi
