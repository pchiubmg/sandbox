#!/usr/bin/env bash
#
# gcp-harden.sh - Apply least-privilege and access hardening to a GCP project.
#
# DRY RUN BY DEFAULT. Without --apply this prints the exact gcloud commands it
# would run and changes nothing. Every fix is opt-in through its own flag, so
# you can work through them one at a time and verify between steps.
#
# Before any IAM mutation the current policy is written to a timestamped backup
# that can be restored with:
#   gcloud projects set-iam-policy PROJECT_ID <backup.json>
#
# Usage:
#   ./gcp-harden.sh --project adeqo-tools                        # show everything it would do
#   ./gcp-harden.sh --project adeqo-tools --fix-default-sa       # still a dry run
#   ./gcp-harden.sh --project adeqo-tools --fix-default-sa --apply
#
# Fixes:
#   --fix-default-sa     remove primitive roles from default service accounts
#   --delete-sa-keys     delete user-managed (downloadable) service account keys
#   --downgrade-humans   drop project Editor/Owner for members in DOWNGRADE_MEMBERS
#   --fix-firewall       disable ingress rules exposing SSH/RDP to 0.0.0.0/0
#   --enable-oslogin     turn on OS Login project-wide and clear metadata SSH keys
#   --org-policies       enforce the preventative org policies (needs Org Admin)
#   --all                every fix above
#
# Requires: gcloud, jq.

set -euo pipefail

# ---------------------------------------------------------------------------
# Principals to strip project-level Editor/Owner from.
#
# Left empty on purpose: --downgrade-humans is a no-op until you fill this in,
# so nobody loses access by accident. Add entries only after checking the
# recommender output in the audit report, and tell the person first.
#
# Format is the full IAM member string, e.g.
#   "user:someone@bmgww.com"
#   "serviceAccount:thing@project.iam.gserviceaccount.com"
# ---------------------------------------------------------------------------
DOWNGRADE_MEMBERS=(
  # "user:mlimardi@bmgww.com"   # audit showed 11825/11825 permissions unused
  # "user:echang@bmgww.com"
  # "user:jhuang@bmgww.com"
)

# Role granted back to downgraded members so they keep read access.
REPLACEMENT_ROLE="roles/viewer"

PROJECT="${CLOUDSDK_CORE_PROJECT:-}"
APPLY=false
DO_DEFAULT_SA=false
DO_SA_KEYS=false
DO_HUMANS=false
DO_FIREWALL=false
DO_OSLOGIN=false
DO_ORG_POLICY=false
ANY_FIX=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project)          PROJECT="$2"; shift 2 ;;
    --apply)            APPLY=true; shift ;;
    --fix-default-sa)   DO_DEFAULT_SA=true; ANY_FIX=true; shift ;;
    --delete-sa-keys)   DO_SA_KEYS=true; ANY_FIX=true; shift ;;
    --downgrade-humans) DO_HUMANS=true; ANY_FIX=true; shift ;;
    --fix-firewall)     DO_FIREWALL=true; ANY_FIX=true; shift ;;
    --enable-oslogin)   DO_OSLOGIN=true; ANY_FIX=true; shift ;;
    --org-policies)     DO_ORG_POLICY=true; ANY_FIX=true; shift ;;
    --all)              DO_DEFAULT_SA=true; DO_SA_KEYS=true; DO_HUMANS=true
                        DO_FIREWALL=true; DO_OSLOGIN=true; DO_ORG_POLICY=true
                        ANY_FIX=true; shift ;;
    -h|--help)          sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)                  echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v gcloud >/dev/null || { echo "gcloud not found" >&2; exit 1; }
command -v jq     >/dev/null || { echo "jq not found (apt-get install jq)" >&2; exit 1; }

[[ -n "$PROJECT" ]] || PROJECT="$(gcloud config get-value project 2>/dev/null)"
if [[ -z "$PROJECT" || "$PROJECT" == "(unset)" ]]; then
  echo "No project set. Pass --project PROJECT_ID." >&2
  exit 2
fi

# No fix selected means "show me everything you could do", still as a dry run.
if [[ "$ANY_FIX" == false ]]; then
  DO_DEFAULT_SA=true; DO_SA_KEYS=true; DO_HUMANS=true
  DO_FIREWALL=true;   DO_OSLOGIN=true; DO_ORG_POLICY=true
  APPLY=false
fi

BOLD=$'\033[1m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; GREEN=$'\033[32m'; DIM=$'\033[2m'; RESET=$'\033[0m'
[[ -t 1 ]] || { BOLD=""; RED=""; YELLOW=""; GREEN=""; DIM=""; RESET=""; }

section() { printf '\n%s=== %s ===%s\n' "$BOLD" "$1" "$RESET"; }
note()    { printf '  %s\n' "$1"; }
skip()    { printf '  %s(skipped: %s)%s\n' "$DIM" "$1" "$RESET"; }

PLANNED=0
EXECUTED=0

# run <description> <command...>
# Prints the command. Executes it only under --apply.
run() {
  local desc="$1"; shift
  ((PLANNED++))
  printf '  %s%s%s\n' "$BOLD" "$desc" "$RESET"
  printf '    %s$ %s%s\n' "$DIM" "$*" "$RESET"
  if [[ "$APPLY" == true ]]; then
    if "$@"; then
      ((EXECUTED++))
      printf '    %s-> done%s\n' "$GREEN" "$RESET"
    else
      printf '    %s-> FAILED (continuing)%s\n' "$RED" "$RESET"
      return 1
    fi
  fi
  return 0
}

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
DEFAULT_COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
DEFAULT_GAE_SA="${PROJECT}@appspot.gserviceaccount.com"

printf '%sGCP hardening%s\n' "$BOLD" "$RESET"
printf 'project: %s (%s)\n' "$PROJECT" "$PROJECT_NUMBER"
printf 'as:      %s\n' "$(gcloud config get-value account 2>/dev/null)"
if [[ "$APPLY" == true ]]; then
  printf 'mode:    %sAPPLY - changes will be made%s\n' "$RED" "$RESET"
else
  printf 'mode:    %sDRY RUN - nothing will change (add --apply to execute)%s\n' "$GREEN" "$RESET"
fi

# ---------------------------------------------------------------------------
# Confirmation and backup
# ---------------------------------------------------------------------------
if [[ "$APPLY" == true ]]; then
  BACKUP="iam-policy-backup-${PROJECT}-$(date -u +%Y%m%d-%H%M%S).json"
  gcloud projects get-iam-policy "$PROJECT" --format=json > "$BACKUP"
  printf '\n  IAM policy backed up to %s%s%s\n' "$BOLD" "$BACKUP" "$RESET"
  printf '  Restore with: gcloud projects set-iam-policy %s %s\n' "$PROJECT" "$BACKUP"

  printf '\n%sThis will modify a live project. Type the project ID to continue: %s' "$YELLOW" "$RESET"
  read -r CONFIRM
  if [[ "$CONFIRM" != "$PROJECT" ]]; then
    echo "Aborted."
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# 1. Default service accounts
# ---------------------------------------------------------------------------
if [[ "$DO_DEFAULT_SA" == true ]]; then
  section "1. Primitive roles on default service accounts"
  note "A default SA with Editor means any workload running as it can act across"
  note "the whole project. Check what depends on it before applying:"
  note "  gcloud compute instances list --project=$PROJECT \\"
  note "    --format='table(name,serviceAccounts[0].email)'"
  note "GKE nodes, Cloud Build, Cloud Run, Cloud Functions and Dataflow commonly"
  note "default to this identity, so removing the role can break running workloads."
  echo

  POLICY="$(gcloud projects get-iam-policy "$PROJECT" --format=json)"
  FOUND=false
  for sa in "$DEFAULT_COMPUTE_SA" "$DEFAULT_GAE_SA"; do
    for role in roles/owner roles/editor; do
      if jq -e --arg r "$role" --arg m "serviceAccount:$sa" \
           '.bindings[] | select(.role==$r) | .members[] | select(.==$m)' \
           <<< "$POLICY" >/dev/null 2>&1; then
        FOUND=true
        run "remove $role from $sa" \
          gcloud projects remove-iam-policy-binding "$PROJECT" \
            --member="serviceAccount:$sa" --role="$role" \
            --condition=None --quiet || true
      fi
    done
  done
  [[ "$FOUND" == false ]] && skip "no primitive roles on default service accounts"

  if [[ "$FOUND" == true ]]; then
    echo
    note "Then give each workload a dedicated identity, for example:"
    note "  gcloud iam service-accounts create app-runtime --project=$PROJECT"
    note "  gcloud projects add-iam-policy-binding $PROJECT \\"
    note "    --member=serviceAccount:app-runtime@${PROJECT}.iam.gserviceaccount.com \\"
    note "    --role=roles/logging.logWriter"
    note "  gcloud compute instances set-service-account VM --zone=ZONE \\"
    note "    --service-account=app-runtime@${PROJECT}.iam.gserviceaccount.com \\"
    note "    --scopes=cloud-platform   # scope the SA's roles, not the VM's scopes"
  fi
fi

# ---------------------------------------------------------------------------
# 2. Exported service account keys
# ---------------------------------------------------------------------------
if [[ "$DO_SA_KEYS" == true ]]; then
  section "2. Downloadable service account keys"
  note "Exported JSON keys never expire and are the usual source of leaked"
  note "credentials. Make sure nothing depends on a key before deleting it."
  echo

  FOUND=false
  while read -r sa; do
    [[ -z "$sa" ]] && continue
    while read -r keyname; do
      [[ -z "$keyname" ]] && continue
      FOUND=true
      KEY_ID="$(basename "$keyname")"
      run "delete key $KEY_ID on $sa" \
        gcloud iam service-accounts keys delete "$KEY_ID" \
          --iam-account="$sa" --project="$PROJECT" --quiet || true
    done < <(gcloud iam service-accounts keys list --iam-account="$sa" \
               --managed-by=user --project="$PROJECT" \
               --format='value(name)' 2>/dev/null || true)
  done < <(gcloud iam service-accounts list --project="$PROJECT" --format='value(email)')

  [[ "$FOUND" == false ]] && skip "no user-managed keys found"
fi

# ---------------------------------------------------------------------------
# 3. Human primitive roles
# ---------------------------------------------------------------------------
if [[ "$DO_HUMANS" == true ]]; then
  section "3. Human Editor/Owner grants"

  if [[ ${#DOWNGRADE_MEMBERS[@]} -eq 0 ]]; then
    skip "DOWNGRADE_MEMBERS is empty - edit the array at the top of this script"
    note "Current holders of primitive roles:"
    gcloud projects get-iam-policy "$PROJECT" \
      --flatten="bindings[].members" \
      --filter="bindings.role:(roles/owner OR roles/editor)" \
      --format="table(bindings.role,bindings.members)" 2>/dev/null || true
    note ""
    note "Check actual usage before removing anything:"
    note "  gcloud recommender recommendations list --project=$PROJECT \\"
    note "    --location=global --recommender=google.iam.policy.Recommender"
  else
    note "Granting $REPLACEMENT_ROLE first so nobody is locked out mid-change."
    echo
    for member in "${DOWNGRADE_MEMBERS[@]}"; do
      run "grant $REPLACEMENT_ROLE to $member" \
        gcloud projects add-iam-policy-binding "$PROJECT" \
          --member="$member" --role="$REPLACEMENT_ROLE" \
          --condition=None --quiet || true
      for role in roles/editor roles/owner; do
        if gcloud projects get-iam-policy "$PROJECT" --format=json \
             | jq -e --arg r "$role" --arg m "$member" \
                 '.bindings[] | select(.role==$r) | .members[] | select(.==$m)' \
                 >/dev/null 2>&1; then
          run "remove $role from $member" \
            gcloud projects remove-iam-policy-binding "$PROJECT" \
              --member="$member" --role="$role" \
              --condition=None --quiet || true
        fi
      done
    done
  fi
fi

# ---------------------------------------------------------------------------
# 4. Firewall
# ---------------------------------------------------------------------------
if [[ "$DO_FIREWALL" == true ]]; then
  section "4. SSH/RDP exposed to the internet"
  note "Rules are disabled rather than deleted, so they can be re-enabled with"
  note "  gcloud compute firewall-rules update RULE --no-disabled"
  echo

  FOUND=false
  while IFS='|' read -r name ports; do
    [[ -z "$name" ]] && continue
    FOUND=true
    run "disable '$name' (allows $ports from 0.0.0.0/0)" \
      gcloud compute firewall-rules update "$name" \
        --project="$PROJECT" --disabled --quiet || true
  done < <(gcloud compute firewall-rules list --project="$PROJECT" --format=json 2>/dev/null \
           | jq -r '.[]
                    | select(.direction=="INGRESS" and (.disabled != true))
                    | select((.sourceRanges // []) | index("0.0.0.0/0"))
                    | select((.allowed // []) | any(
                        ((.ports // []) | length == 0)
                        or ((.ports // []) | any(. == "22" or . == "3389"))))
                    | "\(.name)|" + ((.allowed // []) | map(.IPProtocol + ":" + ((.ports // ["all"]) | join(","))) | join(" "))' \
           || true)

  if [[ "$FOUND" == false ]]; then
    skip "no ingress rules expose SSH/RDP to 0.0.0.0/0"
  else
    echo
    note "Replace them with IAP-tunnelled access, which authenticates via IAM:"
    note "  gcloud compute firewall-rules create allow-ssh-from-iap \\"
    note "    --project=$PROJECT --network=default --direction=INGRESS \\"
    note "    --action=allow --rules=tcp:22 --source-ranges=35.235.240.0/20"
    note "  gcloud projects add-iam-policy-binding $PROJECT \\"
    note "    --member=user:YOU@bmgww.com --role=roles/iap.tunnelResourceAccessor"
    note "  gcloud compute ssh VM --zone=ZONE --tunnel-through-iap"
  fi
fi

# ---------------------------------------------------------------------------
# 5. OS Login
# ---------------------------------------------------------------------------
if [[ "$DO_OSLOGIN" == true ]]; then
  section "5. OS Login"
  note "OS Login ties SSH access to IAM, so revoking a user's role revokes their"
  note "shell. Metadata SSH keys survive offboarding and are not auditable."
  echo

  CURRENT="$(gcloud compute project-info describe --project="$PROJECT" --format=json 2>/dev/null \
             | jq -r '.commonInstanceMetadata.items[]? | select(.key=="enable-oslogin") | .value' || true)"
  if [[ "${CURRENT^^}" == "TRUE" ]]; then
    skip "OS Login already enabled project-wide"
  else
    run "enable OS Login project-wide" \
      gcloud compute project-info add-metadata --project="$PROJECT" \
        --metadata=enable-oslogin=TRUE --quiet || true
    note "Grant login roles to the people who need shell access:"
    note "  gcloud projects add-iam-policy-binding $PROJECT \\"
    note "    --member=user:YOU@bmgww.com --role=roles/compute.osLogin"
  fi

  EXISTING_KEYS="$(gcloud compute project-info describe --project="$PROJECT" --format=json 2>/dev/null \
                   | jq -r '.commonInstanceMetadata.items[]? | select(.key=="ssh-keys") | .value' || true)"
  if [[ -n "$EXISTING_KEYS" ]]; then
    note ""
    note "Project-wide SSH keys are present. Remove them once OS Login works:"
    note "  gcloud compute project-info remove-metadata --project=$PROJECT --keys=ssh-keys"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Org policies
# ---------------------------------------------------------------------------
if [[ "$DO_ORG_POLICY" == true ]]; then
  section "6. Preventative org policies"

  ORG_ID="$(gcloud projects get-ancestors "$PROJECT" --format='value(id,type)' 2>/dev/null \
            | awk '$2=="organization"{print $1}' | head -1 || true)"

  if [[ -z "$ORG_ID" ]]; then
    skip "could not resolve the organization (needs resourcemanager.organizations.get)"
  else
    note "organization: $ORG_ID"
    note "These stop the problem recurring in this and every future project."
    note "iam.automaticIamGrantsForDefaultServiceAccounts applies to newly created"
    note "service accounts only - it does not remove the grant you already have."
    echo

    for c in iam.disableServiceAccountKeyCreation \
             iam.automaticIamGrantsForDefaultServiceAccounts \
             compute.requireOsLogin \
             compute.requireShieldedVm; do
      POLICY_FILE="$(mktemp)"
      cat > "$POLICY_FILE" <<EOF
name: organizations/${ORG_ID}/policies/${c}
spec:
  rules:
  - enforce: true
EOF
      run "enforce $c at the organization" \
        gcloud org-policies set-policy "$POLICY_FILE" --quiet || true
      rm -f "$POLICY_FILE"
    done

    note ""
    note "compute.vmExternalIpAccess is a list constraint - deny all public IPs with:"
    note "  gcloud org-policies deny compute.vmExternalIpAccess --organization=$ORG_ID --all"
    note "Add exemptions for VMs that genuinely need to be reachable."
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
section "Summary"
if [[ "$APPLY" == true ]]; then
  printf '  %d of %d action(s) executed.\n' "$EXECUTED" "$PLANNED"
  printf '  Re-run gcp-audit.sh to confirm the findings have cleared.\n'
  printf '  Restore IAM with: gcloud projects set-iam-policy %s %s\n\n' "$PROJECT" "${BACKUP:-<backup>}"
else
  printf '  %d action(s) planned. Nothing was changed.\n' "$PLANNED"
  printf '  Re-run with --apply to execute.\n\n'
fi
