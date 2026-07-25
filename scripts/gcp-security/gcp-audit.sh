#!/usr/bin/env bash
#
# gcp-audit.sh - Read-only security audit of a GCP project.
#
# Makes no changes. Every gcloud call is a list/describe/read. Safe to run at
# any time, including during an active incident.
#
# Written in response to an AbuseEvent raised against the project: it collects
# the evidence needed to answer "what did Google flag, and how far could an
# attacker have reached from there".
#
# Usage:
#   ./gcp-audit.sh                        # audit the default project
#   ./gcp-audit.sh --project my-project
#   ./gcp-audit.sh --freshness 60d        # widen the log lookback
#
# Requires: gcloud, jq. Run it in Cloud Shell, which has both.

set -uo pipefail   # deliberately no -e: several probes fail benignly when an
                   # API is disabled or the caller lacks org-level read access.

PROJECT="${CLOUDSDK_CORE_PROJECT:-}"
FRESHNESS="30d"
OUTDIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project)   PROJECT="$2"; shift 2 ;;
    --freshness) FRESHNESS="$2"; shift 2 ;;
    --outdir)    OUTDIR="$2"; shift 2 ;;
    -h|--help)   sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v gcloud >/dev/null || { echo "gcloud not found" >&2; exit 1; }
command -v jq     >/dev/null || { echo "jq not found (apt-get install jq)" >&2; exit 1; }

[[ -n "$PROJECT" ]] || PROJECT="$(gcloud config get-value project 2>/dev/null)"
if [[ -z "$PROJECT" || "$PROJECT" == "(unset)" ]]; then
  echo "No project set. Pass --project PROJECT_ID." >&2
  exit 2
fi

[[ -n "$OUTDIR" ]] || OUTDIR="gcp-audit-${PROJECT}-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

BOLD=$'\033[1m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; GREEN=$'\033[32m'; RESET=$'\033[0m'
[[ -t 1 ]] || { BOLD=""; RED=""; YELLOW=""; GREEN=""; RESET=""; }

FINDINGS=()

section() { printf '\n%s=== %s ===%s\n' "$BOLD" "$1" "$RESET"; }
note()    { printf '  %s\n' "$1"; }
crit()    { printf '  %s[CRITICAL]%s %s\n' "$RED"    "$RESET" "$1"; FINDINGS+=("CRITICAL|$1"); }
warn()    { printf '  %s[WARN]%s     %s\n' "$YELLOW" "$RESET" "$1"; FINDINGS+=("WARN|$1"); }
ok()      { printf '  %s[ok]%s       %s\n' "$GREEN"  "$RESET" "$1"; }

# Run a gcloud command, tee raw output to the report dir, tolerate failure.
# capture <outfile> <command...>
capture() {
  local out="$OUTDIR/$1"; shift
  if ! "$@" >"$out" 2>"$out.err"; then
    if [[ -s "$out.err" ]]; then
      note "(could not read: $(head -1 "$out.err" | cut -c1-100))"
    fi
    return 1
  fi
  rm -f "$out.err"
  return 0
}

printf '%sGCP security audit%s\n' "$BOLD" "$RESET"
printf 'project:   %s\n' "$PROJECT"
printf 'as:        %s\n' "$(gcloud config get-value account 2>/dev/null)"
printf 'lookback:  %s\n' "$FRESHNESS"
printf 'report:    %s/\n' "$OUTDIR"

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)' 2>/dev/null)"
if [[ -z "$PROJECT_NUMBER" ]]; then
  echo "Cannot describe project '$PROJECT'. Check the ID and your access." >&2
  exit 1
fi
DEFAULT_COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
DEFAULT_GAE_SA="${PROJECT}@appspot.gserviceaccount.com"
printf 'number:    %s\n' "$PROJECT_NUMBER"

# ---------------------------------------------------------------------------
# 1. Abuse events - the reason we are here
# ---------------------------------------------------------------------------
section "1. Abuse events (last $FRESHNESS)"

ABUSE_FILTER='jsonPayload.@type="type.googleapis.com/google.cloud.abuseevent.logging.v1.AbuseEvent"'
if capture abuse-events.json \
     gcloud logging read "$ABUSE_FILTER" \
       --project="$PROJECT" --freshness="$FRESHNESS" --format=json; then
  COUNT="$(jq 'length' "$OUTDIR/abuse-events.json" 2>/dev/null || echo 0)"
  if [[ "$COUNT" -gt 0 ]]; then
    crit "$COUNT abuse event(s) reported by Google against this project"
    jq -r '.[] | "  - \(.timestamp)
      category:    \(.jsonPayload.detectionCategory // "?")
      action:      \(.jsonPayload.action // "?")
      resource:    \(.jsonPayload.resourceName // .jsonPayload.subscriptionId // "?")
      remediation: \(.jsonPayload.remediationLink // "?")"' \
      "$OUTDIR/abuse-events.json" 2>/dev/null | head -60

    # The detection category drives the whole response, so surface it loudly.
    jq -r '[.[].jsonPayload.detectionCategory] | unique | .[]' \
      "$OUTDIR/abuse-events.json" 2>/dev/null | while read -r cat; do
        [[ -n "$cat" ]] && note "detected category: $cat"
      done
  else
    ok "no abuse events in the last $FRESHNESS (widen with --freshness)"
  fi
fi

# ---------------------------------------------------------------------------
# 2. Project IAM policy
# ---------------------------------------------------------------------------
section "2. Project IAM policy"

if capture iam-policy.json gcloud projects get-iam-policy "$PROJECT" --format=json; then
  note "saved to $OUTDIR/iam-policy.json (this is your restore point)"

  # Primitive roles are the ones that turn one compromised resource into a
  # compromised project.
  jq -r '.bindings[] | select(.role=="roles/owner" or .role=="roles/editor")
         | .role as $r | .members[] | "\($r)|\(.)"' \
     "$OUTDIR/iam-policy.json" 2>/dev/null | sort -u > "$OUTDIR/primitive-roles.txt"

  while IFS='|' read -r role member; do
    [[ -z "$member" ]] && continue
    case "$member" in
      serviceAccount:"$DEFAULT_COMPUTE_SA"|serviceAccount:"$DEFAULT_GAE_SA")
        crit "$member holds $role - a default service account with a primitive role means any workload running as it has project-wide power" ;;
      serviceAccount:*)
        warn "$member holds $role" ;;
      user:*)
        [[ "$role" == "roles/owner" ]] && warn "$member holds $role" || note "$member holds $role" ;;
      *)
        warn "$member holds $role" ;;
    esac
  done < "$OUTDIR/primitive-roles.txt"

  # Anyone on the public internet holding a role is an emergency.
  if grep -qE 'allUsers|allAuthenticatedUsers' "$OUTDIR/iam-policy.json"; then
    crit "policy grants a role to allUsers/allAuthenticatedUsers - the project is publicly writable to some degree"
  else
    ok "no allUsers/allAuthenticatedUsers in the project policy"
  fi

  # External identities are the classic sign of attacker persistence.
  jq -r '.bindings[].members[]' "$OUTDIR/iam-policy.json" 2>/dev/null \
    | grep -E '^user:' | sed 's/^user://' | sort -u > "$OUTDIR/human-members.txt"
  EXTERNAL="$(grep -vE '@bmgww\.com$' "$OUTDIR/human-members.txt" 2>/dev/null || true)"
  if [[ -n "$EXTERNAL" ]]; then
    while read -r m; do
      [[ -n "$m" ]] && crit "external (non-bmgww.com) identity has access: $m"
    done <<< "$EXTERNAL"
  else
    ok "all human principals are @bmgww.com identities"
  fi

  # Conditional bindings can hide access from a casual read of the console.
  COND="$(jq '[.bindings[] | select(has("condition"))] | length' "$OUTDIR/iam-policy.json" 2>/dev/null || echo 0)"
  [[ "$COND" -gt 0 ]] && note "$COND conditional binding(s) present - review them by hand"
fi

# ---------------------------------------------------------------------------
# 3. Service accounts and their keys
# ---------------------------------------------------------------------------
section "3. Service accounts and exported keys"

if capture service-accounts.json \
     gcloud iam service-accounts list --project="$PROJECT" --format=json; then
  SA_COUNT="$(jq 'length' "$OUTDIR/service-accounts.json" 2>/dev/null || echo 0)"
  note "$SA_COUNT service account(s) in the project"

  : > "$OUTDIR/user-managed-keys.txt"
  jq -r '.[].email' "$OUTDIR/service-accounts.json" 2>/dev/null | while read -r sa; do
    [[ -z "$sa" ]] && continue
    KEYS="$(gcloud iam service-accounts keys list \
              --iam-account="$sa" --managed-by=user \
              --project="$PROJECT" --format='value(name,validAfterTime)' 2>/dev/null)"
    if [[ -n "$KEYS" ]]; then
      while read -r line; do
        [[ -z "$line" ]] && continue
        KEY_ID="$(basename "${line%%$'\t'*}")"
        echo "$sa|$KEY_ID|${line#*$'\t'}" >> "$OUTDIR/user-managed-keys.txt"
      done <<< "$KEYS"
    fi
  done

  if [[ -s "$OUTDIR/user-managed-keys.txt" ]]; then
    while IFS='|' read -r sa key created; do
      if [[ "$sa" == "$DEFAULT_COMPUTE_SA" ]]; then
        crit "default compute SA has a downloadable key ($key, created $created) - this is a prime leak candidate and should not exist"
      else
        warn "downloadable key on $sa ($key, created $created)"
      fi
    done < "$OUTDIR/user-managed-keys.txt"
    note "exported JSON keys are the most common source of LEAKED_CREDENTIALS abuse events"
  else
    ok "no user-managed (downloadable) service account keys"
  fi
fi

# ---------------------------------------------------------------------------
# 4. Compute instances - what identity do they run as?
# ---------------------------------------------------------------------------
section "4. Compute instances"

if capture instances.json \
     gcloud compute instances list --project="$PROJECT" --format=json; then
  VM_COUNT="$(jq 'length' "$OUTDIR/instances.json" 2>/dev/null || echo 0)"
  note "$VM_COUNT instance(s)"

  if [[ "$VM_COUNT" -gt 0 ]]; then
    gcloud compute instances list --project="$PROJECT" \
      --format="table(name,zone.basename():label=ZONE,status,
                      serviceAccounts[0].email:label=RUNS_AS,
                      networkInterfaces[0].accessConfigs[0].natIP:label=EXTERNAL_IP)" 2>/dev/null

    # A VM using the default SA *and* the cloud-platform scope is the worst
    # case: shell on the box equals whatever roles that SA holds.
    jq -r --arg sa "$DEFAULT_COMPUTE_SA" '
      .[] | select(.serviceAccounts[0].email == $sa)
          | select(.serviceAccounts[0].scopes[]? | contains("cloud-platform"))
          | .name' "$OUTDIR/instances.json" 2>/dev/null | while read -r vm; do
      [[ -n "$vm" ]] && crit "VM '$vm' runs as the default compute SA with cloud-platform scope - a shell on it inherits that SA's full project access"
    done

    jq -r '.[] | select(.networkInterfaces[0].accessConfigs[0].natIP != null)
               | "\(.name) \(.networkInterfaces[0].accessConfigs[0].natIP)"' \
       "$OUTDIR/instances.json" 2>/dev/null | while read -r vm ip; do
      [[ -n "$vm" ]] && note "VM '$vm' has a public IP ($ip)"
    done

    # Unexpected machine types in unused regions are the cryptomining tell.
    note "machine types in use (look for large/GPU shapes you did not create):"
    jq -r '.[] | "    \(.name)  \(.machineType | split("/") | last)  \(.zone | split("/") | last)"' \
       "$OUTDIR/instances.json" 2>/dev/null
  fi
fi

# ---------------------------------------------------------------------------
# 5. Firewall exposure
# ---------------------------------------------------------------------------
section "5. Firewall rules open to the internet"

if capture firewall.json \
     gcloud compute firewall-rules list --project="$PROJECT" --format=json; then
  # Errors are not suppressed here: a filter that silently fails would print
  # "no rules open to the internet", which is the most dangerous thing this
  # script could get wrong.
  if ! jq -r '.[]
       | select(.direction=="INGRESS" and (.disabled != true))
       | select((.sourceRanges // []) | index("0.0.0.0/0"))
       | "\(.name)|" + ((.allowed // []) | map(.IPProtocol + ":" + ((.ports // ["all"]) | join(","))) | join(" "))' \
       "$OUTDIR/firewall.json" > "$OUTDIR/open-firewall.txt"; then
    crit "could not evaluate firewall rules - check $OUTDIR/firewall.json by hand"
  fi

  if [[ -s "$OUTDIR/open-firewall.txt" ]]; then
    while IFS='|' read -r name allow; do
      [[ -z "$name" ]] && continue
      if [[ "$allow" == *":22"* || "$allow" == *":3389"* || "$allow" == *"all"* ]]; then
        crit "firewall '$name' exposes remote access to 0.0.0.0/0 ($allow)"
      else
        warn "firewall '$name' open to 0.0.0.0/0 ($allow)"
      fi
    done < "$OUTDIR/open-firewall.txt"
    note "SSH/RDP open to the world is the most common initial access vector"
  else
    ok "no ingress rules open to 0.0.0.0/0"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Public storage buckets
# ---------------------------------------------------------------------------
section "6. Storage bucket exposure"

if capture buckets.txt \
     gcloud storage buckets list --project="$PROJECT" --format='value(name)'; then
  if [[ -s "$OUTDIR/buckets.txt" ]]; then
    while read -r bucket; do
      [[ -z "$bucket" ]] && continue
      POLICY="$(gcloud storage buckets get-iam-policy "gs://$bucket" --format=json 2>/dev/null)"
      if grep -qE 'allUsers|allAuthenticatedUsers' <<< "$POLICY"; then
        crit "bucket gs://$bucket is publicly accessible"
      fi
    done < "$OUTDIR/buckets.txt"
    ok "checked $(wc -l < "$OUTDIR/buckets.txt") bucket(s) for public access"
  else
    ok "no buckets in this project"
  fi
fi

# ---------------------------------------------------------------------------
# 7. Suspicious admin activity
# ---------------------------------------------------------------------------
section "7. Admin activity (last $FRESHNESS)"

AUDIT_FILTER="logName=\"projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Factivity\" AND protoPayload.methodName=(\"SetIamPolicy\" OR \"google.iam.admin.v1.CreateServiceAccountKey\" OR \"google.iam.admin.v1.CreateServiceAccount\" OR \"v1.compute.instances.insert\" OR \"v1.compute.firewalls.insert\")"

if capture admin-activity.json \
     gcloud logging read "$AUDIT_FILTER" \
       --project="$PROJECT" --freshness="$FRESHNESS" --limit=200 --format=json; then
  ACT_COUNT="$(jq 'length' "$OUTDIR/admin-activity.json" 2>/dev/null || echo 0)"
  note "$ACT_COUNT privileged action(s) recorded"
  if [[ "$ACT_COUNT" -gt 0 ]]; then
    note "who did what (review for anything you do not recognise):"
    jq -r '.[] | "    \(.timestamp[0:19])  \(.protoPayload.authenticationInfo.principalEmail // "?")  \(.protoPayload.methodName)"' \
       "$OUTDIR/admin-activity.json" 2>/dev/null | sort | uniq -c | sort -rn | head -30
    note "full detail in $OUTDIR/admin-activity.json"
  fi
fi

# ---------------------------------------------------------------------------
# 8. Instance access hardening
# ---------------------------------------------------------------------------
section "8. SSH access configuration"

if capture project-metadata.json \
     gcloud compute project-info describe --project="$PROJECT" --format=json; then
  OSLOGIN="$(jq -r '.commonInstanceMetadata.items[]? | select(.key=="enable-oslogin") | .value' \
             "$OUTDIR/project-metadata.json" 2>/dev/null)"
  if [[ "${OSLOGIN^^}" == "TRUE" ]]; then
    ok "OS Login is enabled project-wide"
  else
    warn "OS Login is not enabled project-wide - SSH access is governed by metadata keys rather than IAM"
  fi

  SSHKEYS="$(jq -r '.commonInstanceMetadata.items[]? | select(.key=="ssh-keys") | .value' \
             "$OUTDIR/project-metadata.json" 2>/dev/null)"
  if [[ -n "$SSHKEYS" ]]; then
    N="$(grep -c . <<< "$SSHKEYS")"
    warn "$N project-wide SSH key(s) in metadata - these grant access to every VM and survive user offboarding"
  else
    ok "no project-wide SSH keys in metadata"
  fi
fi

# ---------------------------------------------------------------------------
# 9. IAM recommender - the "excess permissions" numbers from the console
# ---------------------------------------------------------------------------
section "9. Excess permission recommendations"

if capture iam-recommendations.json \
     gcloud recommender recommendations list \
       --project="$PROJECT" --location=global \
       --recommender=google.iam.policy.Recommender --format=json; then
  REC_COUNT="$(jq 'length' "$OUTDIR/iam-recommendations.json" 2>/dev/null || echo 0)"
  if [[ "$REC_COUNT" -gt 0 ]]; then
    note "$REC_COUNT least-privilege recommendation(s) from Policy Intelligence:"
    jq -r '.[] | "    \(.content.overview.member // "?"): \(.description)"' \
       "$OUTDIR/iam-recommendations.json" 2>/dev/null | head -30
  else
    ok "no pending IAM recommendations (or the API needs enabling)"
  fi
fi

# ---------------------------------------------------------------------------
# 10. Org policy posture
# ---------------------------------------------------------------------------
section "10. Preventative org policies"

for c in iam.disableServiceAccountKeyCreation \
         iam.automaticIamGrantsForDefaultServiceAccounts \
         compute.requireOsLogin \
         compute.vmExternalIpAccess \
         compute.requireShieldedVm; do
  OUT="$(gcloud org-policies describe "$c" --project="$PROJECT" --effective --format=json 2>/dev/null)"
  if [[ -z "$OUT" ]]; then
    note "$c: could not read (needs org-level access)"
  elif grep -q '"enforce": true' <<< "$OUT" || grep -q 'enforce: true' <<< "$OUT"; then
    ok "$c is enforced"
  else
    warn "$c is not enforced"
  fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
section "Summary"

CRITS=0; WARNS=0
for f in "${FINDINGS[@]:-}"; do
  [[ -z "$f" ]] && continue
  [[ "${f%%|*}" == "CRITICAL" ]] && ((CRITS++))
  [[ "${f%%|*}" == "WARN"     ]] && ((WARNS++))
done

printf '  %s%d critical%s, %s%d warning%s\n' "$RED" "$CRITS" "$RESET" "$YELLOW" "$WARNS" "$RESET"
if [[ "$CRITS" -gt 0 ]]; then
  printf '\n  Critical findings:\n'
  for f in "${FINDINGS[@]:-}"; do
    [[ "${f%%|*}" == "CRITICAL" ]] && printf '    - %s\n' "${f#*|}"
  done
fi

{
  printf 'GCP security audit\nproject: %s (%s)\nrun at:  %s\n\n' \
    "$PROJECT" "$PROJECT_NUMBER" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for f in "${FINDINGS[@]:-}"; do
    [[ -n "$f" ]] && printf '[%s] %s\n' "${f%%|*}" "${f#*|}"
  done
} > "$OUTDIR/findings.txt"

printf '\n  Raw evidence and findings saved to %s/\n' "$OUTDIR"
printf '  Next: review findings.txt, then run gcp-harden.sh (dry-run by default).\n\n'
