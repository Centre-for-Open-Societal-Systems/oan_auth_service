#!/usr/bin/env bash
# Run the Fayda login collection with newman and keep everything each run produces.
#
#   ./run_fayda_login.sh start            step 1: prints the Fayda URL to open in a browser
#   ./run_fayda_login.sh finish '<url>'   steps 2-3 with the localhost:3000/callback?... URL
#   ./run_fayda_login.sh me               step 3 again with the saved token (valid ~1 h)
#   ./run_fayda_login.sh logout           step 4 with the saved token
#
# Each run writes to $FAYDA_RUN_DIR/<timestamp>/ (default ~/.cache/oan-fayda-login):
#   newman.txt     newman's verbose output
#   newman.json    newman's JSON report (every request and response)
#   iam-bene.log   iam-bene-portal-api container log for the run
#   frappe.log     lines the bench logs gained during the run
# $FAYDA_RUN_DIR/env.json holds the saved token, its claims and the /auth/me result.
# $FAYDA_RUN_DIR/latest points at the newest run. The token is a live credential: keep it local.
set -uo pipefail

cd "$(dirname "$0")"
COLLECTION=oan_auth_fayda_login_collection.json
BASE_ENV=oan_auth_fayda_login_local_environment.json
BENCH_LOGS=../../../logs
IAM_CONTAINER=iam-bene-portal-api
OUT=${FAYDA_RUN_DIR:-$HOME/.cache/oan-fayda-login}
SAVED_ENV=$OUT/env.json

STEP1="1. Start Fayda login (via IAM)"
STEP2="2. Complete IAM callback with the pasted Fayda redirect URL"
STEP3="3. Who am I (verify token)"
STEP4="4. Logout"

usage() { sed -n '4,7p' "$0" | sed 's/^# *//'; exit 2; }

mode=${1:-}
case $mode in
	start)  env_file=$BASE_ENV; folders=("$STEP1"); extra=() ;;
	finish) [[ -n ${2:-} ]] || usage
	        env_file=$BASE_ENV; folders=("$STEP2" "$STEP3"); extra=(--env-var "fayda_redirect_url=$2") ;;
	me)     env_file=$SAVED_ENV; folders=("$STEP3"); extra=() ;;
	logout) env_file=$SAVED_ENV; folders=("$STEP4"); extra=() ;;
	*)      usage ;;
esac
[[ -f $env_file ]] || { echo "No saved token in $SAVED_ENV: run 'finish' first" >&2; exit 1; }

run=$OUT/$(date +%Y%m%dT%H%M%S)-$mode
mkdir -p "$run"
ln -sfn "$run" "$OUT/latest"

# Remember how long each bench log is, so only this run's lines are kept.
declare -A sizes
for f in "$BENCH_LOGS"/*.log; do sizes[$f]=$(wc -c <"$f"); done
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)

folder_args=()
for f in "${folders[@]}"; do folder_args+=(--folder "$f"); done

newman run "$COLLECTION" -e "$env_file" "${folder_args[@]}" "${extra[@]}" \
	--verbose --reporters cli,json --reporter-json-export "$run/newman.json" \
	--export-environment "$run/env.json" | tee "$run/newman.txt"
status=${PIPESTATUS[0]}

# `start` must not replace a saved token with an empty one.
[[ $mode != start ]] && cp "$run/env.json" "$SAVED_ENV"

docker logs --since "$since" "$IAM_CONTAINER" >"$run/iam-bene.log" 2>&1
: >"$run/frappe.log"
for f in "$BENCH_LOGS"/*.log; do
	before=${sizes[$f]:-0}
	after=$(wc -c <"$f")
	if (( after > before )); then
		echo "==> $(basename "$f")" >>"$run/frappe.log"
		tail -c +$((before + 1)) "$f" >>"$run/frappe.log"
	fi
done

echo "Saved to $run"
exit "$status"
