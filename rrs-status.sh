#!/usr/bin/env bash
# rrs-status.sh — RRS shard swarm progress table
#   ./rrs-status.sh            one snapshot
#   ./rrs-status.sh --watch    refresh every 30 s
#   ./rrs-status.sh --hits     include hit details (members matched)
set -u
VPS_SSH=${VPS_SSH:-freebsd@51.38.36.86}
LAP_SSH=${LAP_SSH:-bloink@192.168.0.99}
PC_LOG=${PC_LOG:-$HOME/rrsscan/scan.log}
MODE=${1:-}
declare -A PC=() VPS=() LAP=()       # shard-suffix -> state (run|done|err)
declare -A PCX=() VPX=() LPX=()      # shard has hits (★)
declare -a HITROWS=()

# keys are the 3-digit suffix; last event on the shard wins chronologically
apply() { # $1=lane assoc-name $2=suffix $3=state
  local -n L=$1
  L[$2]=$3
}

map_lane() {
  local text=$1 lane=$2 id state
  while IFS= read -r line; do
    case "$line" in
      "START "*recroom-*)
        id=${line##*recroom-cdn-assetbundle-}; id=${id%% *}; id=${id%%$'\t'*}
        [[ $id =~ ^[0-9]+$ ]] && apply "$lane" "${id: -3}" run
        ;;
      "FINISH "*recroom-*)
        state=${line#FINISH }; id=${state##*recroom-cdn-assetbundle-}; id=${id%% *}
        state=${state%% *}
        [[ $id =~ ^[0-9]+$ ]] || continue
        case $state in
          DONE) apply "$lane" "${id: -3}" done ;;
          *)    apply "$lane" "${id: -3}" err  ;;   # RETRYNEXT / other
        esac
        ;;
      recroom-cdn-assetbundle-*HIT*)
        id=${line#recroom-cdn-assetbundle-}; id=${id%%$'\t'*}
        [[ $id =~ ^[0-9]+$ ]] || continue
        case $lane in
          PC)  PCX[${id: -3}]=1 ;;
          VPS) VPX[${id: -3}]=1 ;;
          LAP) LPX[${id: -3}]=1 ;;
        esac
        HITROWS+=("$line")
        ;;
      recroom-cdn-assetbundle-*)
        id=${line#recroom-cdn-assetbundle-}
        state=${id##*$'\t'}; id=${id%%$'\t'*}
        [[ $id =~ ^[0-9]+$ ]] || continue
        case $state in
          DONE*)  apply "$lane" "${id: -3}" done ;;
          ERROR*) apply "$lane" "${id: -3}" err ;;
        esac
        ;;
    esac
  done <<< "$text"
}

sym() { # $1=state $2=lanex-assoc-name $3=suffix
  local s=$1
  local -n X=$2
  [[ ${X[$3]:-} ]] && echo "★" && return
  case $s in
    done) echo "✓";; err) echo "✗";; run) echo "▶";; *) echo "·";;
  esac
}

fetch() {
  PC_TXT=$(cat "$PC_LOG" 2>/dev/null || true)
  VPS_TXT=$(ssh -o ConnectTimeout=6 "$VPS_SSH" 'cat ~/rrscan/scan.log 2>/dev/null' || true)
  LAP_TXT=$(ssh -o ConnectTimeout=6 "$LAP_SSH" 'bash -lc "cat /var/home/bloink/rrs/rrsscan/scan.log 2>/dev/null"' || true)
  map_lane "$PC_TXT"  PC
  map_lane "$VPS_TXT" VPS
  map_lane "$LAP_TXT" LAP
}
lane_counts() { # $1=lane  →  "done err hits run"
  local -n L=$1
  local -n X=$2
  local v d=0 e=0 h=0 r=0
  for v in "${L[@]}"; do
    case $v in done) d=$((d+1));; err) e=$((e+1));; run) r=$((r+1));; esac
  done
  echo "$d $e ${#X[@]} $r"
}

draw() {
  local p v l i id
  clear 2>/dev/null || true
  echo "  RRS SHARD SWARM — $(date '+%a %H:%M:%S')   (102 shards × 3 lanes)"
  echo "  ────────┬─────────┬─────────┬─────────"
  printf '  %-7s │ %-7s │ %-7s │ %-7s\n' "SHARD" "PC" "VPS" "LAPTOP"
  echo "  ────────┼─────────┼─────────┼─────────"
  for i in $(seq -f %03g 0 101); do
    p=$(sym "${PC[$i]:-}" PCX "$i")
    v=$(sym "${VPS[$i]:-}" VPX "$i")
    l=$(sym "${LAP[$i]:-}" LPX "$i")
    printf '  %-7s │ %-7s │ %-7s │ %-7s\n' "$i" "$p" "$v" "$l"
  done
  echo "  ────────┴─────────┴─────────┴─────────"
  read -r pc_d pc_e pc_h pc_r <<< "$(lane_counts PC PCX)"
  read -r vp_d vp_e vp_h vp_r <<< "$(lane_counts VPS VPX)"
  read -r lp_d lp_e lp_h lp_r <<< "$(lane_counts LAP LPX)"
  tot=$((pc_d+vp_d+lp_d)); err=$((pc_e+vp_e+lp_e)); hit=$((pc_h+vp_h+lp_h)); run=$((pc_r+vp_r+lp_r))
  echo "  done $tot/306 │ running $run │ errors $err │ lanes-with-hits $hit"
  echo "  PC: ✓${pc_d} ✗${pc_e} ★${pc_h} ▶${pc_r}   VPS: ✓${vp_d} ✗${vp_e} ★${vp_h} ▶${vp_r}   LAP: ✓${lp_d} ✗${lp_e} ★${lp_h} ▶${lp_r}"
  echo "  legend: ✓ done   ▶ in-flight   ✗ error   ★ hit found   · not started"
  if [[ $MODE == --hits && ${#HITROWS[@]} -gt 0 ]]; then
    echo
    echo "  ── HIT details ──"
    local h
    for h in "${HITROWS[@]}"; do echo "    ${h//$'\t'/  }"; done
  fi
}

fetch
draw

if [[ $MODE == --watch ]]; then
  while true; do
    sleep 30
    HITROWS=(); PC=(); VPS=(); LAP=(); PCX=(); VPX=(); LPX=()
    fetch
    draw
  done
fi
