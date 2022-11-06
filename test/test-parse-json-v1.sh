#!/bin/bash
set -e
export LC_ALL=C.UTF-8
for apk in apks/apks/*.apk; do
  [[ "$apk" != *empty* ]] || continue
  [[ "$apk" != *negmod* ]] || continue
  [[ "$apk" != *v2-only* ]] || continue
  [[ "$apk" != *v3-only* ]] || continue
  [[ "$apk" != *weird-compression-method* ]] || continue
  echo "$apk"
  apksigner_result="$( grep -F -A1 "$apk" test-apksigner.out | tail -1 )"
  echo "$apksigner_result"
  apksigtool parse-v1 --json "$apk" 2>&1 || true
  echo
done
