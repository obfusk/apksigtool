#!/bin/bash
set -e
export LC_ALL=C.UTF-8
for apk in apks/*.apk; do
  [[ "$apk" != *empty* ]] || continue
  [[ "$apk" != *negmod* ]] || continue
  [[ "$apk" != *v1-only* ]] || continue
  echo "$apk"
  if apksigner verify --min-sdk-version=28 "$apk" >/dev/null 2>&1; then
    echo 'apksigner: verified'
  else
    echo 'apksigner: not verified'
  fi
  apksigtool parse "$apk" 2>&1 || true
  echo
done
