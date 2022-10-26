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
  apksigtool parse --json "$apk" 2>/dev/null | jq '.pairs[].value._type' || true
  apksigtool clean "$apk" 2>&1 || true
  apksigtool clean "$apk" 2>&1 || true
  apksigtool parse --json "$apk" 2>/dev/null | jq '.pairs[].value._type' || true
  if apksigner verify --min-sdk-version=28 "$apk" >/dev/null 2>&1; then
    echo 'apksigner: verified'
  else
    echo 'apksigner: not verified'
  fi
  if apksigtool verify "$apk" 2>&1; then
    echo 'apksigtool: verified'
  else
    echo 'apksigtool: not verified'
  fi
  echo
done
