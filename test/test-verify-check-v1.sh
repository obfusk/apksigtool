#!/bin/bash
set -e
export LC_ALL=C.UTF-8
for apk in apks/apks/*.apk; do
  [[ "$apk" != *empty* ]] || continue
  [[ "$apk" != *negmod* ]] || continue
  [[ "$apk" != *v1-only* ]] || continue
  [[ "$apk" != *weird-compression-method* ]] || continue
  echo "$apk"
  apksigner_result="$( grep -F -A1 "$apk" test-apksigner.out | tail -1 )"
  echo "$apksigner_result"
  if [ "$apksigner_result" = 'apksigner: verified' ]; then
    apksigner_verified=1
  else
    apksigner_verified=0
  fi
  if apksigtool verify --check-v1 "$apk" 2>&1; then
    apksigtool_verified=1
    echo 'apksigtool: verified'
  else
    apksigtool_verified=0
    echo 'apksigtool: not verified'
  fi
  if [ "$apksigner_verified" == "$apksigtool_verified" ]; then
    echo 'apksigner == apksigtool'
  else
    echo 'apksigner != apksigtool'
  fi
  echo
done
