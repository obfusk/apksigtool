#!/bin/bash
set -e
export LC_ALL=C.UTF-8
for apk in apks/*.apk; do
  [[ "$apk" != *empty* ]] || continue
  [[ "$apk" != *negmod* ]] || continue
  [[ "$apk" != *v1-only* ]] || continue
  echo "$apk"
  if apksigner verify --min-sdk-version=28 "$apk" >/dev/null 2>&1; then
    apksigner_verified=1
    echo 'apksigner: verified'
  else
    apksigner_verified=0
    echo 'apksigner: not verified'
  fi
  if apksigtool verify "$apk" 2>&1; then
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
