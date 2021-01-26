#!/usr/bin/env

set -eu
set -o pipefail

for i in `find ./ -name "*.go" | grep -v '/vendor/'` # or whatever other pattern...
do
  if ! grep -q Copyright $i
  then
    cat LICENSE_HEADER $i >$i.new && mv $i.new $i
  fi
done
