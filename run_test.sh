#!/bin/bash
cd `dirname $0`
DIRS=`git grep -l 'func Test' | xargs dirname | sort -u`
for DIR in $DIRS
do
    pushd $DIR
    go test -v || $(echo ERROR; exit 1)
    popd
done
