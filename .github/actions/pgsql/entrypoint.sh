#!/bin/sh

PGKS=$1
echo "$PGKS"

if [ -n $PGKS ]; then
  apt-get install -y $PGKS
  if [ $? -ne 0 ]; then
    exit 1;
  fi
fi
/etc/init.d/postgresql start

prove
