#!/bin/env bash

set -e

for i in $(ls ./ | grep '[0-9]' ); do
	echo -e "\033[33m=== start build $i  ===\033[0;39m"
	( cd $i && (! test -f Makefile || make) )
	echo -e "\033[32m=== finish build $i ===\033[0;39m"

	i="$i/cilium-ebpf"
	echo -e "\033[33m=== start build $i  ===\033[0;39m"
	(! test -d $i || cd $i && (! test -f Makefile || make) )
	echo -e "\033[32m=== finish build $i ===\033[0;39m"
done

