#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#b53326dce7dd2dabad2677ad82de4fcd4ea85524 -y'
sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyconf https://github.com/vyos/vyconf.git#2da0981501a9bec8b69d29f1e52c10db90571aa4 -y'

eval `opam config env`
make clean
make
