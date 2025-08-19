#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#b53326dce7dd2dabad2677ad82de4fcd4ea85524 -y'
sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyconf https://github.com/vyos/vyconf.git#88d926d30b4219c50bbb1167ab58d60c5c5d2bbb -y'

eval `opam config env`
make clean
make
