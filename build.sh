#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#ccdc583f0f02583771fadae353166ef1a904f4e3 -y'
sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyconf https://github.com/vyos/vyconf.git#0fb5e2f781725196ae010cf64e4d185a8f5ce721 -y'

eval `opam config env`
make clean
make
