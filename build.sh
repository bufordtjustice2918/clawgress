#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#8c1474f99481f5226b1d47d1690b34d9740bf23b -y'
sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyconf https://github.com/vyos/vyconf.git#aedecf6fa96509ef59fd2e1f607a8a13c18d214b -y'

eval `opam config env`
make clean
make
