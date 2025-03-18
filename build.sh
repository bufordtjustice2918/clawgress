#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#d08be19809a3e1c8413e0d98556273244dc18e77 -y'
sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyconf https://github.com/vyos/vyconf.git#33cc7567d909c776d43ea6698267125ea1ec2f66 -y'

eval `opam config env`
make clean
make
