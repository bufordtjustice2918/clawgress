#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#be576e9d9281d8b97059bba3882be8deac4f724d -y'
sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyconf https://github.com/vyos/vyconf.git#a375860a302a224722d254c31a1cb210cb12d972 -y'

eval `opam config env`
make clean
make
