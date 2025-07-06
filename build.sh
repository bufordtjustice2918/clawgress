#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#74c67327160d8dffb8d79bf6691852855715d5f8 -y'
sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyconf https://github.com/vyos/vyconf.git#111bfa17c6ab2a983fb22427d55ecf6fd35d4529 -y'

eval `opam config env`
make clean
make
