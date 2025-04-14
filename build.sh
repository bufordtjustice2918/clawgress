#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#52127a780f81342f454b72e8b8a9493afc530d6b -y'
sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyconf https://github.com/vyos/vyconf.git#4f8cd87849ae16f5efb127b63767176a243bcd8d -y'

eval `opam config env`
make clean
make
