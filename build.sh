#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#6f272cd81318e719d91dcc06b1a5cfb435e1f4c7 -y'
sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyconf https://github.com/vyos/vyconf.git#920b75a6dbf9eac4b94600b759818b2ec28004ae -y'

eval `opam config env`
make clean
make
