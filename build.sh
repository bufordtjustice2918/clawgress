#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#e1b570dfbdb5703688b445f9d54160754cc2d190 -y'
sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyconf https://github.com/vyos/vyconf.git#9c0377200774cf8351dde9e134634aef85381674 -y'

eval `opam config env`
make clean
make
