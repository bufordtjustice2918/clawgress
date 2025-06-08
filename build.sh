#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#e1b570dfbdb5703688b445f9d54160754cc2d190 -y'
sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyconf https://github.com/vyos/vyconf.git#30d9df43317ae7395a11c9e8a5414f177cefae79 -y'

eval `opam config env`
make clean
make
