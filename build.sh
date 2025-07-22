#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#9ca458bc1eaedf45dcca8c7e4a85ba3e3562396a -y'
sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyconf https://github.com/vyos/vyconf.git#f08ff04c71da7e3108120a45c1e2d4feb2f8e331 -y'

eval `opam config env`
make clean
make
