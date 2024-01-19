#!/bin/bash

function usage()
{
cat <<EOF
Usage:
  -u        Switch to UEFI Linux boot build
  -l        Switch to legacy Linux boot build
EOF
}

getopts "ul" OPTION

case $OPTION in
    u)
        sed -i 's/x86_64_efi\ =\ loader\/i386\/linux\.c\;/x86_64_efi\ =\ loader\/i386\/efi\/linux\.c\;/g' grub-core/Makefile.core.def
        echo "Switched to UEFI Linux boot"
        ;;
    l)
        sed -i 's/x86_64_efi\ =\ loader\/i386\/efi\/linux\.c\;/x86_64_efi\ =\ loader\/i386\/linux\.c\;/g' grub-core/Makefile.core.def
        echo "Switched to legacy Linux boot"
        ;;
    *)
        usage
        ;;
esac
