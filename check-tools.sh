#!/bin/sh
#
# Copyright 2022 steadybit GmbH. All rights reserved.
#

rc=0;

check_stress_ng() {
  if stdout=$(stress-ng -V 2>&1); then
    echo "INFO\t$stdout"
  else
    echo "ERROR\t$stdout"
    rc=1
  fi
}
#
#check_ip_rules() {
#  if stdout=$(ip -V 2>&1); then
#    echo "INFO\t$stdout"
#  else
#    echo "ERROR\t$stdout"
#    rc=1
#  fi
#}
#
#check_tc() {
#  if stdout=$(tc -V 2>&1); then
#    echo "INFO\t$stdout"
#  else
#    echo "ERROR\t$stdout"
#    rc=1
#  fi
#}
#
#check_cgexec() {
#  if stdout=$(cgexec --help 2>&1); then
#    echo "INFO\tcgexec is present"
#  else
#    echo "ERROR\t$stdout"
#    rc=1
#  fi
#}
#
#check_umoci() {
#  if stdout=$(umoci -v 2>&1); then
#    echo "INFO\t$stdout"
#  else
#    echo "ERROR\t$stdout"
#    rc=1
#  fi
#}
#
#check_skopeo() {
#  if stdout=$(skopeo -v 2>&1); then
#    echo "INFO\t$stdout"
#  else
#    echo "ERROR\t$stdout"
#    rc=1
#  fi
#}
#
#check_runc() {
#  if stdout=$(runc -v 2>&1); then
#    echo "INFO\t$stdout"
#  else
#    echo "ERROR\t$stdout"
#    rc=1
#  fi
#}
#
#check_dig() {
#  if stdout=$(dig -v 2>&1); then
#    echo "INFO\t$stdout"
#  else
#    echo "ERROR\t$stdout"
#    rc=1
#  fi
#}
#
#check_kill() {
#  stdout=$(kill 2>&1)
#  if [ $? -eq 2 ]; then
#    echo "INFO\tkill is present"
#  else
#    echo "ERROR\t$stdout"
#    rc=1
#  fi
#}

check_stress_ng
#check_ip_rules
#check_tc
#check_cgexec
#check_umoci
#check_skopeo
#check_runc
#check_dig
#check_kill

exit $rc;
