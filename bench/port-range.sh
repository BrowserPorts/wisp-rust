#!/bin/zsh
# Widens the ephemeral port range for churn testing, or restores the default.
# Each upstream connection wispd closes first holds its local port in
# TIME_WAIT for twice the MSL (30 s on macOS), so `wisp-loadgen
# churn-client-close` runs out of the default 16,384 ports within seconds.
# The change is machine-wide and lasts until reboot.
#
# usage: sudo bench/port-range.sh raise|restore|show
set -eu
case "$(uname -s):${1:-show}" in
  Darwin:raise)
    sysctl -w net.inet.ip.portrange.first=10000 net.inet.ip.portrange.hifirst=10000 ;;
  Darwin:restore)
    sysctl -w net.inet.ip.portrange.first=49152 net.inet.ip.portrange.hifirst=49152 ;;
  Darwin:show)
    sysctl net.inet.ip.portrange.first net.inet.ip.portrange.last net.inet.tcp.msl ;;
  Linux:raise)
    sysctl -w net.ipv4.ip_local_port_range="10000 65535" ;;
  Linux:restore)
    sysctl -w net.ipv4.ip_local_port_range="32768 60999" ;;
  Linux:show)
    sysctl net.ipv4.ip_local_port_range ;;
  *)
    print -u2 "usage: sudo $0 raise|restore|show"
    exit 2 ;;
esac
