#!/bin/bash

declare -A d

# Visit https://$FRITZ_BOX_IP/?lp=cap and inspect the value of "Start" buttons to find them.
# Some values are also listed at https://github.com/jpluimers/fritzcap/blob/master/fritzcap-interfaces-table.md

d["Internetverbindung"]="2-1"
# d["Schnittstelle 0 ('internet')"]="3-17"
# d["Schnittstelle 1 ('mstv')"]="3-18"
# d["Routing-Schnittstelle"]="3-0"
# d["tunl0"]="1-tunl0"
# d["ath1"]="1-ath1"
# d["ptm0"]="1-ptm0"
# d["eoam"]="1-eoam"
# d["xfrm"]="1-xfrm"
# d["eth3"]="1-eth3"
# d["eth0"]="1-eth0"
# d["wan"]="1-wan"
# d["wifi0"]="1-wifi0"
# d["eth1"]="1-eth1"
# d["lan"]="1-lan"
# d["ath0"]="1-ath0"
# d["ing0"]="1-ing0"
# d["wifi1"]="1-wifi1"
# d["ppptty"]="1-ppptty"
# d["eth2"]="1-eth2"
# d["cpunet0"]="1-cpunet0"
d["AP2 (2.4 GHz, ath0) - Schnittstelle 1"]="4-135"
d["AP (5 GHz, ath1) - Schnittstelle 1"]="4-133"
# d["WLAN Management Traffic - Schnittstelle 0"]="4-128"
# d["usb4"]="5-204"
# d["usb3"]="5-203"
# d["usb2"]="5-202"
# d["usb1"]="5-201"
