#!/bin/bash

# Put/symlink this file in ~/.wireshark/extcap/
# https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html

set -euo pipefail

# Configurable variables

# fritz.box resolves here:
FRITZ_BOX_IP=192.168.178.1

# Potentially interesting - found by visiting https://$FRITZ_BOX_IP/?lp=cap and inspecting the buttons.
# There is also a listing at https://github.com/jpluimers/fritzcap/blob/master/fritzcap-interfaces-table.md
# 1-lan = lan
# 2-1   = 1. Internet connection
# 3-17  = Interface 0 ('internet')
# 4-135 = AP2 (5 GHz, ath1) - Interface 1
# 4-133 = AP (2.4 GHz, ath0) - Interface 1
# 4-128 = WLAN Management Traffic - Interface 0
FRITZ_BOX_IFACE="1-lan"

FRITZ_BOX_SID=

CAPTURE_FILTER=

FIFO_FILE=

DEBUG=
DEBUG_LOG_FILE=/tmp/fritz-extcap.log
log_debug() {
    if [ -n "$DEBUG" ] && [ -n "$DEBUG_LOG_FILE" ] ; then
        printf "[$$][% 5d] %s\n" "$SECONDS" "$*" >> "$DEBUG_LOG_FILE"
    fi
}


# Constants
EXTCAP_VERSION=0.1
CURL_BIN=/usr/bin/curl
TCPDUMP_BIN=/usr/bin/tcpdump

# --help
showhelp() {
    # Note: Unlike the others, this is not part of the extcap interface and we will be a bit more liberal,
    # and not use absolute paths to common commands.
    local PROG=$(realpath "${BASH_SOURCE[0]}")
    cat <<HELP
Wireshark - fritzbox-capture v$EXTCAP_VERSION

Usage:
 $PROG --extcap-interfaces
 $PROG --extcap-interface=fritzbox-capture --extcap-dlts
 $PROG --extcap-interface=fritzbox-capture --extcap-config
 $PROG --extcap-interface=fritzbox-capture --arg-sid [sid] --fifo myfifo --capture
 $PROG --extcap-interface=fritzbox-capture --arg-sid [sid] --fifo myfifo --capture --extcap-capture-filter 'host 1.1.1.1'
 $PROG --extcap-interface=fritzbox-capture --arg-ip [fritzbox ip] --arg-iface [interface] --arg-sid [sid] --fifo myfifo --capture
Options:
        --extcap-interfaces: list the extcap Interfaces
        --extcap-dlts: list the DLTs
        --extcap-interface <iface>: specify the extcap interface
        --extcap-config: list the additional configuration for an interface
        --capture: run the capture
        --extcap-capture-filter <filter>: the capture filter
        --fifo <file>: dump data to file or fifo
        --help: print this help
        --version: print the version
        --arg-ip <ip>: IP address of FRITZ!Box router. Defaults to: $FRITZ_BOX_IP
        --arg-iface <iface>: Network interface. Defaults to: $FRITZ_BOX_IFACE
                             Visit https://$FRITZ_BOX_IP/?lp=cap and inspect the value of "Start" buttons to find them.
                             Some values are also listed at https://github.com/jpluimers/fritzcap/blob/master/fritzcap-interfaces-table.md
        --arg-sid <sid>: URL with SID or just SID. Log in to the FRITZ!Box and copy a link containing sid. Required.
        --enable-logging: Enable logging
        --log-file <file>: Location of log file. Defaults to: $DEBUG_LOG_FILE
HELP
}

# --version
showversion() {
    echo "fritzbox-capture v$EXTCAP_VERSION"
}

# --extcap-interfaces
extcap_interfaces() {
    echo "extcap {version=$EXTCAP_VERSION}" # {help=helpurl} if I have one.
    echo "interface {value=fritzbox-capture}{display=FRITZ!Box capture}"
}

# --extcap-dlts
extcap_dlts() {
    # Have no idea what to put here, neither the documentation nor Wireshark's source code explains it well.
    # User-defined "DLT" need to start at 147.
    echo "dlt {number=147}{name=fritzbox-capture}{display=The Only FRITZ!Box capture}"
}

# --extcap_config
extcap_config() {
    echo "arg {number=0}{call=--arg-ip}{display=FRITZ!Box IP address}{type=string}{tooltip=FRITZ!Box IP address}{default=$FRITZ_BOX_IP}{required=true}"
    echo "arg {number=1}{call=--arg-iface}{display=FRITZ!Box interface}{type=string}{tooltip=FRITZ!Box capture interface, see https://$FRITZ_BOX_IP/?lp=cap for more info (and inspect the buttons to see the value) }{default=$FRITZ_BOX_IFACE}{required=true}"
    echo "arg {number=2}{call=--arg-sid}{display=FRITZ!Box sid or URL with sid}{type=string}{tooltip=The FRITZ!Box sid - after logging, find and copy a link containing sid}{required=true}"
    echo "arg {number=3}{call=--enable-logging}{display=Enable logging for debugging}{type=boolflag}"
    echo "arg {number=4}{call=--log-file}{display=Location of log file}{type=string}{default=$DEBUG_LOG_FILE}"
}

extcap_capture_filter_validation() {
    # Validation:
    # - non-zero exit code only = greenish = unknown
    # - empty stdout = green = valid
    # - non-empty stdout = red = invalid
    # 
    # Minimal eth capture file with 0 packets
    local DUMMY_PCAP_DATA='4\xcd\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00i\x00\x00\x00'
    if ! printf "$DUMMY_PCAP_DATA" | "$TCPDUMP_BIN" -r- -- "$CAPTURE_FILTER" 2>/dev/null ; then
        echo "Invalid capture filter"
    fi
}

# One of the above functions or "capture" or "exit".
ACTION=

while [[ $# -gt 0 ]] ; do
    case $1 in
        --help|-h)
            ACTION=showhelp
            break
            ;;
        --version)
            ACTION=showversion
            break
            ;;
        --extcap-interfaces)
            ACTION=extcap_interfaces
            ;;
        --extcap-version=*)
            # Ignore - we support all versions.
            ;;
        --extcap-dlts)
            ACTION=extcap_dlts
            ;;
        --extcap-config)
            ACTION=extcap_config
            ;;
        --extcap-interface)
            # We only support one interface (and also use that for easier arg parsing)
            if [[ "$2" != fritzbox-capture ]] ; then
                echo "Unsupported interface: $2 (expected fritzbox-capture)"
                exit 1
            fi
            shift
            ;;
        --capture)
            ACTION=capture
            ;;
        --extcap-capture-filter)
            CAPTURE_FILTER=$2
            [ -z "$ACTION" ] && ACTION=extcap_capture_filter_validation
            shift
            ;;
        --fifo)
            FIFO_FILE=$2
            shift
            ;;
        --arg-ip)
            FRITZ_BOX_IP=$2
            shift
            ;;
        --arg-iface)
            FRITZ_BOX_IFACE=$2
            shift
            ;;
        --arg-sid)
            FRITZ_BOX_SID=$2
            shift
            ;;
        --enable-logging)
            DEBUG=1
            ;;
        --log-file)
            DEBUG_LOG_FILE=$2
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Unknown option $1" >&2
            ;;
    esac
    shift
done

[ -z "$ACTION" ] && ACTION=showhelp
if [[ $ACTION != capture ]] ; then
    $ACTION
    exit $?
fi

# The main meat of this program: capturing

if [ ! -e "$FIFO_FILE" ] ; then
    echo "FIFO pipe is missing" >&2
    exit 1
fi

# wireshark/extcap.c sends SIGTERM when the capture ends, after unlinking FIFO_FILE.
# TODO: Actually, Wireshark doesn't send the signal. The logic works, with kill though.
# TODO: Try to find a good way to exit sooner, rather than relying on failures from FIFO_FILE.
trap 'catch_signal SIGINT' SIGINT
trap 'catch_signal SIGTERM' SIGTERM
exited_with_exitcode=
PID_OF_CURL_CAPTURE=
catch_signal() {
    local SIGNAL=$1
    trap - SIGINT SIGTERM
    log_debug "Received $SIGNAL, cleaning up"

    exec 3>&- # Close FIFO_FILE fd

    if [ -z "$PID_OF_CURL_CAPTURE" ] ; then
        log_debug "Early exit because capture has not started yet"
        # Haven't even started capturing yet, no need to clean up/tear down.
        exit 2
    fi

    if [ -n "$exited_with_exitcode" ] ; then
        log_debug "Cleanup already started, returning control to end"
        # If we are already at the final cleanup, let it finish.
        return
    fi

    if kill -$SIGNAL "$PID_OF_CURL_CAPTURE" ; then
        log_debug "Sent signal to kill curl"
    else
        log_debug "Failed to send signal to kill curl"
    fi
    # Transfer control back to after the wait call.
}

echo_error_and_exit() {
    local ERRMSG=$1

    echo "$ERRMSG" >&2
    log_debug "$ERRMSG"

    # Send EOF to FIFO pipe to get Wireshark to immediately show stderr in a dialog,
    # instead of requiring the user to end the capture first.
    echo > "$FIFO_FILE"

    exit 1
}

# Convenience: Paste URL with sid and we will extract the sid.
if [[ "$FRITZ_BOX_SID" =~ sid=([a-f0-9]{16}) ]]; then
    FRITZ_BOX_SID=${BASH_REMATCH[1]}
elif [[ "$FRITZ_BOX_SID" =~ sid=([a-z0-9]+) ]]; then
    # Just in case the sid becomes a bit longer or shorter.
    # Empirically, the sid appears to be truncated at 16 characters.
    FRITZ_BOX_SID=${BASH_REMATCH[1]}
fi

# Intentionally do not validate the SID beyond the above convenience method.
# Only do the bare minimum: sid check
if [ -z "$FRITZ_BOX_SID" ]; then
    echo_error_and_exit "sid is missing. Log in at https://${FRITZ_BOX_IP} and find a link containing '?sid=' to paste it in the capture options."
    exit 1
fi

log_debug "Verifying that sid is valid"

# Verify that SID is OK
# This is an intentionally lax check, to allow anything that looks potentially valid.
# If the validation somehow fails, then we will fail soon enough, below.
RESPONSE_TEXT=$("$CURL_BIN" --silent --insecure "https://${FRITZ_BOX_IP}/?sid=${FRITZ_BOX_SID}")
if [[ "$RESPONSE_TEXT" != *"?sid="* ]] ; then
    echo_error_and_exit "Invalid sid ($FRITZ_BOX_SID), please log in again at https://${FRITZ_BOX_IP}"
fi

log_debug "SID seems valid"

# Terminating the connection does not stop the capture.
stop_capture_from_fritz() {
    # Lower default max time down from 60 seconds. It should complete within a second, but when the fritzbox is stuck, it won't.
    # I have observed the fritzbox being stuck when there was an existing curl client that was likely stuck.
    # Killing that curl instance resolved the issue. Restarting the fritzbox always works too.
    "$CURL_BIN" --insecure --max-time 5 --silent "https://${FRITZ_BOX_IP}/cgi-bin/capture_notimeout?sid=${FRITZ_BOX_SID}&capture=Stop&ifaceorminor=${FRITZ_BOX_IFACE}" >/dev/null
    # TODO: Should check response text? When sid is invalid, request is 200 OK with body
    # "Internal communication error (login 0). Exiting."
    # Since the capture seems to usually end when the stream stops, let's just not validate it.
}

log_debug "Stopping existing capture, if any."

# Sometimes, stopping won't work, and the fritzbox won't serve new clients (i.e. immediately end the Start request).
if ! stop_capture_from_fritz ; then
    log_debug "Failed to stop remote capture before starting a new one. There may be another capturing client."
    failed_to_stop_capture_at_start=1
else
    failed_to_stop_capture_at_start=
fi

CURL_CAPTURE_FROM_FRITZ=(
    "$CURL_BIN"
    --insecure
    --silent
    --no-buffer
    "https://${FRITZ_BOX_IP}/cgi-bin/capture_notimeout?sid=${FRITZ_BOX_SID}&capture=Start&snaplen=&ifaceorminor=${FRITZ_BOX_IFACE}"
)

# Open FIFO as file descriptor (write-only) rather than passing its name to curl/tcpdump, so that we can control when to close it.
exec 3>"$FIFO_FILE"

TIME_STARTED=$SECONDS
if [ -z "$CAPTURE_FILTER" ] ; then
    log_debug "Starting capture without filter"
    "${CURL_CAPTURE_FROM_FRITZ[@]}" >&3 &
    PID_OF_CURL_CAPTURE=$!
else
    log_debug "Starting capture with filter"
    # With a filter, it's more involved... We want to be able to kill curl ASAP when capturing stops.
    # When curl is just piped to tcpdump, we would only be able to kill tcpdump. 
    # and curl would stay alive until it unsuccessfully tries to write to the pipe.
    #
    # But if we kill curl, and Wireshark closes the FIFO pipe, then tcpdump will exit automatically too.
    #
    # Under normal runs we have two situations:
    # - curl output ends (e.g. capture stopped). Then tcpdump would exit normally too.
    # - curl output is not pcap. tcpdump will detect this and exit. curl tries to write to broken pipe and fails.
    "${CURL_CAPTURE_FROM_FRITZ[@]}" > >("$TCPDUMP_BIN" --immediate-mode --dont-verify-checksums -nNS -s0 -r- -w- -- "$CAPTURE_FILTER" >&3 2>/dev/null) &
    PID_OF_CURL_CAPTURE=$!
fi

# Wait for them to exit, or for catch_signal to be called.
if wait $PID_OF_CURL_CAPTURE ; then
    exited_with_exitcode=$?
else
    exited_with_exitcode=0
fi
TIME_ELAPSED=$(( $SECONDS - $TIME_STARTED ))

log_debug "curl exited with $exited_with_exitcode, duration $TIME_ELAPSED seconds. Trying to stop capture..."

if ! stop_capture_from_fritz ; then
    log_debug "Failed to stop remote capture after completion"
    # The first stop can fail if there is an existing session that cannot be canceled for some reason.
    # The second stop can fail if the existing session is still there and preventing us from capturing - user must be informed.
    # The second stop can also fail if the sid is invalid (logging out does not abort existing capture sessions).
    if [ -n "$failed_to_stop_capture_at_start" ] ; then
        echo "Failed to stop existing capture session. Verify that the capture is stopped at https://${FRITZ_BOX_IP}/?lp=cap" >&2
    fi
fi

if [ $exited_with_exitcode != 0 ] ; then
    log_debug "Exited with error ($exited_with_exitcode)"
    echo "Capture failed or was interrupted" >&2
elif [[ $TIME_ELAPSED -ge 0 ]] && [[ $TIME_ELAPSED -lt 5 ]] ; then
    # Despite succesful exit, the capture ended early. Unlikely to be intentional.
    log_debug "Exited too soon ($TIME_ELAPSED)"
    echo "Capture ended suspiciously early." >&2
    echo "Is sid valid? Is capture supported by https://${FRITZ_BOX_IP}/?lp=cap ?" >&2
    exited_with_exitcode=1
else
    log_debug "Exited normally"
fi

# Flush FIFO file if needed - otherwise Wireshark doesn't know that we're done.
[ -e "$FIFO_FILE" ] && echo >&3
exec 3>&- # Close FIFO_FILE fd

# TODO: Should this extcap script return a non-zero exit code? It's not really significant.
exit $exited_with_exitcode
