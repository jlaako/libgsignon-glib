#!/bin/sh

# Environment variables for the signon daemon
export SSO_LOGGING_LEVEL=2
export SSO_STORAGE_PATH="/tmp/gsignond"
export SSO_SECRET_PATH="/tmp/gsignond"
export SSO_DAEMON_TIMEOUT=5
export SSO_IDENTITY_TIMEOUT=5
export SSO_AUTHSESSION_TIMEOUT=5

#Environment variables for the test application
export G_MESSAGES_DEBUG=all
export G_SLICE=debug-blocks

TEST_APP="$TESTDIR/signon-glib-test-wrapper.sh"

# If dbus-test-runner exists, use it to run the tests in a separate D-Bus
# session
if command -v dbus-test-runner > /dev/null ; then
    echo "Using dbus-test-runner"
    dbus-test-runner -m 180 -t gsignond \
        -t "$TEST_APP" -f com.google.code.AccountsSSO.gSingleSignOn
else
    echo "Using existing D-Bus session"
    pkill gsignond || true
    trap "pkill -9 gsignond" EXIT
    gsignond &
    sleep 2

    $TEST_APP
fi
