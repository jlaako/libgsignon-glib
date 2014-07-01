/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libgsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2012 Canonical Ltd.
 * Copyright (C) 2012-2014 Intel Corporation.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@canonical.com>
 * Contact: Jussi Laako <jussi.laako@linux.intel.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef SIGNONAUTHSESSION_H_
#define SIGNONAUTHSESSION_H_

#include <gio/gio.h>
#include <glib-object.h>
#include <libgsignon-glib/signon-types.h>

G_BEGIN_DECLS

/*
 * Useful session data keys
 */
/**
 * SIGNON_SESSION_DATA_USERNAME:
 *
 * Username.
 */
#define SIGNON_SESSION_DATA_USERNAME      "UserName"
/**
 * SIGNON_SESSION_DATA_SECRET:
 *
 * Secret.
 */
#define SIGNON_SESSION_DATA_SECRET        "Secret"
/**
 * SIGNON_SESSION_DATA_REALM:
 *
 * Realm.
 */
#define SIGNON_SESSION_DATA_REALM         "Realm"
/**
 * SIGNON_SESSION_DATA_PROXY:
 *
 * Proxy.
 */
#define SIGNON_SESSION_DATA_PROXY         "NetworkProxy"

/**
 * SignonSessionDataUiPolicy:
 * @SIGNON_POLICY_DEFAULT: The plugin can decide when to show UI.
 * @SIGNON_POLICY_REQUEST_PASSWORD: Force the user to enter the password.
 * @SIGNON_POLICY_NO_USER_INTERACTION: No UI elements will be shown to the user.
 * @SIGNON_POLICY_VALIDATION: UI elements can be shown to the user only when
 * CAPTCHA-like security measures are required.
 *
 * UI policy for the signon process, passed to the UI plugin.
 */
typedef enum {
    SIGNON_POLICY_DEFAULT = 0,
    SIGNON_POLICY_REQUEST_PASSWORD,
    SIGNON_POLICY_NO_USER_INTERACTION,
    SIGNON_POLICY_VALIDATION,
} SignonSessionDataUiPolicy;

/**
 * SignonAuthSessionState:
 * @SIGNON_AUTH_SESSION_STATE_NOT_STARTED: No message.
 * @SIGNON_AUTH_SESSION_STATE_RESOLVING_HOST: Resolving remote server host name.
 * @SIGNON_AUTH_SESSION_STATE_CONNECTING: Connecting to remote server.
 * @SIGNON_AUTH_SESSION_STATE_SENDING_DATA: Sending data to remote server.
 * @SIGNON_AUTH_SESSION_STATE_WAITING_REPLY: Waiting reply from remote server.
 * @SIGNON_AUTH_SESSION_STATE_USER_PENDING: Waiting response from user.
 * @SIGNON_AUTH_SESSION_STATE_UI_REFRESHING: Refreshing ui request.
 * @SIGNON_AUTH_SESSION_STATE_PROCESS_PENDING: Waiting another process to start.
 * @SIGNON_AUTH_SESSION_STATE_STARTED: Authentication session is started.
 * @SIGNON_AUTH_SESSION_STATE_PROCESS_CANCELING: Canceling.current process.
 * @SIGNON_AUTH_SESSION_STATE_PROCESS_DONE: Authentication completed.
 * @SIGNON_AUTH_SESSION_STATE_CUSTOM: Custom message.
 * @SIGNON_AUTH_SESSION_STATE_LAST: Indicator for last item.
 *
 * State change signals emitted as the request processing proceeds.
 */
enum SignonAuthSessionState {
    SIGNON_AUTH_SESSION_STATE_NOT_STARTED = 0,
    SIGNON_AUTH_SESSION_STATE_RESOLVING_HOST,
    SIGNON_AUTH_SESSION_STATE_CONNECTING,
    SIGNON_AUTH_SESSION_STATE_SENDING_DATA,
    SIGNON_AUTH_SESSION_STATE_WAITING_REPLY,
    SIGNON_AUTH_SESSION_STATE_USER_PENDING,
    SIGNON_AUTH_SESSION_STATE_UI_REFRESHING,
    SIGNON_AUTH_SESSION_STATE_PROCESS_PENDING,
    SIGNON_AUTH_SESSION_STATE_STARTED,
    SIGNON_AUTH_SESSION_STATE_PROCESS_CANCELING,
    SIGNON_AUTH_SESSION_STATE_PROCESS_DONE,
    SIGNON_AUTH_SESSION_STATE_CUSTOM,
    SIGNON_AUTH_SESSION_STATE_LAST
};


/**
 * SIGNON_SESSION_DATA_UI_POLICY:
 * @see_also: #SignonSessionDataUiPolicy
 *
 * Policy for the signon process.
 */
#define SIGNON_SESSION_DATA_UI_POLICY     "UiPolicy"
/**
 * SIGNON_SESSION_DATA_CAPTION:
 *
 * Caption for the UI dialog.
 */
#define SIGNON_SESSION_DATA_CAPTION       "Caption"
/**
 * SIGNON_SESSION_DATA_TIMEOUT:
 *
 * Network timeout, in milliseconds (uint32).
 */
#define SIGNON_SESSION_DATA_TIMEOUT       "NetworkTimeout"
/**
 * SIGNON_SESSION_DATA_WINDOW_ID:
 *
 * Platform-specific window id (for dialog transiency) - uint32.
 */
#define SIGNON_SESSION_DATA_WINDOW_ID     "WindowId"
/**
 * SIGNON_SESSION_DATA_RENEW_TOKEN:
 *
 * Requests the signon plugin to obtain a new token (boolean).
 */
#define SIGNON_SESSION_DATA_RENEW_TOKEN   "RenewToken"


#define SIGNON_TYPE_AUTH_SESSION                 (signon_auth_session_get_type ())
#define SIGNON_AUTH_SESSION(obj)                 (G_TYPE_CHECK_INSTANCE_CAST ((obj), SIGNON_TYPE_AUTH_SESSION, SignonAuthSession))
#define SIGNON_AUTH_SESSION_CLASS(klass)         (G_TYPE_CHECK_CLASS_CAST ((klass), SIGNON_TYPE_AUTH_SESSION, SignonAuthSessionClass))
#define SIGNON_IS_AUTH_SESSION(obj)              (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SIGNON_TYPE_AUTH_SESSION))
#define SIGNON_IS_AUTH_SESSION_CLASS(klass)      (G_TYPE_CHECK_CLASS_TYPE ((klass), SIGNON_TYPE_AUTH_SESSION))
#define SIGNON_AUTH_SESSION_GET_CLASS(obj)       (G_TYPE_INSTANCE_GET_CLASS ((obj), SIGNON_TYPE_AUTH_SESSION, SignonAuthSessionClass))

typedef struct _SignonAuthSessionPrivate SignonAuthSessionPrivate;
typedef struct _SignonAuthSessionClass   SignonAuthSessionClass;

/**
 * SignonAuthSession:
 *
 * Opaque struct. Use the accessor functions below.
 */
struct _SignonAuthSession {
    GObject parent;

    SignonAuthSessionPrivate *priv;
};

/**
 * SignonAuthSessionClass:
 * @parent: reference to the parent class
 *
 * Opaque struct. Use the accessor functions below.
 */
struct _SignonAuthSessionClass {
    GObjectClass parent;
};

GType signon_auth_session_get_type (void) G_GNUC_CONST;

SignonAuthSession *signon_auth_session_new(gint id,
                                           const gchar *method_name,
                                           GError **err);

SignonAuthSession *
signon_auth_session_new_for_identity(SignonIdentity *identity,
                                     const gchar *method_name,
                                     GError **err);

const gchar *signon_auth_session_get_method (SignonAuthSession *self);

typedef void (*SignonAuthSessionQueryAvailableMechanismsCb) (
                    SignonAuthSession* self,
                    gchar **mechanisms,
                    const GError *error,
                    gpointer user_data);

G_GNUC_DEPRECATED
typedef SignonAuthSessionQueryAvailableMechanismsCb
    SignonAuthSessionQueryAvailableMethodsCb;

void signon_auth_session_query_available_mechanisms(SignonAuthSession *self,
                                                    const gchar **wanted_mechanisms,
                                                    SignonAuthSessionQueryAvailableMechanismsCb cb,
                                                    gpointer user_data);

#ifndef SIGNON_DISABLE_DEPRECATED
typedef void (*SignonAuthSessionProcessCb) (SignonAuthSession *self,
                                            GHashTable *session_data,
                                            const GError *error,
                                            gpointer user_data);
SIGNON_DEPRECATED_FOR(signon_auth_session_process_async)
void signon_auth_session_process(SignonAuthSession *self,
                                GHashTable *session_data,
                                const gchar *mechanism,
                                SignonAuthSessionProcessCb cb,
                                gpointer user_data);
#endif
void signon_auth_session_process_async (SignonAuthSession *self,
                                        GVariant *session_data,
                                        const gchar *mechanism,
                                        GCancellable *cancellable,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data);
GVariant *signon_auth_session_process_finish (SignonAuthSession *self,
                                              GAsyncResult *res,
                                              GError **error);

void signon_auth_session_cancel(SignonAuthSession *self);

G_END_DECLS

#endif //SIGNONAUTHSESSIONIMPL_H_
