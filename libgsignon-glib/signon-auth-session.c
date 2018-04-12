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

/**
 * SECTION:signon-auth-session
 * @title: SignonAuthSession
 * @short_description: the authentication session object
 *
 * The #SignonAuthSession object is responsible for handling the client
 * authentication. #SignonAuthSession objects should be created from existing
 * identities (via signon_identity_create_session() or by passing a non-NULL identity
 * to signon_auth_session_new()).
 */

#include "signon-internals.h"
#include "signon-auth-session.h"
#include "signon-dbus-queue.h"
#include "signon-errors.h"
#include "signon-marshal.h"
#include "signon-utils.h"
#include "signon-identity.h"
#include "sso-auth-service.h"
#include "sso-auth-session-gen.h"


G_DEFINE_TYPE (SignonAuthSession, signon_auth_session, G_TYPE_OBJECT);

enum
{
    PROP_0,
    PROP_IDENTITY,
    PROP_APPCTX
};

/* Signals */
enum
{
    STATE_CHANGED,
    LAST_SIGNAL
};

static guint auth_session_signals[LAST_SIGNAL] = { 0 };
static const gchar auth_session_process_pending_message[] =
    "The request is added to queue.";

struct _SignonAuthSessionPrivate
{
    SsoAuthSession *proxy;
    SignonIdentity *identity;
    GCancellable *cancellable;

    guint id;
    gchar *method_name;

    gboolean registering;
    gboolean busy;
    gboolean canceled;
    gboolean dispose_has_run;

    guint signal_state_changed;
    guint signal_unregistered;
};

typedef struct _AuthSessionQueryAvailableMechanismsData
{
    gchar **wanted_mechanisms;
    gpointer cb_data;
} AuthSessionQueryAvailableMechanismsData;

typedef struct _AuthSessionProcessData
{
    GVariant *session_data;
    gchar *mechanism;
    GCancellable *cancellable;
} AuthSessionProcessData;

typedef struct _AuthSessionQueryAvailableMechanismsCbData
{
    SignonAuthSession *self;
    SignonAuthSessionQueryAvailableMechanismsCb cb;
    gpointer user_data;
} AuthSessionQueryAvailableMechanismsCbData;

typedef struct _AuthSessionProcessCbData
{
    SignonAuthSessionProcessCb cb;
    gpointer user_data;
} AuthSessionProcessCbData;

#define SIGNON_AUTH_SESSION_PRIV(obj) (SIGNON_AUTH_SESSION(obj)->priv)
#define SIGNON_AUTH_SESSION_GET_PRIV(obj) (G_TYPE_INSTANCE_GET_PRIVATE ((obj), SIGNON_TYPE_AUTH_SESSION, SignonAuthSessionPrivate))


static void auth_session_state_changed_cb (GDBusProxy *proxy, gint state, gchar *message, gpointer user_data);
static void auth_session_remote_object_destroyed_cb (GDBusProxy *proxy, gpointer user_data);

static gboolean auth_session_priv_init (SignonAuthSession *self, const gchar *method_name, GError **err);

static void auth_session_query_available_mechanisms_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void auth_session_cancel_ready_cb (gpointer object, const GError *error, gpointer user_data);

static void auth_session_check_remote_object(SignonAuthSession *self);

static void
auth_session_process_data_free (AuthSessionProcessData *process_data)
{
    g_free (process_data->mechanism);
    g_variant_unref (process_data->session_data);
    g_slice_free (AuthSessionProcessData, process_data);
}

static void
auth_session_process_reply (GObject *object, GAsyncResult *res,
                            gpointer userdata)
{
    SignonAuthSession *self;
    SsoAuthSession *proxy = SSO_AUTH_SESSION (object);
    GTask *task = G_TASK (userdata);
    GVariant *reply;
    GError *error = NULL;

    g_return_if_fail (task != NULL);
    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    sso_auth_session_call_process_finish (proxy, &reply, res, &error);

    self = SIGNON_AUTH_SESSION (g_async_result_get_source_object (
        (GAsyncResult *)task));
    self->priv->busy = FALSE;

    if (G_LIKELY (error == NULL))
    {
        g_task_return_pointer (task, reply, (GDestroyNotify) g_variant_unref);
    }
    else
    {
        g_task_return_error (task, error);
    }

    g_object_unref (task);
    g_object_unref (self);
}

static void
auth_session_process_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv;
    GTask *task = G_TASK (user_data);
    AuthSessionProcessData *process_data;

    g_return_if_fail (self != NULL);
    priv = self->priv;

    if (error != NULL)
    {
        GError *error_copy = g_error_copy (error);
        DEBUG ("AuthSessionError: %s", error_copy->message);
        g_task_return_error (task, error_copy);
        g_object_unref (task);
        return;
    }

    if (priv->canceled)
    {
        priv->busy = FALSE;
        priv->canceled = FALSE;
        g_task_return_new_error (task, signon_error_quark (),
                                 SIGNON_ERROR_SESSION_CANCELED,
                                 "Authentication session was canceled");
        g_object_unref (task);
        return;
    }

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    process_data = g_task_get_task_data (task);
    g_return_if_fail (process_data != NULL);

    sso_auth_session_call_process (priv->proxy,
                                   process_data->session_data,
                                   process_data->mechanism,
                                   process_data->cancellable,
                                   auth_session_process_reply,
                                   task);
}

static void
process_async_cb_wrapper (GObject *object, GAsyncResult *res,
                          gpointer user_data)
{
    AuthSessionProcessCbData *cb_data = user_data;
    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    GVariant *v_reply;
    GHashTable *reply = NULL;
    GError *error = NULL;
    gboolean cancelled;

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    v_reply = signon_auth_session_process_finish (self, res, &error);

    cancelled = error != NULL &&
        error->domain == G_IO_ERROR &&
        error->code == G_IO_ERROR_CANCELLED;

    /* Do not invoke the callback if the operation was cancelled */
    if (cb_data->cb != NULL && !cancelled)
    {
        if (v_reply != NULL)
            reply = signon_hash_table_from_variant (v_reply);

        cb_data->cb (self, reply, error, cb_data->user_data);
    }
    g_variant_unref (v_reply);

    g_slice_free (AuthSessionProcessCbData, cb_data);
    g_clear_error (&error);
}

static GQuark
auth_session_object_quark (void)
{
  static GQuark quark = 0;

  if (!quark)
    quark = g_quark_from_static_string ("auth_session_object_quark");

  return quark;
}

static void
signon_auth_session_set_property (GObject *object,
                                  guint property_id,
                                  const GValue *value,
                                  GParamSpec *pspec)
{
    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);

    switch (property_id)
    {
        case PROP_IDENTITY:
            self->priv->identity = g_value_dup_object (value);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }
}

static void
signon_auth_session_get_property (GObject *object,
                                  guint property_id,
                                  GValue *value,
                                  GParamSpec *pspec)
{
    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);

    switch (property_id)
    {
        case PROP_IDENTITY:
            g_value_set_object (value, self->priv->identity);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }
}

static void
signon_auth_session_init (SignonAuthSession *self)
{
    self->priv = SIGNON_AUTH_SESSION_GET_PRIV (self);
    self->priv->cancellable = g_cancellable_new ();
}

static void
signon_auth_session_dispose (GObject *object)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    if (priv->dispose_has_run)
        return;

    if (priv->cancellable)
    {
        g_cancellable_cancel (priv->cancellable);
        g_object_unref (priv->cancellable);
        priv->cancellable = NULL;
    }

    if (priv->proxy)
    {
        g_signal_handler_disconnect (priv->proxy, priv->signal_state_changed);
        g_signal_handler_disconnect (priv->proxy, priv->signal_unregistered);
        g_object_unref (priv->proxy);

        priv->proxy = NULL;
    }

    G_OBJECT_CLASS (signon_auth_session_parent_class)->dispose (object);

    priv->dispose_has_run = TRUE;
}

static void
signon_auth_session_finalize (GObject *object)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION(object));

    SignonAuthSession *self = SIGNON_AUTH_SESSION(object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    g_free (priv->method_name);
    g_object_unref (priv->identity);

    G_OBJECT_CLASS (signon_auth_session_parent_class)->finalize (object);
}

static void
signon_auth_session_class_init (SignonAuthSessionClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);
    GParamSpec *pspec;

    object_class->set_property = signon_auth_session_set_property;
    object_class->get_property = signon_auth_session_get_property;

    pspec = g_param_spec_object ("identity",
                                 "Identity Object",
                                 "Identity Object construct parameter",
                                 SIGNON_TYPE_IDENTITY,
                                 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class,
                                     PROP_IDENTITY,
                                     pspec);

    g_type_class_add_private (object_class, sizeof (SignonAuthSessionPrivate));

    /**
     * SignonAuthSession::state-changed:
     * @auth_session: the #SignonAuthSession
     * @state: the current state of the #SignonAuthSession
     * @message: the message associated with the state change
     *
     * Emitted when the state of the #SignonAuthSession changes. The state change
     * is initiated by #GSignondPlugin via #GSignondPlugin::status-changed signal.
     */
    /* FIXME: @state should be registered as a GLib type (or use one from
     * libgsignond-common)
     */
    auth_session_signals[STATE_CHANGED] =
            g_signal_new ("state-changed",
                          G_TYPE_FROM_CLASS (klass),
                          G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
                          0,
                          NULL,
                          NULL,
                          _signon_marshal_VOID__INT_STRING,
                          G_TYPE_NONE, 2,
                          G_TYPE_INT,
                          G_TYPE_STRING);

    object_class->dispose = signon_auth_session_dispose;
    object_class->finalize = signon_auth_session_finalize;
}

/**
 * signon_auth_session_new:
 * @id: the id of the #SignonIdentity to be used. Can be 0, if this session is
 * not bound to any stored identity.
 * @method_name: the name of the authentication method to be used.
 * @err: a pointer to a location which will contain the error, in case this
 * function fails.
 *
 * Creates a new #SignonAuthSession, which can be used to authenticate using
 * the specified method.
 *
 * Returns: a new #SignonAuthSession.
 */
SignonAuthSession *
signon_auth_session_new (gint id,
                         const gchar *method_name,
                         GError **err)
{
    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    SignonIdentity *identity = (id == 0) ?
        signon_identity_new () : signon_identity_new_from_db (id);
    g_return_val_if_fail (identity, NULL);

    SignonAuthSession *self =
        signon_auth_session_new_for_identity (identity, method_name, err);
    g_object_unref (identity);

    return self;
}

/**
 * signon_auth_session_new_for_identity:
 * @identity: #SignonIdentity parent object.
 * @method_name: the name of the authentication method to be used.
 * @err: a pointer to a location which will contain the error, in case this
 * function fails.
 *
 * Creates a new #SignonAuthSession, which can be used to authenticate using
 * the specified method.
 *
 * Returns: a new #SignonAuthSession.
 */
SignonAuthSession *
signon_auth_session_new_for_identity (SignonIdentity *identity,
                                      const gchar *method_name,
                                      GError **err)
{
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    SignonAuthSession *self = SIGNON_AUTH_SESSION(g_object_new (
                                     SIGNON_TYPE_AUTH_SESSION,
                                     "identity", identity,
                                     NULL));
    g_return_val_if_fail (self != NULL, NULL);

    if (!auth_session_priv_init(self, method_name, err))
    {
        if (*err)
            g_warning ("%s returned error: %s", G_STRFUNC, (*err)->message);

        g_object_unref (self);
        return NULL;
    }

    return self;
}

/**
 * signon_auth_session_get_method:
 * @self: the #SignonAuthSession.
 *
 * Get the current authentication method.
 *
 * Returns: the authentication method being used, or %NULL on failure.
 */
const gchar *
signon_auth_session_get_method (SignonAuthSession *self)
{
    g_return_val_if_fail (SIGNON_IS_AUTH_SESSION (self), NULL);
    SignonAuthSessionPrivate *priv = self->priv;

    g_return_val_if_fail (priv != NULL, NULL);

    return priv->method_name;
}

/**
 * SignonAuthSessionQueryAvailableMechanismsCb:
 * @self: the #SignonAuthSession.
 * @mechanisms: (transfer full) (type GStrv): list of available mechanisms.
 * @error: a #GError if an error occurred, %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * Callback to be passed to signon_auth_session_query_available_mechanisms().
 */

/**
 * signon_auth_session_query_available_mechanisms:
 * @self: the #SignonAuthSession.
 * @wanted_mechanisms: a %NULL-terminated list of mechanisms supported by the client.
 * @cb: (scope async): a callback which will be called with the result.
 * @user_data: user data to be passed to the callback.
 *
 * Queries the mechanisms available for this authentication session. The result
 * will be the intersection between @wanted_mechanisms and the mechanisms
 * supported by the authentication plugin (and allowed by the #SignonIdentity that this
 * session belongs to).
 */
void
signon_auth_session_query_available_mechanisms (SignonAuthSession *self,
                                                const gchar **wanted_mechanisms,
                                                SignonAuthSessionQueryAvailableMechanismsCb cb,
                                                gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (self));
    SignonAuthSessionPrivate* priv = self->priv;

    g_return_if_fail (priv != NULL);

    AuthSessionQueryAvailableMechanismsCbData *cb_data = g_slice_new0 (AuthSessionQueryAvailableMechanismsCbData);
    cb_data->self = self;
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    AuthSessionQueryAvailableMechanismsData *operation_data = g_slice_new0 (AuthSessionQueryAvailableMechanismsData);
    operation_data->wanted_mechanisms = g_strdupv ((gchar **)wanted_mechanisms);
    operation_data->cb_data = cb_data;

    auth_session_check_remote_object(self);
    _signon_object_call_when_ready (self,
                                    auth_session_object_quark(),
                                    auth_session_query_available_mechanisms_ready_cb,
                                    operation_data);
}

/**
 * SignonAuthSessionProcessCb:
 * @self: the #SignonAuthSession.
 * @session_data: (transfer full) (element-type utf8 GValue): a dictionary with
 * the response.
 * @error: a #GError if an error occurred, %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * This callback is invoked when the authentication plugin delivers the result
 * of the signon_auth_session_process() operation.
 */

/**
 * signon_auth_session_process:
 * @self: the #SignonAuthSession.
 * @session_data: (transfer none) (element-type utf8 GValue): a dictionary of parameters.
 * @mechanism: the authentication mechanism to be used.
 * @cb: (scope async): a callback which will be called with the result.
 * @user_data: user data to be passed to the callback.
 *
 * Performs one step of the authentication process. If the #SignonIdentity that
 * this session belongs to contains a username and a password, they will be also 
 * passed to the authentication plugin, otherwise they should be set directly in
 * @session_data.
 * @session_data should be used to add additional authentication parameters to the
 * session, or to override the parameters otherwise taken from the identity.
 *
 * Deprecated: 1.8: Use signon_auth_session_process_async() instead.
 */
void
signon_auth_session_process (SignonAuthSession *self,
                             GHashTable *session_data,
                             const gchar* mechanism,
                             SignonAuthSessionProcessCb cb,
                             gpointer user_data)
{
    GVariant *v_session_data;

    g_return_if_fail (SIGNON_IS_AUTH_SESSION (self));
    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    AuthSessionProcessCbData *cb_data = g_slice_new0 (AuthSessionProcessCbData);
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    v_session_data = signon_hash_table_to_variant (session_data);

    signon_auth_session_process_async (self, v_session_data, mechanism, NULL,
                                       process_async_cb_wrapper, cb_data);
}

/**
 * signon_auth_session_process_async:
 * @self: the #SignonAuthSession.
 * @session_data: (transfer full): a dictionary of parameters.
 * @mechanism: the authentication mechanism to be used.
 * @cancellable: (allow-none): optional #GCancellable object, %NULL to ignore.
 * @callback: (scope async): a callback which will be called when the
 * authentication reply is available.
 * @user_data: user data to be passed to the callback.
 *
 * Performs one step of the authentication process.
 * @session_data should be used to add additional authentication parameters to the
 * session.
 * 
 * What specific parameters should be used can be found from authentication plugins'
 * documentation (look for parameters that are expected in gsignond_plugin_request_initial()
 * for the first step, and parameters that are expected in gsignond_plugin_request() for
 * the subsequent steps). See, for example, #GSignondPasswordPlugin and #GSignondDigestPlugin.
 * 
 * If the #SignonIdentity that this session belongs to contains a username and a password, 
 * the daemon will pass them to the authentication plugin, otherwise they should be set directly in
 * @session_data. The daemon also passes a list of identity's allowed realms to the plugin,
 * and they cannot be overriden.
 *
 * Since: 1.8
 */
void
signon_auth_session_process_async (SignonAuthSession *self,
                                   GVariant *session_data,
                                   const gchar *mechanism,
                                   GCancellable *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data)
{
    SignonAuthSessionPrivate *priv;
    GTask *task;
    AuthSessionProcessData *process_data;

    g_return_if_fail (session_data != NULL);
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (self));
    priv = self->priv;

    task = g_task_new (self, cancellable, callback, user_data);

    process_data = g_slice_new0 (AuthSessionProcessData);
    process_data->session_data = g_variant_ref_sink (session_data);
    process_data->mechanism = g_strdup (mechanism);
    process_data->cancellable = cancellable;
    g_task_set_task_data (task, process_data, (GDestroyNotify) auth_session_process_data_free);

    priv->busy = TRUE;

    auth_session_check_remote_object(self);
    _signon_object_call_when_ready (self,
                                    auth_session_object_quark(),
                                    auth_session_process_ready_cb,
                                    task);
}

/**
 * signon_auth_session_process_finish:
 * @self: the #SignonAuthSession.
 * @res: A #GAsyncResult obtained from the #GAsyncReadyCallback passed to
 * signon_auth_session_process_async().
 * @error: return location for error, or %NULL.
 *
 * Collect the result of the signon_auth_session_process_async() operation.
 *
 * Returns: a #GVariant of type %G_VARIANT_TYPE_VARDICT containing the
 * authentication reply. As with signon_auth_session_process_async(), specific
 * parameters contained in the #GVariant can be found from plugins' documentation:
 * #GSignondPlugin::response-final for the final response, and #GSignondPlugin::response
 * for the intermediate responses. See, for example, #GSignondPasswordPlugin 
 * and #GSignondDigestPlugin.
 *
 * Since: 1.8
 */
GVariant *
signon_auth_session_process_finish (SignonAuthSession *self, GAsyncResult *res,
                                    GError **error)
{
    g_return_val_if_fail (g_task_is_valid (res, self), NULL);

    return g_task_propagate_pointer (G_TASK (res), error);
}

/**
 * signon_auth_session_cancel:
 * @self: the #SignonAuthSession.
 *
 * Cancel the authentication session.
 */
void
signon_auth_session_cancel (SignonAuthSession *self)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (self));
    SignonAuthSessionPrivate *priv = self->priv;

    g_return_if_fail (priv != NULL);

    auth_session_check_remote_object(self);

    if (!priv->busy)
        return;

    priv->canceled = TRUE;
    _signon_object_call_when_ready (self,
                                    auth_session_object_quark(),
                                    auth_session_cancel_ready_cb,
                                    NULL);
}

static void
auth_session_state_changed_cb (GDBusProxy *proxy,
                               gint state,
                               gchar *message,
                               gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (user_data));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (user_data);

    g_signal_emit ((GObject *)self,
                    auth_session_signals[STATE_CHANGED],
                    0,
                    state,
                    message);
}

static void auth_session_remote_object_destroyed_cb (GDBusProxy *proxy,
                                                     gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (user_data));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (user_data);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);
    DEBUG ("remote object unregistered");

    if (priv->proxy)
    {
        g_object_unref (priv->proxy);
        priv->proxy = NULL;
    }

    /*
     * as remote object is destroyed only
     * when the session core is destroyed,
     * so there should not be any processes
     * running
     * */
    priv->busy = FALSE;
    priv->canceled = FALSE;
    _signon_object_not_ready(self);
}

static gboolean
auth_session_priv_init (SignonAuthSession *self,
                        const gchar *method_name, GError **err)
{
    g_return_val_if_fail (SIGNON_IS_AUTH_SESSION (self), FALSE);
    SignonAuthSessionPrivate *priv = SIGNON_AUTH_SESSION_PRIV (self);
    g_return_val_if_fail (priv, FALSE);

    priv->method_name = g_strdup (method_name);

    priv->registering = FALSE;
    priv->busy = FALSE;
    priv->canceled = FALSE;
    return TRUE;
}

static void
auth_session_query_mechanisms_reply (GObject *object, GAsyncResult *res,
                                     gpointer userdata)
{
    SsoAuthSession *proxy = SSO_AUTH_SESSION (object);
    gchar **mechanisms = NULL;
    GError *error = NULL;
    AuthSessionQueryAvailableMechanismsCbData *cb_data =
        (AuthSessionQueryAvailableMechanismsCbData *)userdata;
    g_return_if_fail (cb_data != NULL);

    sso_auth_session_call_query_available_mechanisms_finish (proxy,
                                                             &mechanisms,
                                                             res,
                                                             &error);
    if (SIGNON_IS_NOT_CANCELLED (error))
    {
        (cb_data->cb) (cb_data->self, mechanisms, error, cb_data->user_data);
    }

    g_clear_error (&error);
    g_slice_free (AuthSessionQueryAvailableMechanismsCbData, cb_data);
}

static void
auth_session_query_available_mechanisms_ready_cb (gpointer object, const GError *error,
                                                  gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    AuthSessionQueryAvailableMechanismsData *operation_data =
        (AuthSessionQueryAvailableMechanismsData *)user_data;
    g_return_if_fail (operation_data != NULL);

    AuthSessionQueryAvailableMechanismsCbData *cb_data = operation_data->cb_data;
    g_return_if_fail (cb_data != NULL);

    if (error)
    {
        (cb_data->cb)
            (self, NULL, error, cb_data->user_data);

        g_slice_free (AuthSessionQueryAvailableMechanismsCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);
        sso_auth_session_call_query_available_mechanisms (
            priv->proxy,
            (const char **)operation_data->wanted_mechanisms,
            priv->cancellable,
            auth_session_query_mechanisms_reply,
            cb_data);

        g_signal_emit (self,
                       auth_session_signals[STATE_CHANGED],
                       0,
                       SIGNON_AUTH_SESSION_STATE_PROCESS_PENDING,
                       auth_session_process_pending_message);
    }

    g_strfreev (operation_data->wanted_mechanisms);
    g_slice_free (AuthSessionQueryAvailableMechanismsData, operation_data);
}

static void
auth_session_cancel_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));
    g_return_if_fail (user_data == NULL);

    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    if (error)
    {
        //TODO: in general this function does not return any values,
        // that is why I think it should not emit anything for this particular case
        DEBUG("error during initialization");
    }
    else if (priv->proxy && priv->busy)
        sso_auth_session_call_cancel_sync (priv->proxy,
                                           priv->cancellable,
                                           NULL);

    priv->busy = FALSE;
    priv->canceled = FALSE;
}

static void
signon_auth_session_complete (SignonAuthSession *self,
                              GError *error,
                              GDBusConnection *connection,
                              const gchar *bus_name,
                              const gchar *object_path)
{
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    priv->registering = FALSE;
    if (!g_strcmp0(object_path, "") || error)
    {
        if (error)
            DEBUG ("Error message is %s", error->message);
        else
            error = g_error_new (signon_error_quark(),
                                 SIGNON_ERROR_RUNTIME,
                                 "Cannot create remote AuthSession object");
    }
    else
    {
        GError *proxy_error = NULL;

        priv->proxy =
            sso_auth_session_proxy_new_sync (connection,
                                             G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
                                             bus_name,
                                             object_path,
                                             priv->cancellable,
                                             &proxy_error);
        if (G_UNLIKELY (proxy_error != NULL))
        {
            g_warning ("Failed to initialize AuthSession proxy: %s",
                       proxy_error->message);
            g_clear_error (&proxy_error);
        }

        g_dbus_proxy_set_default_timeout ((GDBusProxy *)priv->proxy,
                                          G_MAXINT);

        priv->signal_state_changed =
            g_signal_connect (priv->proxy,
                              "state-changed",
                              G_CALLBACK (auth_session_state_changed_cb),
                              self);

        priv->signal_unregistered =
           g_signal_connect (priv->proxy,
                             "unregistered",
                             G_CALLBACK (auth_session_remote_object_destroyed_cb),
                             self);
    }

    DEBUG ("Object path received: %s", object_path);
    _signon_object_ready (self, auth_session_object_quark (), error);
}

static void
auth_session_check_remote_object(SignonAuthSession *self)
{
    g_return_if_fail (self != NULL);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    if (priv->proxy != NULL)
        return;

    g_return_if_fail (priv->identity != NULL);

    if (!priv->registering)
    {
        DEBUG ("%s %d", G_STRFUNC, __LINE__);

        priv->registering = TRUE;
        signon_identity_get_auth_session (priv->identity,
                                          self,
                                          priv->method_name,
                                          signon_auth_session_complete);

    }
}

