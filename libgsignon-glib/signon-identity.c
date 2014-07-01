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
 * SECTION:signon-identity
 * @title: SignonIdentity
 * @short_description: client side presentation of a credential.
 *
 * The #SignonIdentity objects represent identities and provide operations that 
 * can be performed on them such as identity creation, removal, starting an authentication 
 * session, and so on. 
 * 
 * Identities can also be stored and retrieved from a gSSO database, in which
 * case they also contain a number of properties that can be retrieved
 * using signon_identity_query_info() and are represented via #SignonIdentityInfo.
 * Such identities are identified by a numeric id number and they are subject
 * to access control.
 * 
 * <refsect1><title>Operations on an identity</title></refsect1>
 * 
 * - a new identity can be created with signon_identity_new() or
 * signon_identity_new_with_context(). This operation does not store the
 * identity to the database, the identity is not visible to other applications,
 * and accordingly it is not subject to access control.
 * 
 * - an authentication session can be started from an identity using 
 * signon_identity_create_session() or signon_auth_session_new(). If the identity
 * has been retrieved from a database, only the authentication methods listed
 * in associated #SignonIdentityInfo are allowed to be used.
 * 
 * - identites stored in a database can be enumerated using 
 * signon_auth_service_query_identities(). Only the identites owned by the 
 * requesting application are returned.
 * 
 * - identities stored in a database can be retrieved using signon_identity_new_from_db()
 * or signon_identity_new_with_context_from_db(), subject to access control (an
 * application performing that operation has to be either the identity's owner,
 * or it has to be on the ACL list).
 * 
 * - newly created identities can be stored to the database, and identities already
 * in the database can be updated using signon_identity_store_credentials_with_info()
 * (with #SignonIdentityInfo)
 * or signon_identity_store_credentials_with_args() (with separate arguments that
 * together form the contents of #SignonIdentityInfo). Only the owners can update
 * identites.
 * 
 * - identites in the database can be removed by their owners using
 * signon_identity_remove().
 * 
 * - identity owners can request to close all authentication sessions and
 * remove all secrets and tokens using signon_identity_signout().
 * 
 * <refsect1><title>Data fields in #SignonIdentityInfo</title></refsect1>
 * 
 * These are the data fields that are stored into the database as a part of an
 * identity record using signon_identity_store_credentials_with_args() or
 * signon_identity_store_credentials_with_info() and can be retrieved using
 * signon_identity_query_info() or signon_auth_service_query_identities():
 * 
 * - Caption is a display name for the identity, presented to the user. Default
 * value is an empty caption. 
 *
 * - Realms is a list of realms that the identity can be used in.
 *   Interpretation of this field is up to the method. Typically it is
 *   a list of internet domains allowed for an authentication request.
 *   Default value is an empty list.
 * 
 * - Type is a #SignonIdentityType. Interpretation of this field is up to the application;
 * gSSO does not use it. Default value is #SIGNON_IDENTITY_TYPE_OTHER
 * 
 * - Owner is a #SignonSecurityContext object, which specifies the identity
 * owner. Owners are allowed to perform all of the operations on the identity
 * specified above. By default an identity's owner is determined by gSSO daemon
 * using system services for the system context, and a string supplied in 
 * signon_identity_new_with_context() for the application context.
 * 
 * - ACL is a list of #SignonSecurityContext objects, that specifies applications
 * that can access the identity to perform authentication sessions. They're not
 * allowed to make any changes to the identity. Default value is an empty list,
 * and depending on how gSSO is configured it's also possible to provide a list 
 * with a wildcard item to relax the access control restriction 
 * (see #SignonSecurityContext).
 * 
 * - Methods is a #GHashTable containing method names as keys, and lists of 
 * allowed mechanisms as values (also, a special value "*" means that any 
 * mechanism is allowed). Only those methods and mechanisms that are in the table
 * are allowed to be used in authentication sessions. Default is an empty list.
 * 
 * - Id is a numeric identification of the identity record in the database. The
 * application cannot set this, as it's determined by the daemon.
 * 
 * - Username is used to provide a username to authentication plugins after 
 * issuing signon_auth_session_process_async(). Applications can override this
 * by providing a username explicitly in the @session_data parameter to that 
 * function. By default there is no username.
 * 
 * - Secret is used in the same way as username, but it is write-only (cannot
 * be retrieved from a #SignonIdentityInfo). It is also possible to prevent
 * secret from being stored in the database.
 * 
 */

#include "signon-identity.h"
#include "signon-auth-session.h"
#include "signon-internals.h"
#include "signon-dbus-queue.h"
#include "signon-utils.h"
#include "signon-errors.h"
#include "sso-auth-service.h"
#include "sso-identity-gen.h"

G_DEFINE_TYPE (SignonIdentity, signon_identity, G_TYPE_OBJECT);

enum
{
    PROP_0,
    PROP_ID,
    PROP_APPCTX
};

typedef enum {
    NOT_REGISTERED,
    PENDING_REGISTRATION,
    REGISTERED,
} IdentityRegistrationState;

typedef enum  {
    DATA_UPDATED = 0,
    IDENTITY_REMOVED,
    IDENTITY_SIGNED_OUT
} RemoteIdentityState;

struct _SignonIdentityPrivate
{
    SsoIdentity *proxy;
    SsoAuthService *auth_service_proxy;
    GCancellable *cancellable;

    SignonIdentityInfo *identity_info;

    GSList *sessions;
    IdentityRegistrationState registration_state;

    gboolean removed;
    gboolean signed_out;
    gboolean updated;

    guint id;
    gchar *app_ctx;

    guint signal_info_updated;
    guint signal_unregistered;
};

enum {
    SIGNEDOUT_SIGNAL,
    REMOVED_SIGNAL,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL];

#define SIGNON_IDENTITY_PRIV(obj) (SIGNON_IDENTITY(obj)->priv)

typedef struct _IdentityStoreCredentialsCbData
{
    SignonIdentity *self;
    SignonIdentityStoreCredentialsCb cb;
    gpointer user_data;
} IdentityStoreCredentialsCbData;

typedef struct _IdentityStoreCredentialsData
{
    GVariant *info_variant;
    gpointer cb_data;
} IdentityStoreCredentialsData;

typedef enum {
    SIGNON_VERIFY_USER,
    SIGNON_VERIFY_SECRET,
    SIGNON_INFO,
    SIGNON_REMOVE,
    SIGNON_SIGNOUT
} IdentityOperation;

typedef struct _IdentitySessionCbData
{
    SignonIdentity *self;
    SignonAuthSession *session;
    SignonIdentitySessionReadyCb cb;
} IdentitySessionCbData;

typedef struct _IdentitySessionData
{
    const gchar *method;
    gpointer cb_data;
} IdentitySessionData;

typedef struct _IdentityVerifyCbData
{
    SignonIdentity *self;
    GVariant *args;
    SignonIdentityVerifyCb cb;
    gpointer user_data;
} IdentityVerifyCbData;

typedef struct _IdentityVerifyData
{
    gchar *data_to_send;
    GHashTable *params;
    IdentityOperation operation;
    gpointer cb_data;
} IdentityVerifyData;

typedef struct _IdentityInfoCbData
{
    SignonIdentity *self;
    SignonIdentityInfoCb cb;
    gpointer user_data;
} IdentityInfoCbData;

typedef struct _IdentityCredentialsUpdateCbData
{
    SignonIdentity *self;
    gchar *message;
    SignonIdentityVoidCb cb;
    gpointer user_data;
} IdentityCredentialsUpdateCbData;

typedef struct _IdentityReferenceCbData
{
    SignonIdentity *self;
    gchar *reference;
    SignonIdentityVoidCb cb;
    gpointer user_data;
} IdentityReferenceCbData;

typedef struct _IdentityVoidCbData
{
    SignonIdentity *self;
    SignonIdentityVoidCb cb;
    gpointer user_data;
} IdentityVoidCbData;

typedef struct _IdentityVoidData
{
    IdentityOperation operation;
    gpointer cb_data;
} IdentityVoidData;

static void identity_check_remote_registration (SignonIdentity *self);
static void identity_store_credentials_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_store_credentials_reply (GObject *object,
                                              GAsyncResult *res,
                                              gpointer userdata);
static void identity_verify_ready_cb (gpointer object, const GError *error, gpointer user_data);

static void identity_remove_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_credentials_update_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_signout_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_info_ready_cb (gpointer object, const GError *error, gpointer user_data);

static void identity_process_signout (SignonIdentity *self);
static void identity_process_updated (SignonIdentity *self);
static void identity_process_removed (SignonIdentity *self);
static void identity_get_auth_session_reply (GObject *object,
                                             GAsyncResult *res,
                                             gpointer userdata);
static void identity_session_ready_cb (gpointer object, const GError *error,
                                       gpointer user_data);
static void identity_session_object_destroyed_cb (gpointer data,
                                                  GObject *where_the_session_was);

static GQuark
identity_object_quark ()
{
  static GQuark quark = 0;

  if (!quark)
    quark = g_quark_from_static_string ("identity_object_quark");

  return quark;
}

static void
signon_identity_set_property (GObject *object,
                              guint property_id,
                              const GValue *value,
                              GParamSpec *pspec)
{
    SignonIdentity *self = SIGNON_IDENTITY (object);

    switch (property_id)
    {
    case PROP_ID:
        self->priv->id = g_value_get_uint (value);
        break;
    case PROP_APPCTX:
        g_free (self->priv->app_ctx);
        self->priv->app_ctx = g_strdup (g_value_get_string (value));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
signon_identity_get_property (GObject *object,
                              guint property_id,
                              GValue *value,
                              GParamSpec *pspec)
{
    SignonIdentity *self = SIGNON_IDENTITY (object);

    switch (property_id)
    {
    case PROP_ID:
        g_value_set_uint (value, self->priv->id);
        break;
    case PROP_APPCTX:
        g_value_set_string (value, self->priv->app_ctx);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
signon_identity_init (SignonIdentity *identity)
{
    SignonIdentityPrivate *priv;

    identity->priv = G_TYPE_INSTANCE_GET_PRIVATE (identity,
                                                  SIGNON_TYPE_IDENTITY,
                                                  SignonIdentityPrivate);

    priv = identity->priv;
    priv->proxy = NULL;
    priv->auth_service_proxy = sso_auth_service_get_instance();
    priv->cancellable = g_cancellable_new ();
    priv->registration_state = NOT_REGISTERED;

    priv->removed = FALSE;
    priv->signed_out = FALSE;
    priv->updated = FALSE;

    priv->app_ctx = NULL;
}

static void
signon_identity_dispose (GObject *object)
{
    SignonIdentity *identity = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = identity->priv;

    if (priv->cancellable)
    {
        g_cancellable_cancel (priv->cancellable);
        g_object_unref (priv->cancellable);
        priv->cancellable = NULL;
    }

    if (priv->identity_info)
    {
        signon_identity_info_free (priv->identity_info);
        priv->identity_info = NULL;
    }

    g_clear_object (&priv->auth_service_proxy);

    if (priv->proxy)
    {
        g_signal_handler_disconnect (priv->proxy, priv->signal_info_updated);
        g_signal_handler_disconnect (priv->proxy, priv->signal_unregistered);
        g_object_unref (priv->proxy);
        priv->proxy = NULL;
    }

    if (priv->sessions)
        g_critical ("SignonIdentity: the list of AuthSessions MUST be empty");

    G_OBJECT_CLASS (signon_identity_parent_class)->dispose (object);
}

static void
signon_identity_finalize (GObject *object)
{
    SignonIdentity *identity = SIGNON_IDENTITY (object);
    if (identity->priv->app_ctx)
    {
        g_free(identity->priv->app_ctx);
        identity->priv->app_ctx = NULL;
    }

    G_OBJECT_CLASS (signon_identity_parent_class)->finalize (object);
}

static void
signon_identity_class_init (SignonIdentityClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);
    GParamSpec *pspec;

    object_class->set_property = signon_identity_set_property;
    object_class->get_property = signon_identity_get_property;

    pspec = g_param_spec_uint ("id",
                               "Identity ID",
                               "Set/Get Identity ID",
                               0,
                               G_MAXUINT,
                               0,
                               G_PARAM_READWRITE);
    g_object_class_install_property (object_class,
                                     PROP_ID,
                                     pspec);

    pspec = g_param_spec_string ("app_ctx",
                                 "Application Context",
                                 "Set/Get Application Security Context",
                                 "",
                                 G_PARAM_READWRITE);
    g_object_class_install_property (object_class,
                                     PROP_APPCTX,
                                     pspec);

    g_type_class_add_private (object_class, sizeof (SignonIdentityPrivate));

    /**
     * SignonIdentity::signout:
     *
     * Emitted when the identity was signed out.
     */
    signals[SIGNEDOUT_SIGNAL] = g_signal_new("signout",
                                    G_TYPE_FROM_CLASS (klass),
                                    G_SIGNAL_RUN_LAST | G_SIGNAL_NO_RECURSE | G_SIGNAL_NO_HOOKS,
                                    0 /* class closure */,
                                    NULL /* accumulator */,
                                    NULL /* accu_data */,
                                    g_cclosure_marshal_VOID__VOID,
                                    G_TYPE_NONE /* return_type */,
                                    0);
    /**
     * SignonIdentity::removed:
     *
     * Emitted when the identity was removed (deleted).
     */
    signals[REMOVED_SIGNAL] = g_signal_new("removed",
                                           G_TYPE_FROM_CLASS (klass),
                                           G_SIGNAL_RUN_LAST | G_SIGNAL_NO_RECURSE | G_SIGNAL_NO_HOOKS,
                                           0,
                                           NULL,
                                           NULL,
                                           g_cclosure_marshal_VOID__VOID,
                                           G_TYPE_NONE,
                                           0);

    object_class->dispose = signon_identity_dispose;
    object_class->finalize = signon_identity_finalize;
}

static void
identity_state_changed_cb (GDBusProxy *proxy,
                           gint state,
                           gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (user_data));
    SignonIdentity *self = SIGNON_IDENTITY (user_data);

    switch (state) {
        case DATA_UPDATED:
            DEBUG ("State changed to DATA_UPDATED");
            identity_process_updated (self);
            break;
        case IDENTITY_REMOVED:
            DEBUG ("State changed to IDENTITY_REMOVED");
            identity_process_removed (self);
            break;
        case IDENTITY_SIGNED_OUT:
            DEBUG ("State changed to IDENTITY_SIGNED_OUT");
            identity_process_signout (self);
            break;
        default:
            g_critical ("wrong state value obtained from signon daemon");
    };
}

static void
identity_remote_object_destroyed_cb(GDBusProxy *proxy,
                                    gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (user_data));
    SignonIdentity *self = SIGNON_IDENTITY (user_data);

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    if (priv->proxy)
    {
        g_object_unref (priv->proxy);
        priv->proxy = NULL;
    }

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    _signon_object_not_ready(self);

    priv->registration_state = NOT_REGISTERED;

    signon_identity_info_free (priv->identity_info);
    priv->identity_info = NULL;

    priv->removed = FALSE;
    priv->signed_out = FALSE;
    priv->updated = FALSE;
}

static void
identity_registered (SignonIdentity *identity,
                     char *object_path, GVariant *identity_data,
                     GError *error)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (identity));

    SignonIdentityPrivate *priv;
    priv = identity->priv;

    g_return_if_fail (priv != NULL);

    if (!error)
    {
        GDBusConnection *connection;
        GDBusProxy *auth_service_proxy;
        const gchar *bus_name;
        GError *proxy_error = NULL;

        DEBUG("%s: %s", G_STRFUNC, object_path);
        /*
         * TODO: as Aurel will finalize the code polishing so we will
         * need to implement the refresh of the proxy to SignonIdentity
         * */
        g_return_if_fail (priv->proxy == NULL);

        auth_service_proxy = (GDBusProxy *)priv->auth_service_proxy;
        connection = g_dbus_proxy_get_connection (auth_service_proxy);
        bus_name = g_dbus_proxy_get_name (auth_service_proxy);

        priv->proxy =
            sso_identity_proxy_new_sync (connection,
                                         G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
                                         bus_name,
                                         object_path,
                                         priv->cancellable,
                                         &proxy_error);
        if (G_UNLIKELY (proxy_error != NULL))
        {
            g_warning ("Failed to initialize Identity proxy: %s",
                       proxy_error->message);
            g_clear_error (&proxy_error);
        }

        priv->signal_info_updated =
            g_signal_connect (priv->proxy,
                              "info-updated",
                              G_CALLBACK (identity_state_changed_cb),
                              identity);

        priv->signal_unregistered =
            g_signal_connect (priv->proxy,
                              "unregistered",
                              G_CALLBACK (identity_remote_object_destroyed_cb),
                              identity);

        if (identity_data)
        {
            DEBUG("%s: ", G_STRFUNC);
            priv->identity_info =
                signon_identity_info_new_from_variant (identity_data);
            g_variant_unref (identity_data);
        }

        priv->updated = TRUE;
    }
    else
        g_warning ("%s: %s", G_STRFUNC, error->message);

    /*
     * execute queued operations or emit errors on each of them
     * */
    priv->registration_state = REGISTERED;

    /*
     * TODO: if we will add a new state for identity: "INVALID"
     * consider emission of another error, like "invalid"
     * */
    _signon_object_ready (identity, identity_object_quark (), error);

    /*
     * as the registration failed we do not
     * request for new registration, but emit
     * same error again and again
     * */
}

/**
 * signon_identity_get_last_error:
 * @identity: the #SignonIdentity.
 *
 * Get the most recent error that occurred on @identity.
 *
 * Returns: a #GError containing the most recent error, or %NULL on failure.
 */
const GError *
signon_identity_get_last_error (SignonIdentity *identity)
{
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);
    return _signon_object_last_error(identity);
}

static void
identity_new_cb (GObject *object, GAsyncResult *res,
                 gpointer userdata)
{
    SignonIdentity *identity = (SignonIdentity*)userdata;
    SsoAuthService *proxy = SSO_AUTH_SERVICE (object);
    gchar *object_path = NULL;
    GError *error = NULL;

    g_return_if_fail (identity != NULL);
    DEBUG ("%s", G_STRFUNC);

    sso_auth_service_call_register_new_identity_finish (proxy,
                                                        &object_path,
                                                        res,
                                                        &error);
    if (SIGNON_IS_NOT_CANCELLED (error))
    {
        identity_registered (identity, object_path, NULL, error);
    }
    if (object_path) g_free (object_path);
    g_clear_error (&error);
}

static void
identity_new_from_db_cb (GObject *object, GAsyncResult *res,
                         gpointer userdata)
{
    SignonIdentity *identity = (SignonIdentity*)userdata;
    SsoAuthService *proxy = SSO_AUTH_SERVICE (object);
    gchar *object_path = NULL;
    GVariant *identity_data;
    GError *error = NULL;

    g_return_if_fail (identity != NULL);
    DEBUG ("%s", G_STRFUNC);

    sso_auth_service_call_get_identity_finish (proxy,
                                               &object_path,
                                               &identity_data,
                                               res,
                                               &error);
    if (SIGNON_IS_NOT_CANCELLED (error))
    {
        identity_registered (identity, object_path, identity_data, error);
    }
    if (object_path) g_free (object_path);
    g_clear_error (&error);
}

static void
identity_check_remote_registration (SignonIdentity *self)
{
    g_return_if_fail (self != NULL);
    SignonIdentityPrivate *priv = self->priv;

    g_return_if_fail (priv != NULL);

    if (priv->registration_state != NOT_REGISTERED)
        return;

    if (priv->id != 0)
        sso_auth_service_call_get_identity (priv->auth_service_proxy,
                                            priv->id,
                                            priv->app_ctx,
                                            priv->cancellable,
                                            identity_new_from_db_cb,
                                            self);
    else
        sso_auth_service_call_register_new_identity (priv->auth_service_proxy,
                                                     priv->app_ctx,
                                                     priv->cancellable,
                                                     identity_new_cb,
                                                     self);

    priv->registration_state = PENDING_REGISTRATION;
}

/**
 * signon_identity_new_from_db:
 * @id: identity ID.
 *
 * Construct an identity object associated with an existing identity
 * record.
 * This is essentially equivalent to calling
 * signon_identity_new_with_context_from_db() and passing %NULL as the
 * application context.
 * 
 * Applications can determine the @id either by enumerating the identities with 
 * signon_auth_service_query_identities() (if they're the owner of the identity) 
 * or via other means (such as the system's accounts service, or an application 
 * configuration).
 * 
 * Returns: an instance of a #SignonIdentity.
 */
SignonIdentity *
signon_identity_new_from_db (guint32 id)
{
    return signon_identity_new_with_context_from_db (id, NULL);
}

/**
 * signon_identity_new_with_context_from_db:
 * @id: identity ID.
 * @application_context: application security context, can be %NULL.
 *
 * Construct an identity object associated with an existing identity
 * record. See #SignonSecurityContext for a discussion of @application_context contents.
 * Together with the system context it is used to determine by the gSSO daemon 
 * if the application can access the identity (the application needs to be either the 
 * identity's owner or to be present on the ACL).
 * 
 * Applications can determine the @id either by enumerating the identities with 
 * signon_auth_service_query_identities() (if they're the owner of the identity) 
 * or via other means (such as the system's accounts service, or an application 
 * configuration).
 * 
 * Returns: an instance of a #SignonIdentity.
 */
SignonIdentity*
signon_identity_new_with_context_from_db (guint32 id, const gchar *application_context)
{
    SignonIdentity *identity;
    DEBUG ("%s %d: %d\n", G_STRFUNC, __LINE__, id);
    if (id == 0)
        return NULL;

    identity = g_object_new (SIGNON_TYPE_IDENTITY,
                             "id", id,
                             "app_ctx", application_context,
                             NULL);
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);
    g_return_val_if_fail (identity->priv != NULL, NULL);

    identity->priv->id = id;
    identity->priv->app_ctx = (application_context) ?
        g_strdup (application_context) : g_strdup ("");
    identity_check_remote_registration (identity);

    return identity;
}

/**
 * signon_identity_new:
 *
 * Construct a new, empty, identity object.
 * This is essentially equivalent to calling signon_identity_new_with_context()
 * and passing %NULL as the application context.
 *
 * Returns: an instance of an #SignonIdentity.
 */
SignonIdentity *
signon_identity_new ()
{
    return signon_identity_new_with_context (NULL);
}

/**
 * signon_identity_new_with_context:
 * @application_context: application security context, can be %NULL.
 *
 * Construct a new, empty, identity object. See #SignonSecurityContext for a 
 * discussion of @application_context contents. @application_context is used to set the identity's owner
 * if the identity is stored to the database with signon_identity_store_credentials_with_args()
 * or signon_identity_store_credentials_with_info().
 *
 * Returns: an instance of an #SignonIdentity.
 */
SignonIdentity*
signon_identity_new_with_context (const gchar *application_context)
{
    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    SignonIdentity *identity = g_object_new (
                                     SIGNON_TYPE_IDENTITY,
                                     "app_ctx", application_context,
                                     NULL);
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);
    g_return_val_if_fail (identity->priv != NULL, NULL);

    identity->priv->app_ctx = (application_context) ?
        g_strdup (application_context) : g_strdup ("");
    identity_check_remote_registration (identity);

    return identity;
}

/**
 * signon_identity_create_session:
 * @self: the #SignonIdentity.
 * @method: authentication method.
 * @error: pointer to a location which will receive the error, if any.
 *
 * Creates an authentication session for this identity. If the identity has been
 * retrieved from the database, the authentication method must be one of those 
 * listed in signon_identity_info_get_methods(), otherwise it can be any method
 * supported by gSSO.
 *
 * Returns: (transfer full): a new #SignonAuthSession.
 */
SignonAuthSession *
signon_identity_create_session(SignonIdentity *self,
                               const gchar *method,
                               GError **error)
{
    g_return_val_if_fail (SIGNON_IS_IDENTITY (self), NULL);

    SignonIdentityPrivate *priv = self->priv;
    g_return_val_if_fail (priv != NULL, NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    if (method == NULL)
    {
        DEBUG ("NULL method as input. Aborting.");
        g_set_error(error,
                    signon_error_quark(),
                    SIGNON_ERROR_UNKNOWN,
                    "NULL input method.");
        return NULL;
    }

    GSList *list = priv->sessions;
    while (list)
    {
        SignonAuthSession *session = SIGNON_AUTH_SESSION (priv->sessions->data);
        const gchar *sessionMethod = signon_auth_session_get_method (session);
        if (g_strcmp0(sessionMethod, method) == 0)
        {
            DEBUG ("Auth Session with method `%s` already created.", method);
            g_set_error (error,
                         signon_error_quark(),
                         SIGNON_ERROR_METHOD_NOT_AVAILABLE,
                         "Authentication session for this method already requested.");
            return NULL;
        }

        list = list->next;
    }

    SignonAuthSession *session =
        signon_auth_session_new_for_identity (self,
                                              method,
                                              error);
    if (session)
    {
        DEBUG ("%s %d - success", G_STRFUNC, __LINE__);
        priv->sessions = g_slist_append(priv->sessions, session);
        g_object_weak_ref (G_OBJECT(session),
                           identity_session_object_destroyed_cb,
                           self);
        /*
         * if you want to delete the identity
         * you MUST delete all authsessions
         * first
         * */
        g_object_ref (self);
        priv->signed_out = FALSE;
    }

    return session;
}

/**
 * signon_identity_store_credentials_with_info:
 * @self: the #SignonIdentity.
 * @info: the #SignonIdentityInfo data to store.
 * @cb: (scope async): callback.
 * @user_data: user_data.
 *
 * Stores the data contained in @info into the identity record in the database.
 * See above for the detailed discussion of the meaning of various fields and
 * their defaults.
 */
void
signon_identity_store_credentials_with_info(SignonIdentity *self,
                                            const SignonIdentityInfo *info,
                                            SignonIdentityStoreCredentialsCb cb,
                                            gpointer user_data)
{
    IdentityStoreCredentialsCbData *cb_data;
    IdentityStoreCredentialsData *operation_data;

    DEBUG ();
    g_return_if_fail (SIGNON_IS_IDENTITY (self));
    g_return_if_fail (info != NULL);

    SignonIdentityPrivate *priv = self->priv;
    SignonIdentityInfo *new_info = signon_identity_info_copy (info);
    if (priv->identity_info)
        signon_identity_info_free (priv->identity_info);
    priv->identity_info = new_info;

    cb_data = g_slice_new0 (IdentityStoreCredentialsCbData);
    cb_data->self = self;
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    operation_data = g_slice_new0 (IdentityStoreCredentialsData);
    operation_data->info_variant =
        signon_identity_info_to_variant (priv->identity_info);
    operation_data->cb_data = cb_data;

    identity_check_remote_registration (self);
    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_store_credentials_ready_cb,
                                    operation_data);
}

/**
 * signon_identity_store_credentials_with_args:
 * @self: the #SignonIdentity.
 * @username: (allow-none): username.
 * @secret: (allow-none): secret.
 * @store_secret: whether gSSO should save the password in secret storage.
 * @methods: (transfer none) (element-type utf8 GStrv): allowed methods.
 * @caption: (allow-none): caption.
 * @realms: (allow-none): allowed realms.
 * @owner: (allow-none): owner.
 * @access_control_list: (allow-none): access control list.
 * @type: the type of the identity.
 * @cb: (scope async): callback.
 * @user_data: user_data.
 *
 * Stores the given data into the identity. See above for the meaning
 * of the specific fields.
 */
void signon_identity_store_credentials_with_args(SignonIdentity *self,
                                                 const gchar *username,
                                                 const gchar *secret,
                                                 const gboolean store_secret,
                                                 GHashTable *methods,
                                                 const gchar *caption,
                                                 const gchar* const *realms,
                                                 const SignonSecurityContext *owner,
                                                 SignonSecurityContextList *access_control_list,
                                                 SignonIdentityType type,
                                                 SignonIdentityStoreCredentialsCb cb,
                                                 gpointer user_data)
{
    SignonIdentityInfo *info;

    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    info = signon_identity_info_new ();
    signon_identity_info_set_username (info, username);
    signon_identity_info_set_secret (info, secret, store_secret);
    signon_identity_info_set_methods (info, methods);
    signon_identity_info_set_caption (info, caption);
    signon_identity_info_set_realms (info, realms);
    if (owner)
    {
        signon_identity_info_set_owner (info, owner);
    }
    if (access_control_list)
    {
        signon_identity_info_set_access_control_list (info,
                                                      access_control_list);
    }
    signon_identity_info_set_identity_type (info, type);

    signon_identity_store_credentials_with_info (self, info, cb, user_data);
    signon_identity_info_free (info);
}

static void
identity_store_credentials_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    IdentityStoreCredentialsData *operation_data =
        (IdentityStoreCredentialsData *)user_data;
    g_return_if_fail (operation_data != NULL);

    IdentityStoreCredentialsCbData *cb_data = operation_data->cb_data;
    g_return_if_fail (cb_data != NULL);

    if (error)
    {
        DEBUG ("IdentityError: %s", error->message);

        if (cb_data->cb)
        {
            (cb_data->cb) (self, 0, error, cb_data->user_data);
        }

        g_slice_free (IdentityStoreCredentialsCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);

        sso_identity_call_store (priv->proxy,
                                 operation_data->info_variant,
                                 priv->cancellable,
                                 identity_store_credentials_reply,
                                 cb_data);
    }

    g_slice_free (IdentityStoreCredentialsData, operation_data);
}

static void
identity_store_credentials_reply (GObject *object, GAsyncResult *res,
                                  gpointer userdata)
{
    IdentityStoreCredentialsCbData *cb_data = (IdentityStoreCredentialsCbData *)userdata;
    SsoIdentity *proxy = SSO_IDENTITY (object);
    guint id;
    GError *error = NULL;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    SignonIdentityPrivate *priv = cb_data->self->priv;

    sso_identity_call_store_finish (proxy, &id, res, &error);

    if (error == NULL)
    {
        g_return_if_fail (priv->identity_info == NULL);

        g_object_set (cb_data->self, "id", id, NULL);
        cb_data->self->priv->id = id;

        /*
         * if the previous state was REMOVED
         * then we need to reset it
         * */
        priv->removed = FALSE;
    }

    if (SIGNON_IS_NOT_CANCELLED (error) && cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, id, error, cb_data->user_data);
    }

    g_clear_error(&error);
    g_slice_free (IdentityStoreCredentialsCbData, cb_data);
}

static void
identity_verify_reply (GObject *object, GAsyncResult *res,
                       gpointer userdata)
{
    SsoIdentity *proxy = SSO_IDENTITY (object);
    gboolean valid;
    GError *error = NULL;
    IdentityVerifyCbData *cb_data = (IdentityVerifyCbData *)userdata;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);

    sso_identity_call_verify_user_finish (proxy, &valid, res, &error);

    if (SIGNON_IS_NOT_CANCELLED (error) && cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, valid, error, cb_data->user_data);
    }

    g_clear_error(&error);
    g_variant_unref (cb_data->args);
    g_slice_free (IdentityVerifyCbData, cb_data);
}

static void
identity_verify_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    IdentityVerifyCbData *cb_data = (IdentityVerifyCbData *)user_data;
    g_return_if_fail (cb_data != NULL);

    if (priv->removed == TRUE)
    {
        GError *new_error = g_error_new (signon_error_quark(),
                                         SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                         "Already removed from database.");

        if (cb_data->cb)
        {
            (cb_data->cb) (self, FALSE, new_error, cb_data->user_data);
        }

        g_error_free (new_error);
        g_variant_unref (cb_data->args);
        g_slice_free (IdentityVerifyCbData, cb_data);
    }
    else if (error)
    {
        DEBUG ("IdentityError: %s", error->message);

        if (cb_data->cb)
        {
            (cb_data->cb) (self, FALSE, error, cb_data->user_data);
        }

        g_variant_unref (cb_data->args);
        g_slice_free (IdentityVerifyCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);

        sso_identity_call_verify_user (priv->proxy,
                                       cb_data->args,
                                       priv->cancellable,
                                       identity_verify_reply,
                                       cb_data);
    }
}

/**
 * signon_identity_verify_user:
 * @self: the #SignonIdentity.
 * @args: optional extra arguments (vardict) controlling SignOn UI.
 * @cb: (scope async): callback.
 * @user_data: user_data.
 *
 * Asks user to enter his credentials to verify the current user.
 */
void signon_identity_verify_user(SignonIdentity *self,
                                 GVariant *args,
                                 SignonIdentityVerifyCb cb,
                                 gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    IdentityVerifyCbData *cb_data = g_slice_new0 (IdentityVerifyCbData);
    cb_data->self = self;
    cb_data->args = g_variant_ref_sink (args);
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    identity_check_remote_registration (self);
    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_verify_ready_cb,
                                    cb_data);
}

static void
identity_process_updated (SignonIdentity *self)
{
    DEBUG ("%d %s", __LINE__, __func__);

    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv->proxy != NULL);

    signon_identity_info_free (priv->identity_info);
    priv->identity_info = NULL;
    priv->updated = FALSE;

    DEBUG ("%s info freed, to be updated", __func__);
}

static void
identity_process_removed (SignonIdentity *self)
{
    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    DEBUG ("%d %s", __LINE__, __func__);

    SignonIdentityPrivate *priv = self->priv;

    if (priv->removed == TRUE)
        return;

    priv->removed = TRUE;
    signon_identity_info_free (priv->identity_info);
    priv->identity_info = NULL;

    g_object_set (self, "id", 0, NULL);
    priv->id = 0;
    g_signal_emit(G_OBJECT(self), signals[REMOVED_SIGNAL], 0);
}

static void
identity_process_signout(SignonIdentity *self)
{
    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    DEBUG ("%d %s", __LINE__, __func__);
    SignonIdentityPrivate *priv = self->priv;

    if (priv->signed_out == TRUE)
        return;

    GSList *llink = priv->sessions;
    while (llink)
    {
        GSList *next = llink->next;
        g_object_unref (G_OBJECT(llink->data));
        llink = next;
    }

    priv->signed_out = TRUE;
    g_signal_emit(G_OBJECT(self), signals[SIGNEDOUT_SIGNAL], 0);
}

/*
 * TODO: fix the implementation
 * of signond: it returns result = TRUE
 * in ANY CASE
 * */
static void
identity_signout_reply (GObject *object, GAsyncResult *res,
                        gpointer userdata)
{
    SsoIdentity *proxy = SSO_IDENTITY (object);
    gboolean result;
    GError *error = NULL;
    IdentityVoidCbData *cb_data = (IdentityVoidCbData *)userdata;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    sso_identity_call_sign_out_finish (proxy, &result, res, &error);

    if (SIGNON_IS_NOT_CANCELLED (error) && cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, error, cb_data->user_data);
    }

    g_clear_error(&error);
    g_slice_free (IdentityVoidCbData, cb_data);
}

static void
identity_credentials_updated_reply (GObject *object, GAsyncResult *res,
                                    gpointer userdata)
{
    SsoIdentity *proxy = SSO_IDENTITY (object);
    guint result;
    GError *error = NULL;
    IdentityCredentialsUpdateCbData *cb_data =
        (IdentityCredentialsUpdateCbData *)userdata;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    sso_identity_call_request_credentials_update_finish (proxy, &result,
                                                         res, &error);
    if (SIGNON_IS_NOT_CANCELLED (error) && cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, error, cb_data->user_data);
    }

    g_clear_error (&error);
    g_free (cb_data->message);
    g_slice_free (IdentityCredentialsUpdateCbData, cb_data);
}

static void
identity_removed_reply (GObject *object, GAsyncResult *res,
                        gpointer userdata)
{
    SsoIdentity *proxy = SSO_IDENTITY (object);
    GError *error = NULL;
    IdentityVoidCbData *cb_data = (IdentityVoidCbData *)userdata;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    sso_identity_call_remove_finish (proxy, res, &error);

    if (SIGNON_IS_NOT_CANCELLED (error) && cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, error, cb_data->user_data);
    }

    g_clear_error(&error);
    g_slice_free (IdentityVoidCbData, cb_data);
}

static void
identity_info_reply(GObject *object, GAsyncResult *res,
                    gpointer userdata)
{
    SsoIdentity *proxy = SSO_IDENTITY (object);
    GVariant *identity_data = NULL;
    DEBUG ("%d %s", __LINE__, __func__);

    GError *error = NULL;
    IdentityInfoCbData *cb_data = (IdentityInfoCbData *)userdata;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    SignonIdentityPrivate *priv = cb_data->self->priv;

    sso_identity_call_get_info_finish (proxy, &identity_data, res, &error);

    if (identity_data != NULL)
    {
        priv->identity_info =
                signon_identity_info_new_from_variant (identity_data);
        g_variant_unref (identity_data);
    }

    if (SIGNON_IS_NOT_CANCELLED (error) && cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, priv->identity_info, error, cb_data->user_data);
    }

    g_clear_error(&error);
    g_slice_free (IdentityInfoCbData, cb_data);

    priv->updated = TRUE;
}

static void
identity_info_ready_cb(gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    IdentityVoidData *operation_data =
        (IdentityVoidData *)user_data;
    g_return_if_fail (operation_data != NULL);

    IdentityInfoCbData *cb_data = operation_data->cb_data;
    g_return_if_fail (cb_data != NULL);

    if (priv->removed == TRUE)
    {
        DEBUG ("%s identity removed", G_STRFUNC);

        GError *new_error = g_error_new (signon_error_quark(),
                                         SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                         "Already removed from database.");
        if (cb_data->cb)
            (cb_data->cb) (self, NULL, new_error, cb_data->user_data);

        g_error_free (new_error);
    }
    else if (error || priv->id == 0)
    {
        DEBUG ("%s identity is new", G_STRFUNC);

        if (error)
            DEBUG ("IdentityError: %s", error->message);
        else
            DEBUG ("Identity is not stored and has no info yet");

        if (cb_data->cb)
            (cb_data->cb) (self, NULL, error, cb_data->user_data);
    }
    else if (priv->updated == FALSE)
    {
        DEBUG ("%s identity needs update, call daemon", G_STRFUNC);

        g_return_if_fail (priv->proxy != NULL);
        sso_identity_call_get_info (priv->proxy,
                                    priv->cancellable,
                                    identity_info_reply,
                                    cb_data);
        goto free_op_data;
    }
    else
    {
        DEBUG ("%s pass existing one", G_STRFUNC);

        if (cb_data->cb)
            (cb_data->cb) (self, priv->identity_info, error, cb_data->user_data);
    }

    g_slice_free (IdentityInfoCbData, cb_data);

free_op_data:
    g_slice_free (IdentityVoidData, operation_data);
}

static void
identity_signout_ready_cb(gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    IdentityVoidCbData *cb_data = (IdentityVoidCbData *)user_data;

    g_return_if_fail (cb_data != NULL);

    if (priv->removed == TRUE)
    {
        GError *new_error = g_error_new (signon_error_quark(),
                                         SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                         "Already removed from database.");
        if (cb_data->cb)
        {
            (cb_data->cb) (self, new_error, cb_data->user_data);
        }

        g_error_free (new_error);
        g_slice_free (IdentityVoidCbData, cb_data);
    }
    else if (error)
    {
        DEBUG ("IdentityError: %s", error->message);
        if (cb_data->cb)
        {
            (cb_data->cb) (self, error, cb_data->user_data);
        }

        g_slice_free (IdentityVoidCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);
        sso_identity_call_sign_out (priv->proxy,
                                    priv->cancellable,
                                    identity_signout_reply,
                                    cb_data);
    }
}

static void
identity_remove_ready_cb(gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    IdentityVoidCbData *cb_data = (IdentityVoidCbData *)user_data;
    g_return_if_fail (cb_data != NULL);

    if (priv->removed == TRUE)
    {
        GError *new_error = g_error_new (signon_error_quark(),
                                          SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                         "Already removed from database.");
        if (cb_data->cb)
        {
            (cb_data->cb) (self, new_error, cb_data->user_data);
        }

        g_error_free (new_error);
        g_slice_free (IdentityVoidCbData, cb_data);
    }
    else if (error)
    {
        DEBUG ("IdentityError: %s", error->message);
        if (cb_data->cb)
        {
            (cb_data->cb) (self, error, cb_data->user_data);
        }

        g_slice_free (IdentityVoidCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);
        sso_identity_call_remove (priv->proxy,
                                  priv->cancellable,
                                  identity_removed_reply,
                                  cb_data);
    }
}

void static
identity_credentials_update_ready_cb(gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    IdentityCredentialsUpdateCbData *cb_data =
        (IdentityCredentialsUpdateCbData *)user_data;
    g_return_if_fail (cb_data != NULL);

    if (priv->removed == TRUE)
    {
        GError *new_error = g_error_new (signon_error_quark(),
                                         SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                         "Already removed from database.");
        if (cb_data->cb)
        {
            (cb_data->cb) (self, new_error, cb_data->user_data);
        }

        g_error_free (new_error);
        g_free (cb_data->message);
        g_slice_free (IdentityCredentialsUpdateCbData, cb_data);
    }
    if (error)
    {
        DEBUG ("IdentityError: %s", error->message);

        if (cb_data->cb)
        {
            (cb_data->cb) (self, error, cb_data->user_data);
        }

        g_free (cb_data->message);
        g_slice_free (IdentityCredentialsUpdateCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);
        sso_identity_call_request_credentials_update (priv->proxy,
                                                      cb_data->message,
                                                      priv->cancellable,
                                                      identity_credentials_updated_reply,
                                                      cb_data);
    }
}

void static
identity_void_operation(SignonIdentity *self,
                        gint operation,
                        gpointer cb_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    IdentityVoidData *operation_data = g_slice_new0 (IdentityVoidData);
    operation_data->cb_data = cb_data;
    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_info_ready_cb,
                                    operation_data);
}

static void
identity_reference_added_reply (GObject *object, GAsyncResult *res,
                        gpointer userdata)
{
    SsoIdentity *proxy = SSO_IDENTITY (object);
    gint result;
    GError *error = NULL;
    IdentityReferenceCbData *cb_data = (IdentityReferenceCbData *)userdata;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    sso_identity_call_add_reference_finish (proxy, &result, res, &error);

    if (SIGNON_IS_NOT_CANCELLED (error) && cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, error, cb_data->user_data);
    }

    g_clear_error(&error);
    g_free (cb_data->reference);
    g_slice_free (IdentityReferenceCbData, cb_data);
}

static void
identity_reference_removed_reply (GObject *object, GAsyncResult *res,
                        gpointer userdata)
{
    SsoIdentity *proxy = SSO_IDENTITY (object);
    gint result;
    GError *error = NULL;
    IdentityReferenceCbData *cb_data = (IdentityReferenceCbData *)userdata;

    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    sso_identity_call_remove_reference_finish (proxy, &result, res, &error);

    if (SIGNON_IS_NOT_CANCELLED (error) && cb_data->cb)
    {
        (cb_data->cb) (cb_data->self, error, cb_data->user_data);
    }

    g_clear_error(&error);
    g_free (cb_data->reference);
    g_slice_free (IdentityReferenceCbData, cb_data);
}

static void
identity_add_reference_ready_cb(gpointer object, const GError *error,
    gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    IdentityReferenceCbData *cb_data = (IdentityReferenceCbData *)user_data;
    g_return_if_fail (cb_data != NULL);

    if (priv->removed == TRUE)
    {
        GError *new_error = g_error_new (signon_error_quark(),
                                          SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                         "Already removed from database.");
        if (cb_data->cb)
        {
            (cb_data->cb) (self, new_error, cb_data->user_data);
        }

        g_error_free (new_error);
        g_free (cb_data->reference);
        g_slice_free (IdentityReferenceCbData, cb_data);
    }
    else if (error)
    {
        DEBUG ("IdentityError: %s", error->message);
        if (cb_data->cb)
        {
            (cb_data->cb) (self, error, cb_data->user_data);
        }

        g_free (cb_data->reference);
        g_slice_free (IdentityReferenceCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);
        sso_identity_call_add_reference (priv->proxy,
                                  cb_data->reference,
                                  priv->cancellable,
                                  identity_reference_added_reply,
                                  cb_data);
    }
}

static void
identity_remove_reference_ready_cb(gpointer object, const GError *error,
    gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    IdentityReferenceCbData *cb_data = (IdentityReferenceCbData *)user_data;
    g_return_if_fail (cb_data != NULL);

    if (priv->removed == TRUE)
    {
        GError *new_error = g_error_new (signon_error_quark(),
                                          SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                         "Already removed from database.");
        if (cb_data->cb)
        {
            (cb_data->cb) (self, new_error, cb_data->user_data);
        }

        g_error_free (new_error);
        g_free (cb_data->reference);
        g_slice_free (IdentityReferenceCbData, cb_data);
    }
    else if (error)
    {
        DEBUG ("IdentityError: %s", error->message);
        if (cb_data->cb)
        {
            (cb_data->cb) (self, error, cb_data->user_data);
        }
        g_free (cb_data->reference);
        g_slice_free (IdentityReferenceCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);
        sso_identity_call_remove_reference (priv->proxy,
                                  cb_data->reference,
                                  priv->cancellable,
                                  identity_reference_removed_reply,
                                  cb_data);
    }
}

/**
 * signon_identity_remove:
 * @self: the #SignonIdentity.
 * @cb: (scope async): callback to be called when the operation has completed.
 * @user_data: user_data to pass to the callback.
 *
 * Removes the corresponding credentials record from the database.
 */
void signon_identity_remove(SignonIdentity *self,
                           SignonIdentityRemovedCb cb,
                           gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    IdentityVoidCbData *cb_data = g_slice_new0 (IdentityVoidCbData);
    cb_data->self = self;
    cb_data->cb = (SignonIdentityVoidCb)cb;
    cb_data->user_data = user_data;

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    identity_check_remote_registration (self);
    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_remove_ready_cb,
                                    cb_data);
}

/**
 * signon_identity_request_credentials_update:
 * @self: the #SignonIdentity.
 * @message: message to be displayed to the user.
 * @cb: (scope async): callback to be called when the operation has completed.
 * @user_data: user_data to pass to the callback.
 *
 * Requests user to re-enter his credentials.
 */
void signon_identity_request_credentials_update(SignonIdentity *self,
                                                const gchar *message,
                                                SignonIdentityCredentialsUpdatedCb cb,
                                                gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    IdentityCredentialsUpdateCbData *cb_data =
        g_slice_new0 (IdentityCredentialsUpdateCbData);
    cb_data->self = self;
    cb_data->message = g_strdup (message);
    cb_data->cb = (SignonIdentityVoidCb)cb;
    cb_data->user_data = user_data;

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    identity_check_remote_registration (self);
    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_credentials_update_ready_cb,
                                    cb_data);
}

/**
 * signon_identity_signout:
 * @self: the #SignonIdentity.
 * @cb: (scope async): callback.
 * @user_data: user_data.
 *
 * Asks signond to close all authentication sessions for this
 * identity, and to remove any stored secrets associated with it (password and
 * authentication tokens).
 */
void signon_identity_signout(SignonIdentity *self,
                             SignonIdentitySignedOutCb cb,
                             gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    IdentityVoidCbData *cb_data = g_slice_new0 (IdentityVoidCbData);
    cb_data->self = self;
    cb_data->cb = (SignonIdentityVoidCb)cb;
    cb_data->user_data = user_data;

    identity_check_remote_registration (self);
    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_signout_ready_cb,
                                    cb_data);
}

/**
 * signon_identity_add_reference:
 * @self: the #SignonIdentity.
 * @reference: reference to be added
 * @cb: callback
 * @user_data: user_data.
 *
 * Adds named reference to identity. Not currently supported by gSSO.
 */
void signon_identity_add_reference(SignonIdentity *self,
                             const gchar *reference,
                             SignonIdentityReferenceAddedCb cb,
                             gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    IdentityReferenceCbData *cb_data = g_slice_new0 (IdentityReferenceCbData);
    cb_data->self = self;
    cb_data->reference = g_strdup (reference);
    cb_data->cb = (SignonIdentityVoidCb)cb;
    cb_data->user_data = user_data;

    identity_check_remote_registration (self);
    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_add_reference_ready_cb,
                                    cb_data);
}

/**
 * signon_identity_remove_reference:
 * @self: the #SignonIdentity.
 * @reference: reference to be removed
 * @cb: callback
 * @user_data: user_data.
 *
 * Removes named reference from identity. Not currently supported by gSSO.
 */
void signon_identity_remove_reference(SignonIdentity *self,
                             const gchar *reference,
                             SignonIdentityReferenceRemovedCb cb,
                             gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    IdentityReferenceCbData *cb_data = g_slice_new0 (IdentityReferenceCbData);
    cb_data->self = self;
    cb_data->reference = g_strdup (reference);
    cb_data->cb = (SignonIdentityVoidCb)cb;
    cb_data->user_data = user_data;

    identity_check_remote_registration (self);
    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_remove_reference_ready_cb,
                                    cb_data);
}

/**
 * signon_identity_query_info:
 * @self: the #SignonIdentity.
 * @cb: (scope async): callback.
 * @user_data: user_data.
 *
 * Fetches the #SignonIdentityInfo data associated with this
 * identity.
 */
void signon_identity_query_info(SignonIdentity *self,
                                SignonIdentityInfoCb cb,
                                gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    IdentityInfoCbData *cb_data = g_slice_new0 (IdentityInfoCbData);
    cb_data->self = self;
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    identity_check_remote_registration (self);
    identity_void_operation(self,
                            SIGNON_INFO,
                            cb_data);
}

static void
identity_get_auth_session_reply (GObject *object, GAsyncResult *res,
                                 gpointer userdata)
{
    SsoIdentity *proxy = SSO_IDENTITY (object);
    gchar *object_path = NULL;
    GError *error = NULL;

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    sso_identity_call_get_auth_session_finish (proxy,
                                               &object_path,
                                               res,
                                               &error);

    IdentitySessionCbData *cb_data = (IdentitySessionCbData *) userdata;
    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->cb != NULL);

    if (SIGNON_IS_NOT_CANCELLED (error))
    {
        (cb_data->cb) (cb_data->session,
                error,
                g_dbus_proxy_get_connection ((GDBusProxy *)proxy),
                g_dbus_proxy_get_name ((GDBusProxy *)proxy),
                object_path);
    }
    g_slice_free (IdentitySessionCbData, cb_data);
    if (object_path) g_free (object_path);
    g_clear_error (&error);
}

static void
identity_session_ready_cb(gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));
    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    IdentitySessionData *operation_data = (IdentitySessionData *) user_data;
    g_return_if_fail (operation_data != NULL);

    IdentitySessionCbData *cb_data = operation_data->cb_data;
    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->cb != NULL);

    if (error)
    {
        (cb_data->cb) (cb_data->session, (GError *)error, NULL, NULL, NULL);
    }
    else if (priv->removed == TRUE)
    {
        GError *new_error = g_error_new (signon_error_quark(),
                                         SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                         "Already removed from database.");
        (cb_data->cb) (cb_data->session, new_error, NULL, NULL, NULL);
        g_error_free (new_error);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);

        sso_identity_call_get_auth_session (
            priv->proxy,
            operation_data->method,
            priv->cancellable,
            identity_get_auth_session_reply,
            cb_data);
    }

    g_slice_free (IdentitySessionData, operation_data);
}

static void
identity_session_object_destroyed_cb(gpointer data,
                                     GObject *where_the_session_was)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (data));
    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    SignonIdentity *self = SIGNON_IDENTITY (data);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    priv->sessions = g_slist_remove(priv->sessions, (gpointer)where_the_session_was);
    g_object_unref (self);
}

//FIXME: is this a private method?
/**
 * signon_identity_get_auth_session:
 * @self: the #SignonIdentity.
 * @session: the #SignonAuthSession object to get the remote object for.
 * @method: method name for the session.
 * @cb: (scope async): completion callback.
 *
 * Obtain a remote object for a local session object. Should not be used by
 * applications.
 */
void signon_identity_get_auth_session (SignonIdentity *self,
                                       SignonAuthSession *session,
                                       const gchar *method,
                                       SignonIdentitySessionReadyCb cb)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (self));
    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    IdentitySessionCbData *cb_data = g_slice_new0 (IdentitySessionCbData);
    cb_data->self = self;
    cb_data->session = session;
    cb_data->cb = cb;

    IdentitySessionData *operation_data = g_slice_new0 (IdentitySessionData);
    operation_data->method = method;
    operation_data->cb_data = cb_data;

    identity_check_remote_registration (self);
    _signon_object_call_when_ready (self,
                                    identity_object_quark(),
                                    identity_session_ready_cb,
                                    operation_data);
}

