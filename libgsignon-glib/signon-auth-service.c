/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libgsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2012 Canonical Ltd.
 * Copyright (C) 2014 Intel Corporation.
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
 * SECTION:signon-auth-service
 * @title: SignonAuthService
 * @short_description: the authorization service object
 *
 * The #SignonAuthService is the main object in this library. It provides top-level
 * functions to query existing identities, available methods and their mechanisms.
 */

#include "signon-auth-service.h"
#include "signon-errors.h"
#include "signon-internals.h"
#include "sso-auth-service.h"
#include <gio/gio.h>
#include <glib.h>

G_DEFINE_TYPE (SignonAuthService, signon_auth_service, G_TYPE_OBJECT);

struct _SignonAuthServicePrivate
{
    SsoAuthService *proxy;
    GCancellable *cancellable;
};

typedef struct _MethodCbData
{
    SignonAuthService *service;
    SignonQueryMethodsCb cb;
    gpointer userdata;
} MethodCbData;

typedef struct _MechanismCbData
{
    SignonAuthService *service;
    SignonQueryMechanismCb cb;
    gpointer userdata;
    gchar *method;
} MechanismCbData;

typedef struct _IdentityCbData
{
    SignonAuthService *service;
    SignonQueryIdentitiesCb cb;
    gpointer userdata;
} IdentityCbData;

typedef struct _ClearCbData
{
    SignonAuthService *service;
    SignonClearCb cb;
    gpointer userdata;
} ClearCbData;

#define SIGNON_AUTH_SERVICE_PRIV(obj) (SIGNON_AUTH_SERVICE(obj)->priv)

static void
signon_auth_service_init (SignonAuthService *auth_service)
{
    SignonAuthServicePrivate *priv;

    priv = G_TYPE_INSTANCE_GET_PRIVATE (auth_service, SIGNON_TYPE_AUTH_SERVICE,
                                        SignonAuthServicePrivate);
    auth_service->priv = priv;

    /* Create the proxy */
    priv->cancellable = g_cancellable_new ();
    priv->proxy = sso_auth_service_get_instance ();
}

static void
signon_auth_service_dispose (GObject *object)
{
    SignonAuthService *auth_service = SIGNON_AUTH_SERVICE (object);
    SignonAuthServicePrivate *priv = auth_service->priv;

    if (priv->cancellable)
    {
        g_cancellable_cancel (priv->cancellable);
        g_object_unref (priv->cancellable);
        priv->cancellable = NULL;
    }

    if (priv->proxy)
    {
        g_object_unref (priv->proxy);
        priv->proxy = NULL;
    }

    G_OBJECT_CLASS (signon_auth_service_parent_class)->dispose (object);
}

static void
signon_auth_service_finalize (GObject *object)
{
    G_OBJECT_CLASS (signon_auth_service_parent_class)->finalize (object);
}

static void
signon_auth_service_class_init (SignonAuthServiceClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (SignonAuthServicePrivate));

    object_class->dispose = signon_auth_service_dispose;
    object_class->finalize = signon_auth_service_finalize;
}

/**
 * signon_auth_service_new:
 *
 * Create a new #SignonAuthService.
 *
 * Returns: an instance of an #SignonAuthService.
 */
SignonAuthService *
signon_auth_service_new (void)
{
    return g_object_new (SIGNON_TYPE_AUTH_SERVICE, NULL);
}

static void
auth_query_methods_cb (GObject *object, GAsyncResult *res,
                       gpointer user_data)
{
    SsoAuthService *proxy = SSO_AUTH_SERVICE (object);
    MethodCbData *data = (MethodCbData*)user_data;
    gchar **value = NULL;
    GError *error = NULL;

    g_return_if_fail (data != NULL);

    sso_auth_service_call_query_methods_finish (proxy, &value,
                                                res, &error);
    (data->cb)
        (data->service, value, error, data->userdata);

    g_clear_error (&error);
    g_slice_free (MethodCbData, data);
}

static void
auth_query_mechanisms_cb (GObject *object, GAsyncResult *res,
                          gpointer user_data)
{
    SsoAuthService *proxy = SSO_AUTH_SERVICE (object);
    MechanismCbData *data = (MechanismCbData*) user_data;
    gchar **value = NULL;
    GError *error = NULL;

    g_return_if_fail (data != NULL);

    sso_auth_service_call_query_mechanisms_finish (proxy, &value,
                                                   res, &error);
    (data->cb)
        (data->service, data->method, value, error, data->userdata);

    if (error)
        g_error_free (error);
    g_free (data->method);
    g_slice_free (MechanismCbData, data);
}

/**
 * SignonQueryMethodsCb:
 * @auth_service: the #SignonAuthService.
 * @methods: (transfer full) (type GStrv): list of available methods.
 * @error: a #GError if an error occurred, %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * Callback to be passed to signon_auth_service_query_methods().
 */

/**
 * signon_auth_service_query_methods:
 * @auth_service: the #SignonAuthService.
 * @cb: (scope async): callback to be invoked.
 * @user_data: user data.
 *
 * Lists all the available authentication methods.
 */
void
signon_auth_service_query_methods (SignonAuthService *auth_service,
                                   SignonQueryMethodsCb cb,
                                   gpointer user_data)
{
    SignonAuthServicePrivate *priv;

    g_return_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service));
    g_return_if_fail (cb != NULL);
    priv = SIGNON_AUTH_SERVICE_PRIV (auth_service);

    MethodCbData *cb_data;
    cb_data = g_slice_new (MethodCbData);
    cb_data->service = auth_service;
    cb_data->cb = cb;
    cb_data->userdata = user_data;

    sso_auth_service_call_query_methods (priv->proxy,
                                         priv->cancellable,
                                         auth_query_methods_cb,
                                         cb_data);
}

/**
 * SignonQueryMechanismCb:
 * @auth_service: the #SignonAuthService.
 * @method: the authentication method being inspected.
 * @mechanisms: (transfer full) (type GStrv): list of available mechanisms.
 * @error: a #GError if an error occurred, %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * Callback to be passed to signon_auth_service_query_mechanisms().
 */

/**
 * signon_auth_service_query_mechanisms:
 * @auth_service: the #SignonAuthService.
 * @method: the name of the method whose mechanisms must be
 * retrieved.
 * @cb: (scope async): callback to be invoked.
 * @user_data: user data.
 *
 * Lists all the available mechanisms for an authentication method.
 */
void
signon_auth_service_query_mechanisms (SignonAuthService *auth_service,
                                      const gchar *method,
                                      SignonQueryMechanismCb cb,
                                      gpointer user_data)
{
    SignonAuthServicePrivate *priv;

    g_return_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service));
    g_return_if_fail (cb != NULL);
    priv = SIGNON_AUTH_SERVICE_PRIV (auth_service);

    MechanismCbData *cb_data;
    cb_data = g_slice_new (MechanismCbData);
    cb_data->service = auth_service;
    cb_data->cb = cb;
    cb_data->userdata = user_data;
    cb_data->method = g_strdup (method);

    sso_auth_service_call_query_mechanisms (priv->proxy,
                                            method,
                                            priv->cancellable,
                                            auth_query_mechanisms_cb,
                                            cb_data);
}

static void
auth_query_identities_cb (GObject *object, GAsyncResult *res,
                          gpointer user_data)
{
    SsoAuthService *proxy = SSO_AUTH_SERVICE (object);
    IdentityCbData *data = (IdentityCbData *) user_data;
    GVariant *value = NULL;
    GError *error = NULL;
    GVariantIter iter;
    GVariant *identity_var;
    GList *identity_list = NULL;

    g_return_if_fail (data != NULL);

    sso_auth_service_call_query_identities_finish (proxy,
                                                   &value,
                                                   res,
                                                   &error);

    if (value && !error)
    {
        g_variant_iter_init (&iter, value);
        while (g_variant_iter_next (&iter, "@a{sv}", &identity_var))
        {
            identity_list = 
                g_list_append (identity_list,
                               signon_identity_info_new_from_variant (identity_var));
            g_variant_unref (identity_var);
        }
    }
    (data->cb)
        (data->service, identity_list, error, data->userdata);

    if (error)
        g_error_free (error);
    g_slice_free (IdentityCbData, data);
}

/**
 * SignonQueryIdentitiesCb:
 * @auth_service: the #SignonAuthService.
 * @identities: (element-type SignonIdentity): #GList based list of #SignonIdentityInfo.
 * @error: a #GError if an error occurred, %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * Callback to be passed to signon_auth_service_query_identities().
 */

/**
 * signon_auth_service_query_identities:
 * @auth_service: the #SignonAuthService.
 * @filter: (element-type utf8 GVariant): filter variant dictionary based on #GHashTable.
 * @application_context: application security context, can be %NULL.
 * @cb: (scope async): callback to be invoked.
 * @user_data: user data.
 *
 * Query available identities, possibly applying a filter. 
 *
 * @filter is a #GHashTable that contains filter conditions in the form of 
 * string keys and #GVariant values. Currently the following keys are supported:
 * 
 * - "Owner". The value should be a #SignonSecurityContext (use 
 * signon_security_context_build_variant() to create a #GVariant). 
 * Identites whose owner doesn't match will be filtered out. This key has
 * effect only if the requesting application is a keychain application as determined
 * by #GSignondAccessControlManager.
 * - "Type". The value should be a #SignonIdentityType.
 * - "Caption". The value is a string, and only those identites whose caption
 * begins with the supplied value will be returned.
 * 
 * The meaning of @application_context is explained in #SignonSecurityContext.
 * It is used by #GSignondAccessControlManager to determine if the requesting 
 * application is a keychain application. If it is, then all identites will be
 * returned (subject to "Owner" key in @filter). If it's not, then only the
 * identites which the application owns will be returned (but "Type" and "Caption"
 * can still be set in the @filter).
 * 
 */
/*
 * //FIXME: @filter should come with setters and getters!
 */
void
signon_auth_service_query_identities (SignonAuthService *auth_service,
                                      GHashTable *filter,
                                      const gchar *application_context,
                                      SignonQueryIdentitiesCb cb,
                                      gpointer user_data)
{
    SignonAuthServicePrivate *priv;
    GVariantBuilder builder;
    GHashTableIter iter;
    const gchar *key;
    GVariant *value;
    GVariant *filter_var;

    g_return_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service));
    g_return_if_fail (cb != NULL);
    priv = SIGNON_AUTH_SERVICE_PRIV (auth_service);

    IdentityCbData *cb_data;
    cb_data = g_slice_new (IdentityCbData);
    cb_data->service = auth_service;
    cb_data->cb = cb;
    cb_data->userdata = user_data;

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
    if (filter)
    {
        g_hash_table_iter_init (&iter, filter);
        while (g_hash_table_iter_next (&iter,
                                       (gpointer) &key,
                                       (gpointer) &value))
            g_variant_builder_add (&builder, "{sv}", key, value);
    }
    filter_var = g_variant_builder_end (&builder);

    if (!application_context)
        application_context = "";

    sso_auth_service_call_query_identities (priv->proxy,
                                            filter_var,
                                            application_context,
                                            priv->cancellable,
                                            auth_query_identities_cb,
                                            cb_data);
}


static void
auth_clear_cb (GObject *object, GAsyncResult *res, gpointer user_data)
{
    SsoAuthService *proxy = SSO_AUTH_SERVICE (object);
    ClearCbData *data = (ClearCbData*)user_data;
    gboolean value = FALSE;
    GError *error = NULL;

    g_return_if_fail (data != NULL);

    sso_auth_service_call_clear_finish (proxy, &value, res, &error);
    (data->cb)
        (data->service, value, error, data->userdata);

    g_clear_error (&error);
    g_slice_free (ClearCbData, data);
}

/**
 * SignonClearCb:
 * @auth_service: the #SignonAuthService.
 * @success: TRUE if clear succeeded.
 * @error: a #GError if an error occurred, %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * Callback to be passed to signon_auth_service_clear().
 */

/**
 * signon_auth_service_clear:
 * @auth_service: the #SignonAuthService.
 * @cb: (scope async): callback to be invoked.
 * @user_data: user data.
 *
 * Clears / wipes out all stored data.
 */
void
signon_auth_service_clear (SignonAuthService *auth_service,
                           SignonClearCb cb,
                           gpointer user_data)
{
    SignonAuthServicePrivate *priv;

    g_return_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service));
    g_return_if_fail (cb != NULL);
    priv = SIGNON_AUTH_SERVICE_PRIV (auth_service);

    ClearCbData *cb_data;
    cb_data = g_slice_new (ClearCbData);
    cb_data->service = auth_service;
    cb_data->cb = cb;
    cb_data->userdata = user_data;

    sso_auth_service_call_clear (priv->proxy,
                                 priv->cancellable,
                                 auth_clear_cb,
                                 cb_data);
}

