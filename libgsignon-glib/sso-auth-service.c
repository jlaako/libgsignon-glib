/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libgsignon-glib
 *
 * Copyright (C) 2012 Canonical Ltd.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@canonical.com>
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

#include <config.h>
#include "signon-errors.h"
#include "signon-internals.h"
#include "sso-auth-service.h"

static GHashTable *thread_objects = NULL;
static GMutex map_mutex;

static SsoAuthService *
get_singleton (void)
{
    SsoAuthService *object = NULL;

    g_mutex_lock (&map_mutex);

    if (thread_objects != NULL)
    {
        GWeakRef *ref;
        ref = g_hash_table_lookup (thread_objects, g_thread_self ());
        if (ref != NULL)
        {
            object = g_weak_ref_get (ref);
        }
    }

    g_mutex_unlock (&map_mutex);
    return object;
}

static void
g_thread_ref_free (GWeakRef *data)
{
    g_slice_free (GWeakRef, data);
}

static void
set_singleton (SsoAuthService *object)
{
    g_return_if_fail (IS_SSO_AUTH_SERVICE (object));

    g_mutex_lock (&map_mutex);

    if (thread_objects == NULL)
    {
        thread_objects = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                NULL, (GDestroyNotify)g_thread_ref_free);
    }

    if (object != NULL)
    {
        GWeakRef *ref = g_slice_new (GWeakRef);
        g_weak_ref_init (ref, object);
        g_hash_table_insert (thread_objects, g_thread_self (), ref);
    }

    g_mutex_unlock (&map_mutex);
}

static void
_on_auth_service_destroyed (gpointer data, GObject *obj)
{
    (void)data;
    (void)obj;
    g_mutex_lock (&map_mutex);
    if (thread_objects)
    {
        g_hash_table_unref (thread_objects);
        thread_objects = NULL;
    }
    g_mutex_unlock (&map_mutex);
}


SsoAuthService *
sso_auth_service_get_instance (void)
{
    SsoAuthService *sso_auth_service = NULL;
    GDBusConnection *connection = NULL;
    GError *error = NULL;

    sso_auth_service = get_singleton ();
    if (sso_auth_service != NULL) return sso_auth_service;

#ifdef USE_P2P
    gchar *bus_address = g_strdup_printf (SIGNOND_BUS_ADDRESS, g_get_user_runtime_dir());
    connection = g_dbus_connection_new_for_address_sync (bus_address,
                                                         G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
                                                         NULL,
                                                         NULL,
                                                         &error);
    g_free (bus_address);
#else
    connection = g_bus_get_sync (SIGNOND_BUS_TYPE, NULL, &error);
#endif
    /* Create the object */
    sso_auth_service =
        sso_auth_service_proxy_new_sync (connection,
                                         G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
#ifdef USE_P2P
                                         NULL,
#else
                                         SIGNOND_SERVICE,
#endif
                                         SIGNOND_DAEMON_OBJECTPATH,
                                         NULL,
                                         &error);
    g_object_weak_ref (G_OBJECT (sso_auth_service), _on_auth_service_destroyed, sso_auth_service);
    if (G_LIKELY (error == NULL)) {
        set_singleton (sso_auth_service);
    }
    else
    {
        g_warning ("Couldn't activate signond: %s", error->message);
        g_clear_error (&error);
    }

    /* While at it, register the error mapping with GDBus */
    signon_error_quark ();

    return sso_auth_service;
}
