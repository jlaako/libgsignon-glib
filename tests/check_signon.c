/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libgsignon-glib
 *
 * Copyright (C) 2009-2011 Nokia Corporation.
 * Copyright (C) 2011-2012 Canonical Ltd.
 * Copyright (C) 2012 Intel Corporation.
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
 * @example check_signon.c
 * Shows how to initialize the framework.
 */

#define SIGNON_DISABLE_DEPRECATION_WARNINGS

#include "libgsignon-glib/signon-internals.h"
#include "libgsignon-glib/signon-auth-service.h"
#include "libgsignon-glib/signon-auth-session.h"
#include "libgsignon-glib/signon-identity.h"
#include "libgsignon-glib/signon-errors.h"

#include <glib.h>
#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const gchar *ssotest_mechanisms[] =
    { "mech1", "mech2", "mech3", "BLOB", NULL };
static GMainLoop *main_loop = NULL;
static SignonIdentity *identity = NULL;
static SignonAuthService *auth_service = NULL;
static gboolean id_destroyed = FALSE;

#define SIGNOND_IDLE_TIMEOUT (5 + 2)

static void
_stop_mainloop ()
{
    if (main_loop) {
        g_main_loop_quit (main_loop);
    }
}

static void
_run_mainloop ()
{
    if (main_loop)
        g_main_loop_run (main_loop);
}


static void
_setup ()
{
#if !GLIB_CHECK_VERSION (2, 36, 0)
    g_type_init ();
#endif
    if (main_loop == NULL) {
        main_loop = g_main_loop_new (NULL, FALSE);
    }
}

static void
_teardown ()
{
    if (auth_service)
    {
        g_object_unref (auth_service);
        auth_service = NULL;
    }

    if (identity)
    {
        g_object_unref (identity);
        identity = NULL;
    }

    if (main_loop) {
        _stop_mainloop ();
        g_main_loop_unref (main_loop);
        main_loop = NULL;
    }
}

static void
new_identity_store_credentials_cb(
        SignonIdentity *self,
        guint32 id,
        const GError *error,
        gpointer user_data)
{
    gint *new_id = user_data;

    if(error)
    {
        g_warning ("%s %d: %s", G_STRFUNC, __LINE__, error->message);
        fail();
    }

    fail_unless (id > 0);

    *new_id = id;

    _stop_mainloop ();
}

static guint
new_identity()
{
    SignonIdentity *idty;
    GHashTable *methods;
    guint id = 0;

    idty = signon_identity_new ();
    fail_unless (SIGNON_IS_IDENTITY (idty));
    methods = g_hash_table_new (g_str_hash, g_str_equal);
    g_hash_table_insert (methods, "ssotest", ssotest_mechanisms);
    signon_identity_store_credentials_with_args (idty,
                                                 "James Bond",
                                                 "007",
                                                 TRUE,
                                                 methods,
                                                 "MI-6",
                                                 NULL,
                                                 NULL,
                                                 NULL,
                                                 0,
                                                 new_identity_store_credentials_cb,
                                                 &id);
    g_hash_table_destroy (methods);

    if (id == 0)
        _run_mainloop ();

    g_object_unref (idty);

    return id;

}

START_TEST(test_init)
{
    g_debug("%s", G_STRFUNC);
    auth_service = signon_auth_service_new ();

    fail_unless (SIGNON_IS_AUTH_SERVICE (auth_service),
                 "Failed to initialize the AuthService.");
}
END_TEST

static void
signon_query_methods_cb (SignonAuthService *auth_service, gchar **methods,
                         GError *error, gpointer user_data)
{
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        _stop_mainloop ();
        if (methods) g_strfreev (methods);
        fail();
    }

    gboolean has_ssotest = FALSE;
    gchar **pmethods = methods;

    fail_unless (g_strcmp0 (user_data, "Hello") == 0, "Got wrong string");
    fail_unless (methods != NULL, "The methods does not exist");

    while (*pmethods)
    {
        if (g_strcmp0 (*pmethods, "ssotest") == 0)
        {
            has_ssotest = TRUE;
            break;
        }
        pmethods++;
    }
    g_strfreev (methods);
    fail_unless (has_ssotest, "ssotest method does not exist");

    _stop_mainloop ();
}

START_TEST(test_query_methods)
{
    g_debug("%s", G_STRFUNC);

    auth_service = signon_auth_service_new ();

    fail_unless (SIGNON_IS_AUTH_SERVICE (auth_service),
                 "Failed to initialize the AuthService.");

    signon_auth_service_query_methods (auth_service, (SignonQueryMethodsCb)signon_query_methods_cb, "Hello");
    _run_mainloop ();
}
END_TEST

static void
signon_query_mechanisms_cb (SignonAuthService *auth_service, gchar *method,
        gchar **mechanisms, GError *error, gpointer user_data)
{
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        if (mechanisms) g_strfreev (mechanisms);
        _stop_mainloop ();
        fail();
    }

    gboolean has_mech1 = FALSE;
    gboolean has_mech2 = FALSE;
    gboolean has_mech3 = FALSE;
    gchar **pmechanisms = mechanisms;

    fail_unless (strcmp (user_data, "Hello") == 0, "Got wrong string");
    fail_unless (mechanisms != NULL, "The mechanisms does not exist");

    while (*pmechanisms)
    {
        if (g_strcmp0 (*pmechanisms, "mech1") == 0)
            has_mech1 = TRUE;

        if (g_strcmp0 (*pmechanisms, "mech2") == 0)
            has_mech2 = TRUE;

        if (g_strcmp0 (*pmechanisms, "mech3") == 0)
            has_mech3 = TRUE;

        pmechanisms++;
    }
    g_strfreev (mechanisms);
    fail_unless (has_mech1, "mech1 mechanism does not exist");
    fail_unless (has_mech2, "mech2 mechanism does not exist");
    fail_unless (has_mech3, "mech3 mechanism does not exist");

    _stop_mainloop ();
}

static void
signon_query_mechanisms_cb_fail (SignonAuthService *auth_service,
                                 gchar *method,
                                 gchar **mechanisms,
                                 GError *error, gpointer user_data)
{
    fail_unless (error != NULL);
    fail_unless (mechanisms == NULL);
    fail_unless (error->domain == SIGNON_ERROR);
    fail_unless (error->code == SIGNON_ERROR_METHOD_NOT_KNOWN);
    if (mechanisms) g_strfreev (mechanisms);
    _stop_mainloop ();
}

START_TEST(test_query_mechanisms)
{
    g_debug("%s", G_STRFUNC);
    auth_service = signon_auth_service_new ();

    fail_unless (SIGNON_IS_AUTH_SERVICE (auth_service),
                 "Failed to initialize the AuthService.");

    signon_auth_service_query_mechanisms (auth_service,
                                          "ssotest",
                                          (SignonQueryMechanismCb)signon_query_mechanisms_cb,
                                          "Hello");

    _run_mainloop ();

    /* Test a non existing method */
    signon_auth_service_query_mechanisms (auth_service,
                                          "non-existing",
                                          (SignonQueryMechanismCb)signon_query_mechanisms_cb_fail,
                                          "Hello");
    _run_mainloop ();
}
END_TEST


static gboolean
test_quit_main_loop_cb (gpointer data)
{
    _stop_mainloop ();
    return FALSE;
}

static void
test_auth_session_query_mechanisms_cb (SignonAuthSession *self,
                                       gchar **mechanisms,
                                       const GError *error,
                                       gpointer user_data)
{
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        _stop_mainloop ();
        fail();
    }

    fail_unless (mechanisms != NULL, "The mechanisms does not exist");

    gchar** patterns = (gchar**)user_data;

    int i = g_strv_length(mechanisms);
    int x = g_strv_length(patterns);
    fail_unless( i == x, "The number of obtained methods is wrong: %d vs %d", i, x);

    while ( i > 0 )
    {
        gchar* pattern = patterns[--i];
        fail_unless(g_strcmp0(pattern, mechanisms[i]) == 0, "The obtained mechanism differs from predefined pattern: %s vs %s", mechanisms[i], pattern);
    }

    g_strfreev(mechanisms);
    _stop_mainloop ();
}

START_TEST(test_auth_session_query_mechanisms)
{
    GError *err = NULL;

    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL, "Cannot create Iddentity object");

    SignonAuthSession *auth_session = signon_identity_create_session(idty,
                                                                     "ssotest",
                                                                     &err);
    fail_unless (auth_session != NULL, "Cannot create AuthSession object");

    g_clear_error(&err);

    gchar* patterns[4];
    patterns[0] = g_strdup("mech1");
    patterns[1] = g_strdup("mech2");
    patterns[2] = g_strdup("mech3");
    patterns[3] = NULL;

    signon_auth_session_query_available_mechanisms(auth_session,
                                                  (const gchar**)patterns,
                                                  test_auth_session_query_mechanisms_cb,
                                                  (gpointer)patterns);

    _run_mainloop ();

    g_free(patterns[2]);
    patterns[2] = NULL;

    signon_auth_session_query_available_mechanisms(auth_session,
                                                  (const gchar**)patterns,
                                                  test_auth_session_query_mechanisms_cb,
                                                  (gpointer)patterns);

    _run_mainloop ();

    g_free(patterns[1]);
    patterns[1] = NULL;

    signon_auth_session_query_available_mechanisms(auth_session,
                                                  (const gchar**)patterns,
                                                  test_auth_session_query_mechanisms_cb,
                                                  (gpointer)patterns);

    _run_mainloop ();

    g_free(patterns[0]);
    g_object_unref (auth_session);
    g_object_unref (idty);

}
END_TEST

static void
test_auth_session_query_mechanisms_nonexisting_cb (SignonAuthSession *self,
                                                  gchar **mechanisms,
                                                  const GError *error,
                                                  gpointer user_data)
{
    if (!error)
    {
        _stop_mainloop ();
        fail();
        return;
    }

    g_warning ("%s: %s", G_STRFUNC, error->message);
    _stop_mainloop ();
}

START_TEST(test_auth_session_query_mechanisms_nonexisting)
{
    GError *err = NULL;

    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL, "Cannot create Iddentity object");

    SignonAuthSession *auth_session = signon_identity_create_session(idty,
                                                                     "nonexisting",
                                                                     &err);
    fail_unless (auth_session != NULL, "Cannot create AuthSession object");

    g_clear_error(&err);

    gchar* patterns[4];
    patterns[0] = g_strdup("mech1");
    patterns[1] = g_strdup("mech2");
    patterns[2] = g_strdup("mech3");
    patterns[3] = NULL;

    signon_auth_session_query_available_mechanisms(auth_session,
                                                  (const gchar**)patterns,
                                                  test_auth_session_query_mechanisms_nonexisting_cb,
                                                  (gpointer)patterns);

    _run_mainloop ();

    g_free(patterns[0]);
    g_free(patterns[1]);
    g_free(patterns[2]);
    g_object_unref (auth_session);
    g_object_unref (idty);

}
END_TEST

static void
test_auth_session_states_cb (SignonAuthSession *self,
                             gint state,
                             gchar *message,
                             gpointer user_data)
{
    gint *state_counter = (gint *)user_data;
    (*state_counter)++;
}

static void
test_auth_session_process_cb (SignonAuthSession *self,
                             GHashTable *sessionData,
                             const GError *error,
                             gpointer user_data)
{
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        _stop_mainloop ();
        fail();
    }

    fail_unless (sessionData != NULL, "The result is empty");

    gchar* usernameKey = g_strdup(SIGNON_SESSION_DATA_USERNAME);
    GValue* usernameVa = (GValue*)g_hash_table_lookup(sessionData, usernameKey);

    gchar* realmKey = g_strdup(SIGNON_SESSION_DATA_REALM);
    GValue* realmVa = (GValue*)g_hash_table_lookup(sessionData, realmKey);

    fail_unless(g_strcmp0(g_value_get_string(usernameVa), "test_username") == 0, "Wrong value of username");
    fail_unless(g_strcmp0(g_value_get_string(realmVa), "testRealm_after_test") == 0, "Wrong value of realm");

    g_hash_table_destroy(sessionData);

    g_free(usernameKey);
    g_free(realmKey);

    _stop_mainloop ();
}

static void
_on_identity_destroyed (gpointer data, GObject *obj)
{
    id_destroyed = TRUE;
}

static void
_on_auth_session_destroyed (gpointer data, GObject *obj)
{
    gboolean *is_destroyed = (gboolean *)data;
    *is_destroyed = TRUE;
}

START_TEST(test_auth_session_creation)
{
    GError *err = NULL;
    gboolean auth_sess_destroyed = FALSE;

    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL, "Cannot create Identity object");

    SignonAuthSession *auth_session = signon_identity_create_session(idty,
                                                                    "ssotest",
                                                                    &err);

    fail_unless (auth_session != NULL, "Cannot create AuthSession object");

    id_destroyed = FALSE;
    g_object_weak_ref (G_OBJECT (idty), _on_identity_destroyed, NULL);
    g_object_weak_ref (G_OBJECT (auth_session), _on_auth_session_destroyed,
            &auth_sess_destroyed);

    g_object_unref (idty);
    fail_unless (id_destroyed == FALSE, "Identity must stay untill all its session are not destroyed");

    g_object_unref (auth_session);

    fail_if (auth_sess_destroyed == FALSE, "AuthSession is not synchronized with parent Identity");
    fail_if (id_destroyed == FALSE, "Identity is not synchronized with its AuthSession");

    g_clear_error(&err);

}
END_TEST

START_TEST(test_auth_session_process)
{
    gint state_counter = 0;
    GError *err = NULL;

    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL, "Cannot create Iddentity object");

    SignonAuthSession *auth_session = signon_identity_create_session(idty,
                                                                     "ssotest",
                                                                     &err);

    fail_unless (auth_session != NULL, "Cannot create AuthSession object");

    g_clear_error(&err);

    g_signal_connect(auth_session, "state-changed",
                     G_CALLBACK(test_auth_session_states_cb), &state_counter);

    GHashTable* sessionData = g_hash_table_new(g_str_hash,
                                               g_str_equal);
    GValue* usernameVa = g_new0(GValue, 1);
    gchar* usernameKey = g_strdup(SIGNON_SESSION_DATA_USERNAME);
    g_value_init (usernameVa, G_TYPE_STRING);
    g_value_set_static_string(usernameVa, "test_username");

    g_hash_table_insert (sessionData,
                         usernameKey,
                         usernameVa);

    GValue* passwordVa = g_new0(GValue, 1);
    gchar* passwordKey = g_strdup(SIGNON_SESSION_DATA_SECRET);

    g_value_init (passwordVa, G_TYPE_STRING);
    g_value_set_static_string(passwordVa, "test_username");

    g_hash_table_insert (sessionData,
                         passwordKey,
                         passwordVa);

    signon_auth_session_process(auth_session,
                               sessionData,
                               "mech1",
                               test_auth_session_process_cb,
                               sessionData);

    _run_mainloop ();

    fail_unless (state_counter == 12, "Wrong numer of state change signals: %d", state_counter);
    state_counter = 0;

    signon_auth_session_process(auth_session,
                               sessionData,
                               "mech1",
                               test_auth_session_process_cb,
                               sessionData);

    _run_mainloop ();
    fail_unless (state_counter == 12, "Wrong numer of state change signals: %d", state_counter);
    state_counter = 0;

    signon_auth_session_process(auth_session,
                               sessionData,
                               "mech1",
                               test_auth_session_process_cb,
                               sessionData);

    _run_mainloop ();
    fail_unless (state_counter == 12, "Wrong numer of state change signals: %d", state_counter);
    state_counter = 0;

    g_object_unref (auth_session);
    g_object_unref (idty);

    g_value_unset(usernameVa);
    g_free(usernameVa);
    g_free(usernameKey);

    g_value_unset(passwordVa);
    g_free(passwordVa);
    g_free(passwordKey);

    g_hash_table_unref (sessionData);
}
END_TEST

static void
test_auth_session_process_failure_cb (GObject *source_object,
                                      GAsyncResult *res,
                                      gpointer user_data)
{
    g_debug("%s", G_STRFUNC);
    SignonAuthSession *auth_session = SIGNON_AUTH_SESSION (source_object);
    GVariant *v_reply;
    GError **error = user_data;

    fail_unless (SIGNON_IS_AUTH_SESSION (source_object));

    v_reply = signon_auth_session_process_finish (auth_session, res, error);
    fail_unless (v_reply == NULL);

    _stop_mainloop ();
}

START_TEST(test_auth_session_process_failure)
{
    SignonIdentity *idty;
    SignonAuthSession *auth_session;
    GVariantBuilder builder;
    GVariant *session_data;
    GError *error = NULL;

    g_debug("%s", G_STRFUNC);

    guint id = new_identity();

    fail_unless (id != 0);

    idty = signon_identity_new_from_db (id);

    fail_unless (idty != NULL, "Cannot create Identity object");
    auth_session = signon_auth_session_new_for_identity (idty,
                                                         "ssotest",
                                                         &error);
    fail_unless (auth_session != NULL, "Cannot create AuthSession object");
    fail_unless (error == NULL);

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add (&builder, "{sv}",
                           "key", g_variant_new_string ("value"));

    session_data = g_variant_builder_end (&builder);

    signon_auth_session_process_async (auth_session,
                                       session_data,
                                       "mechx",
                                       NULL,
                                       test_auth_session_process_failure_cb,
                                       &error);
    _run_mainloop ();
    fail_unless (error != NULL);
    fail_unless (error->domain == SIGNON_ERROR);
    fail_unless (error->code == SIGNON_ERROR_MECHANISM_NOT_AVAILABLE);
    g_error_free (error);

    g_object_unref (auth_session);
    g_object_unref (idty);
}
END_TEST

static void
test_auth_session_process_after_store_cb (SignonAuthSession *self,
                                          GHashTable *reply,
                                          const GError *error,
                                          gpointer user_data)
{
    GValue *v_username;

    if (error != NULL)
    {
        fail("Got error: %s", error->message);
        _stop_mainloop ();
        return;
    }

    fail_unless (reply != NULL, "The result is empty");

    v_username = g_hash_table_lookup(reply,
                                     SIGNON_SESSION_DATA_USERNAME);

    fail_unless (g_strcmp0 (g_value_get_string (v_username), "Nice user") == 0,
                 "Wrong value of username");

    g_hash_table_unref (reply);
    g_object_unref (self);

    _stop_mainloop ();
}

static void
test_auth_session_process_after_store_start_session(SignonIdentity *self,
                                                    guint32 id,
                                                    const GError *error,
                                                    gpointer user_data)
{
    GError *err = NULL;

    if (error != NULL)
    {
        g_warning ("%s %d: %s", G_STRFUNC, __LINE__, error->message);
        fail();
        _stop_mainloop ();
        return;
    }

    fail_unless (id > 0);

    SignonAuthSession *auth_session =
        signon_identity_create_session (self,
                                        "ssotest",
                                        &err);

    fail_unless (auth_session != NULL, "Cannot create AuthSession object");
    if (err != NULL)
    {
        fail ("Got error: %s", err->message);
        g_clear_error (&err);
    }

    GHashTable *session_data = g_hash_table_new (g_str_hash,
                                                 g_str_equal);

    signon_auth_session_process (auth_session,
                                 session_data,
                                 "mech1",
                                 test_auth_session_process_after_store_cb,
                                 NULL);
    g_hash_table_unref (session_data);
}

START_TEST(test_auth_session_process_after_store)
{
    SignonIdentityInfo *info;
    SignonIdentity *idty;

    g_debug("%s", G_STRFUNC);

    idty = signon_identity_new ();
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    info = signon_identity_info_new ();
    signon_identity_info_set_method (info, "ssotest", ssotest_mechanisms);
    signon_identity_info_set_owner_from_values (info, "someone", "else");
    signon_identity_info_access_control_list_append (info,
        signon_security_context_new_from_values ("*", "*"));
    signon_identity_info_set_username (info, "Nice user");

    signon_identity_store_credentials_with_info (idty,
                                                 info,
                                                 test_auth_session_process_after_store_start_session,
                                                 NULL);
    _run_mainloop ();

    g_object_unref (idty);
    signon_identity_info_free (info);
}
END_TEST

static GHashTable *create_methods_hashtable()
{
    gchar *mechanisms[] = {
            "mechanism1",
            "mechanism2",
            "mechanism3",
            NULL
    };

    GHashTable *methods = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                                                (GDestroyNotify)g_strfreev);

    g_hash_table_insert (methods, g_strdup("method1"), g_strdupv(mechanisms));
    g_hash_table_insert (methods, g_strdup("method2"), g_strdupv(mechanisms));
    g_hash_table_insert (methods, g_strdup("method3"), g_strdupv(mechanisms));

    return methods;
}

static gboolean
identity_registeration_timeout_cb (gpointer data)
{
    g_debug("%s", G_STRFUNC);
    _stop_mainloop ();
    return FALSE;
}

START_TEST(test_get_existing_identity)
{
    g_debug("%s", G_STRFUNC);
    guint id = new_identity();

    fail_unless (id != 0);

    identity = signon_identity_new_from_db (id);

    fail_unless (identity != NULL);
    fail_unless (SIGNON_IS_IDENTITY (identity),
                 "Failed to initialize the Identity.");

    g_timeout_add (1000, identity_registeration_timeout_cb, identity);
    _run_mainloop ();

    const GError *error = NULL;
    error = signon_identity_get_last_error(identity);
    fail_unless (error == NULL);
}
END_TEST

START_TEST(test_get_nonexisting_identity)
{
    g_debug("%s", G_STRFUNC);
    identity = signon_identity_new_from_db (G_MAXINT);

    fail_unless (identity != NULL);
    fail_unless (SIGNON_IS_IDENTITY (identity),
                 "Failed to initialize the Identity.");

    g_timeout_add (1000, identity_registeration_timeout_cb, identity);
    _run_mainloop ();

    const GError *error = NULL;
    error = signon_identity_get_last_error(identity);
    fail_unless (error != NULL);

    fail_unless (error->domain == SIGNON_ERROR);
    fail_unless (error->code == SIGNON_ERROR_IDENTITY_NOT_FOUND);
}
END_TEST

static void store_credentials_identity_cb(SignonIdentity *self,
                                         guint32 id,
                                         const GError *error,
                                         gpointer user_data)
{
    if(error)
    {
        g_warning ("%s %d: %s", G_STRFUNC, __LINE__, error->message);
        fail();
    }

    fail_unless (id > 0);

    if (user_data != NULL)
    {
        gint *last_id = (gint *)user_data;
        g_warning ("%s (prev_id vs new_id): %d vs %d", G_STRFUNC, *last_id, id);

        fail_unless (id == (*last_id) + 1);
        (*last_id) += 1;
    }

    /* Wait some time to ensure that the info-updated signals are
     * processed
     */
    g_timeout_add_seconds (2, test_quit_main_loop_cb, main_loop);
}

START_TEST(test_store_credentials_identity)
{
    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    gint last_id = new_identity();

    GHashTable *methods = create_methods_hashtable();

    signon_identity_store_credentials_with_args (idty,
                                                 "James Bond",
                                                 "007",
                                                 1,
                                                 methods,
                                                 "MI-6",
                                                 NULL,
                                                 NULL,
                                                 NULL,
                                                 0,
                                                 store_credentials_identity_cb,
                                                 &last_id);
    g_hash_table_destroy (methods);

    g_timeout_add (1000, test_quit_main_loop_cb, idty);
    _run_mainloop ();

    g_object_unref(idty);
}
END_TEST

static void identity_remove_cb(SignonIdentity *self, const GError *error, gpointer user_data)
{

    g_warning (" %s ", __func__);
     if (error)
     {
        g_warning ("Error: %s ", error->message);
        fail_if (user_data == NULL, "There should be no error in callback");
     }
    else
    {
        g_warning ("No error");
        fail_if (user_data != NULL, "The callback must return an error");
    }

    _stop_mainloop ();
}

START_TEST(test_remove_identity)
{
    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new ();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    /*
     * Try to remove non-stored identity
     * */
    signon_identity_remove(idty, identity_remove_cb, NULL);
    _run_mainloop ();

    /*
     * Try to remove existing identy
     * */

    gint id = new_identity();
    SignonIdentity *idty2 = signon_identity_new_from_db (id);

    signon_identity_remove(idty2, identity_remove_cb, NULL);
    _run_mainloop ();

    /*
     * Try to remove already removed
     * */
    signon_identity_remove(idty2, identity_remove_cb, GINT_TO_POINTER(TRUE));

    g_object_unref (idty);
    g_object_unref (idty2);
}
END_TEST

static void identity_ref_add_cb(SignonIdentity *self, const GError *error,
    gpointer user_data)
{
    g_warning (" %s ", __func__);
    if (error)
    {
        g_warning ("Error: %s ", error->message);
        fail_if (user_data == NULL, "There should be no error in callback");
    }
    else
    {
        g_warning ("No error");
        fail_if (user_data != NULL, "The callback must return an error");
    }

    _stop_mainloop ();
}

static void identity_ref_remove_cb(SignonIdentity *self, const GError *error,
    gpointer user_data)
{
    g_warning (" %s ", __func__);
    if (error)
    {
        g_warning ("Error: %s ", error->message);
        fail_if (user_data == NULL, "There should be no error in callback");
    }
    else
    {
        g_warning ("No error");
        fail_if (user_data != NULL, "The callback must return an error");
    }

    _stop_mainloop ();
}

START_TEST(test_referenc_remove_identity)
{
    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new ();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    /*
     * Try to remove non-existing reference
     * */
    signon_identity_remove_reference(idty, "no-ref", identity_ref_remove_cb,
        GINT_TO_POINTER(TRUE));
    _run_mainloop ();

    gint id = new_identity();
    SignonIdentity *idty2 = signon_identity_new_from_db (id);
    signon_identity_add_reference(idty2, "app-rem1", identity_ref_add_cb,
        NULL);
    _run_mainloop ();

    /*
     * Try to remove existing reference
     * */
    signon_identity_remove_reference(idty2, "app-rem1", identity_remove_cb,
        NULL);
    _run_mainloop ();

    g_object_unref (idty);
    g_object_unref (idty2);
}
END_TEST

START_TEST(test_referenc_add_identity)
{
    g_debug("%s", G_STRFUNC);

    gint id = new_identity();
    SignonIdentity *idty = signon_identity_new_from_db (id);
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");
    /*
     * Try to add non-existing reference
     * */
    signon_identity_add_reference(idty, "app1", identity_ref_add_cb,
        NULL);
    _run_mainloop ();

    /*
     * Try to add an existing reference (which replaces the old one)
     * */
    signon_identity_add_reference(idty, "app1", identity_ref_add_cb,
        NULL);
    _run_mainloop ();

    /*
     * Try to add another reference
     * */
    signon_identity_add_reference(idty, "app2", identity_ref_add_cb,
        NULL);
    _run_mainloop ();

    g_object_unref (idty);
}
END_TEST

static gboolean _contains(gchar **mechs, gchar *mech)
{
    gboolean present = FALSE;
    gint i = 0;
    while (mechs[i] != NULL)
    {
        if (g_strcmp0 (mech, mechs[i]) == 0) present = TRUE;
        i++;
    }
    return present;
}

static void identity_info_cb(SignonIdentity *self, SignonIdentityInfo *info, const GError *error, gpointer user_data)
{
     if (error)
     {
        g_warning ("%s: Error: %s ", __func__, error->message);
        fail_if (info != NULL, "Error: %s ", error->message);
        _stop_mainloop ();
        return;
     }

     g_warning ("No error");

     SignonIdentityInfo **pattern_ptr = (SignonIdentityInfo **)user_data;
     SignonIdentityInfo *pattern = NULL;

     if (pattern_ptr)
         pattern = (*pattern_ptr);

     if (pattern == NULL)
         fail_unless (info == NULL, "The info must be NULL");
     else
     {
         fail_unless (info != NULL, "The info must be non-null");
         fail_unless (g_strcmp0 (signon_identity_info_get_username(info),
                                 signon_identity_info_get_username(pattern)) == 0, "The info has wrong username");
         fail_unless (g_strcmp0 (signon_identity_info_get_caption(info),
                                 signon_identity_info_get_caption(pattern)) == 0, "The info has wrong caption");

         fail_unless (signon_identity_info_get_identity_type (info) == signon_identity_info_get_identity_type (pattern),
            "Wrong identity type");

         GHashTable *methods = (GHashTable *)signon_identity_info_get_methods (info);
         gchar **mechs1 = g_hash_table_lookup (methods, "method1");
         gchar **mechs2 = g_hash_table_lookup (methods, "method2");
         gchar **mechs3 = g_hash_table_lookup (methods, "method3");

         fail_unless (g_strv_length (mechs1) == 3);
         fail_unless (g_strv_length (mechs2) == 3);
         fail_unless (g_strv_length (mechs3) == 3);

         fail_unless (_contains(mechs1, "mechanism1"));
         fail_unless (_contains(mechs1, "mechanism2"));
         fail_unless (_contains(mechs1, "mechanism3"));

         fail_unless (_contains(mechs2, "mechanism1"));
         fail_unless (_contains(mechs2, "mechanism2"));
         fail_unless (_contains(mechs2, "mechanism3"));

         fail_unless (_contains(mechs3, "mechanism1"));
         fail_unless (_contains(mechs3, "mechanism2"));
         fail_unless (_contains(mechs3, "mechanism3"));
     }

     if (info)
     {
         signon_identity_info_free (pattern);
         *pattern_ptr = signon_identity_info_copy (info);
     }

     _stop_mainloop ();
}

static SignonIdentityInfo *create_standard_info()
{
    GHashTable *methods;

    g_debug("%s", G_STRFUNC);

    SignonIdentityInfo *info = signon_identity_info_new ();

    methods = g_hash_table_new (g_str_hash, g_str_equal);
    g_hash_table_insert (methods, "ssotest", ssotest_mechanisms);
    signon_identity_info_set_methods (info, methods);
    g_hash_table_destroy (methods);

    signon_identity_info_set_owner_from_values (info, "", "");
    signon_identity_info_access_control_list_append (info,
        signon_security_context_new_from_values ("*", "*"));
    signon_identity_info_set_username (info, "James Bond");
    signon_identity_info_set_secret (info, "007", TRUE);
    signon_identity_info_set_caption (info, "MI-6");

    gchar *mechanisms[] = {
            "mechanism1",
            "mechanism2",
            "mechanism3",
            NULL
    };

    signon_identity_info_set_method (info, "method1", (const gchar **)mechanisms);
    signon_identity_info_set_method (info, "method2", (const gchar **)mechanisms);
    signon_identity_info_set_method (info, "method3", (const gchar **)mechanisms);

    return info;
}

START_TEST(test_info_identity)
{
    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new ();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    SignonIdentityInfo *info = NULL;

    /*
     * Try to get_info for non-stored idetnity
     * */
    signon_identity_query_info (idty, identity_info_cb, &info);
    _run_mainloop ();

    GHashTable *methods = create_methods_hashtable();
    signon_identity_store_credentials_with_args (idty,
                                                "James Bond",
                                                "007",
                                                 1,
                                                 methods,
                                                 "MI-6",
                                                 NULL,
                                                 NULL,
                                                 NULL,
                                                 SIGNON_IDENTITY_TYPE_WEB,
                                                 store_credentials_identity_cb,
                                                 NULL);
    _run_mainloop ();
    g_hash_table_destroy (methods);

    info = signon_identity_info_new ();
    signon_identity_info_set_username (info, "James Bond");
    signon_identity_info_set_secret (info, "007", TRUE);
    signon_identity_info_set_caption (info, "MI-6");

    gchar *mechanisms[] = {
            "mechanism1",
            "mechanism2",
            "mechanism3",
            NULL
    };

    signon_identity_info_set_method (info, "method1", (const gchar **)mechanisms);
    signon_identity_info_set_method (info, "method2", (const gchar **)mechanisms);
    signon_identity_info_set_method (info, "method3", (const gchar **)mechanisms);
    signon_identity_info_set_identity_type (info, SIGNON_IDENTITY_TYPE_WEB);

    signon_identity_query_info (idty, identity_info_cb, &info);
    _run_mainloop ();

    gint id = signon_identity_info_get_id (info);
    fail_unless (id != 0);
    SignonIdentity *idty2 = signon_identity_new_from_db (id);

    signon_identity_query_info (idty2, identity_info_cb, &info);
    _run_mainloop ();

    /*
     * Try to update one identity and
     * have a look what will happen
     * */
    signon_identity_info_set_username (info, "James Bond_2nd version");
    signon_identity_info_set_caption (info, "caption_2nd version");

    signon_identity_store_credentials_with_info (idty2,
                                                 info,
                                                 store_credentials_identity_cb,
                                                 NULL);
    _run_mainloop ();

    signon_identity_query_info (idty, identity_info_cb, &info);
    _run_mainloop ();

    /*
     * Try to remove existing identity and
     * have a look what will happen
     * */
    signon_identity_remove(idty2, identity_remove_cb, NULL);
    _run_mainloop ();

    /*
     * no main_loops required as
     * the callback is executed immediately
     * */
    signon_identity_query_info (idty2, identity_info_cb, NULL);
    signon_identity_query_info (idty, identity_info_cb, NULL);

    signon_identity_info_free (info);
    g_object_unref (idty);
    g_object_unref (idty2);
}
END_TEST

static void identity_signout_cb (SignonIdentity *self,
                                const GError *error,
                                gpointer user_data)
{
    if (error)
        g_warning ("%s: %s", G_STRFUNC, error->message);
    else
        g_warning ("%s: No error", G_STRFUNC);

    fail_unless (error == NULL, "There should be no error in callback");
    _stop_mainloop ();
}

static void identity_signout_signal_cb (gpointer instance, gpointer user_data)
{
    gint *incr = (gint *)user_data;
    (*incr) = (*incr) + 1;
    g_warning ("%s: %d", G_STRFUNC, *incr);
}

START_TEST(test_signout_identity)
{
    gboolean as1_destroyed = FALSE, as2_destroyed = FALSE;
    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new ();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    SignonIdentityInfo *info = create_standard_info();

    signon_identity_store_credentials_with_info (idty,
                                                 info,
                                                 store_credentials_identity_cb,
                                                 NULL);
    _run_mainloop ();
    signon_identity_query_info (idty, identity_info_cb, &info);
    _run_mainloop ();

    gint id = signon_identity_info_get_id (info);
    SignonIdentity *idty2 = signon_identity_new_from_db (id);

    /* wait some more time to ensure that the object gets registered */
    g_timeout_add_seconds (2, test_quit_main_loop_cb, main_loop);
    _run_mainloop ();

    signon_identity_info_free (info);

    GError *err = NULL;

    SignonAuthSession *as1 = signon_identity_create_session (idty,
                                                            "ssotest",
                                                            &err);
    fail_unless (as1 != NULL, "cannot create AuthSession");

    SignonAuthSession *as2 = signon_identity_create_session (idty2,
                                                             "ssotest",
                                                             &err);
    fail_unless (as2 != NULL, "cannot create AuthSession");

    gint counter = 0;

    g_signal_connect (idty, "signout",
                      G_CALLBACK(identity_signout_signal_cb), &counter);
    g_signal_connect (idty2, "signout",
                      G_CALLBACK(identity_signout_signal_cb), &counter);

    g_object_weak_ref (G_OBJECT (as1), _on_auth_session_destroyed,
            &as1_destroyed);
    g_object_weak_ref (G_OBJECT (as2), _on_auth_session_destroyed,
            &as2_destroyed);
    signon_identity_signout (idty, identity_signout_cb, NULL);
    _run_mainloop ();

    fail_unless (counter == 2, "Lost some of SIGNOUT signals");
    fail_if (as1_destroyed == FALSE, "Authsession1 was not destroyed after signout");
    fail_if (as2_destroyed == FALSE, "Authsession2 was not destroyed after signout");

    g_object_unref (idty);
    g_object_unref (idty2);
}
END_TEST

START_TEST(test_unregistered_identity)
{
    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new ();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    SignonIdentityInfo *info = create_standard_info();

    signon_identity_store_credentials_with_info (idty,
                                                 info,
                                                 store_credentials_identity_cb,
                                                 NULL);
    _run_mainloop ();

    /*
     * give the time for identity to became idle
     * */
    sleep(SIGNOND_IDLE_TIMEOUT);
    SignonIdentity *idty2 = signon_identity_new ();

    /*
     * give time to handle unregistered signal
     * */
    g_timeout_add_seconds (5, test_quit_main_loop_cb, main_loop);

    signon_identity_query_info (idty, identity_info_cb, &info);
    _run_mainloop ();

    signon_identity_info_free (info);
    g_object_unref (idty);
    g_object_unref (idty2);
}
END_TEST

START_TEST(test_unregistered_auth_session)
{
    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new ();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    GError *err = NULL;
    SignonAuthSession *as = signon_identity_create_session(idty,
                                                          "ssotest",
                                                           &err);
    /* give time to register the objects */
    g_timeout_add_seconds (2, test_quit_main_loop_cb, main_loop);
    _run_mainloop ();

    /*
     * give the time for identity to became idle
     * */
    sleep(SIGNOND_IDLE_TIMEOUT);
    SignonIdentity *idty2 = signon_identity_new ();

    /*
     * give time to handle unregistered signal
     * */
    g_timeout_add_seconds (5, test_quit_main_loop_cb, main_loop);
    _run_mainloop ();


    gchar* patterns[4];
    patterns[0] = g_strdup("mech1");
    patterns[1] = g_strdup("mech2");
    patterns[2] = g_strdup("mech3");
    patterns[3] = NULL;

    signon_auth_session_query_available_mechanisms(as,
                                                  (const gchar**)patterns,
                                                  test_auth_session_query_mechanisms_cb,
                                                  (gpointer)patterns);
    _run_mainloop ();

    g_object_unref (as);
    g_object_unref (idty);
    g_object_unref (idty2);

    g_free (patterns[0]);
    g_free (patterns[1]);
    g_free (patterns[2]);
    g_free (patterns[3]);
}
END_TEST

void free_identity_info_cb (gpointer data)
{
    SignonIdentityInfo *info;

    signon_identity_info_free (info);
}

void query_identities_cb (SignonAuthService *auth_service,
    SignonIdentityList *identity_list, const GError *error, gpointer user_data)
{
    SignonIdentityList *iter = identity_list;

    while (iter && !error)
    {
        SignonIdentityInfo *info = (SignonIdentityInfo *) iter->data;
        const gchar *caption = signon_identity_info_get_caption (info);

        g_print ("\tid=%d username='%s' caption='%s'\n",
                 signon_identity_info_get_id (info),
                 signon_identity_info_get_username (info),
                 caption);

        fail_unless (g_strcmp0 (caption, "MI-6") == 0,
                     "Wrong caption in identity");

        iter = g_list_next (iter);
    }
    g_list_free_full (identity_list, free_identity_info_cb);

    fail_unless (error == NULL, "There should be no error in callback");
    _stop_mainloop ();
}

START_TEST(test_query_identities)
{
    g_debug("%s", G_STRFUNC);

    SignonAuthService *asrv = signon_auth_service_new ();

    signon_auth_service_query_identities (asrv, NULL, NULL, query_identities_cb, NULL);

    g_timeout_add_seconds (5, test_quit_main_loop_cb, main_loop);
    _run_mainloop ();

    g_object_unref (asrv);
}
END_TEST

static void
test_regression_unref_process_cb (SignonAuthSession *self,
                                  GHashTable *reply,
                                  const GError *error,
                                  gpointer user_data)
{
    GValue *v_string;

    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        _stop_mainloop ();
        fail();
    }

    fail_unless (reply != NULL, "The result is empty");

    fail_unless (g_strcmp0 (user_data, "Hi there!") == 0,
                 "Didn't get expected user_data");

    v_string = g_hash_table_lookup(reply, "James");
    fail_unless (v_string != 0);
    fail_unless (g_strcmp0 (g_value_get_string (v_string), "Bond") == 0,
                 "Wrong reply data");

    g_hash_table_destroy (reply);

    /* The next line is actually the regression we want to test */
    g_object_unref (self);

    _stop_mainloop ();
}

START_TEST(test_regression_unref)
{
    SignonIdentity *idty;
    SignonAuthSession *auth_session;
    GHashTable *session_data;
    GError *error = NULL;
    GValue v_string = G_VALUE_INIT;
    gchar *test_msg = g_strdup ("Hi there!");

    g_debug ("%s", G_STRFUNC);

    guint id = new_identity();
    fail_unless (id != 0);
    idty = signon_identity_new_from_db (id);

    fail_unless (idty != NULL);
    auth_session = signon_auth_session_new_for_identity (idty, "ssotest",
                                                         &error);
    fail_unless (auth_session != NULL);

    session_data = g_hash_table_new (g_str_hash, g_str_equal);
    g_value_init (&v_string, G_TYPE_STRING);
    g_value_set_static_string (&v_string, "Bond");
    g_hash_table_insert (session_data, "James", &v_string);


    signon_auth_session_process (auth_session,
                                 session_data,
                                 "mech1",
                                 test_regression_unref_process_cb,
                                 test_msg);
    _run_mainloop ();

    g_free (test_msg);
    g_object_unref (idty);
    g_hash_table_unref (session_data);

}
END_TEST

Suite *
signon_suite(void)
{
    Suite *s = suite_create ("signon-glib");

    /* Core test case */
    TCase * tc_core = tcase_create("Core");
    tcase_add_checked_fixture (tc_core, _setup, _teardown);

    /*
     * 18 minutes timeout
     * */
    tcase_set_timeout(tc_core, 1080);
    tcase_add_test (tc_core, test_init);
    tcase_add_test (tc_core, test_query_methods);

    tcase_add_test (tc_core, test_query_mechanisms);
    tcase_add_test (tc_core, test_get_existing_identity);
    tcase_add_test (tc_core, test_get_nonexisting_identity);

    tcase_add_test (tc_core, test_auth_session_creation);
    tcase_add_test (tc_core, test_auth_session_query_mechanisms);
    tcase_add_test (tc_core, test_auth_session_query_mechanisms_nonexisting);
    tcase_add_test (tc_core, test_auth_session_process);
    tcase_add_test (tc_core, test_auth_session_process_failure);
    tcase_add_test (tc_core, test_auth_session_process_after_store);
    tcase_add_test (tc_core, test_store_credentials_identity);
    tcase_add_test (tc_core, test_remove_identity);
    tcase_add_test (tc_core, test_referenc_remove_identity);
    tcase_add_test (tc_core, test_referenc_add_identity);
    tcase_add_test (tc_core, test_info_identity);

    tcase_add_test (tc_core, test_query_identities);

    tcase_add_test (tc_core, test_signout_identity);
    tcase_add_test (tc_core, test_unregistered_identity);
    tcase_add_test (tc_core, test_unregistered_auth_session);

    tcase_add_test (tc_core, test_regression_unref);
    suite_add_tcase (s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite * s = signon_suite();
    SRunner * sr = srunner_create(s);

    srunner_set_xml(sr, "/tmp/result.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free (sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vim: set ai et tw=75 ts=4 sw=4: */

