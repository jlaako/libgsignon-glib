/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2013 Intel Corporation.
 *
 * Contact: Alexander Kanavin <alex.kanavin@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <glib.h>
#include <stdlib.h>
#include "libgsignon-glib/signon-auth-service.h"
#include "libgsignon-glib/signon-identity.h"

typedef struct {
    GMainLoop *main_loop;
    SignonSecurityContext *security_context;
} AclModifyUserData;

static void
signon_query_methods_cb (SignonAuthService *auth_service, gchar **methods,
                         const GError *error, gpointer user_data)
{
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_main_loop_quit (user_data);
        return;
    }

    if (!methods) {
        g_warning ("%s: %s", G_STRFUNC, "NULL methods");
        return;
    }

    gchar **pmethods = methods;

    g_print("Available authentication methods:\n");
    while (*pmethods)
    {
        g_print("\t%s\n", *pmethods);
        pmethods++;
    }
    g_strfreev (methods);
    g_main_loop_quit (user_data);
}

static void query_auth_methods(GMainLoop* main_loop)
{
    SignonAuthService* auth_service = signon_auth_service_new();
    
    signon_auth_service_query_methods (auth_service, 
                                       signon_query_methods_cb,
				                       main_loop);
    g_main_loop_run(main_loop);
    
    g_object_unref(auth_service);
}

static void
signon_query_mechanisms_cb (SignonAuthService *auth_service,
                            const gchar *method,
                            gchar **mechanisms,
                            const GError *error,
                            gpointer user_data)
{
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_main_loop_quit (user_data);
        return;
    }

    if (!mechanisms) {
        g_warning("%s: %s", G_STRFUNC, "NULL mechanisms");
        return;
    }

    gchar **pmechanisms = mechanisms;

    g_print("Available authentication mechanisms for method %s:\n", method);
    while (*pmechanisms)
    {
        g_print("\t%s\n", *pmechanisms);
        pmechanisms++;
    }
    g_strfreev (mechanisms);
    g_main_loop_quit (user_data);
}

static void query_auth_mechanisms(GMainLoop* main_loop, const gchar* method)
{
    SignonAuthService* auth_service = signon_auth_service_new();
    
    signon_auth_service_query_mechanisms (auth_service,
                                          method,
                                          signon_query_mechanisms_cb, 
                                          main_loop);
    g_main_loop_run(main_loop);
    
    g_object_unref(auth_service);
}

static void signon_query_identities_cb (SignonAuthService *auth_service,
    SignonIdentityList *identity_list, const GError *error, gpointer user_data)
{
    GList *iter = identity_list;
    
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_main_loop_quit (user_data);
        return;
    }
    
    g_print("Available identities:\n");
    while (iter)
    {
        SignonIdentityInfo *info = (SignonIdentityInfo *) iter->data;

        g_print ("\tid=%d caption='%s' ACL:",
                 signon_identity_info_get_id (info),
                 signon_identity_info_get_caption (info));

        SignonSecurityContextList *acl = signon_identity_info_get_access_control_list(info);
        for(acl = g_list_first(acl); acl != NULL; acl = g_list_next(acl)) {
            const SignonSecurityContext *context = acl->data;
            g_print(" (%s:%s)", signon_security_context_get_system_context(context),
                    signon_security_context_get_application_context(context));
        }
        g_print("\n");

        iter = g_list_next (iter);
    }
    g_list_free_full (identity_list, (GDestroyNotify)signon_identity_info_free);

    g_main_loop_quit (user_data);
}

static void query_auth_identities(GMainLoop* main_loop)
{
    SignonAuthService* auth_service = signon_auth_service_new();
    
    signon_auth_service_query_identities (auth_service,
                                          NULL, NULL,
                                          signon_query_identities_cb,
                                          main_loop);
    g_main_loop_run(main_loop);
    
    g_object_unref(auth_service);
}

static void signon_store_identity_cb(SignonIdentity *self,
                                                    guint32 id,
                                                    const GError *error,
                                                    gpointer user_data)
{
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_main_loop_quit (user_data);
        return;
    }

    g_print("Identity stored with id %d\n", id);
    g_main_loop_quit (user_data);
}

static void create_auth_identity(GMainLoop* main_loop, const gchar* identity_caption,
    const gchar* identity_method, const gchar* allowed_realms)
{
    const gchar* all_mechanisms[] = { "*", NULL };

    SignonIdentity* identity = signon_identity_new();
    SignonIdentityInfo* identity_info = signon_identity_info_new();
    signon_identity_info_set_caption(identity_info, identity_caption);
    signon_identity_info_set_method(identity_info, identity_method, all_mechanisms);
    if (g_strcmp0(identity_method, "password") == 0)
        signon_identity_info_set_secret(identity_info, NULL, TRUE);
    
    if (allowed_realms != NULL) {
        gchar** realms_array = g_strsplit(allowed_realms, ",", 0);
        signon_identity_info_set_realms(identity_info, (const gchar* const *) realms_array);
        g_strfreev(realms_array);
    }
    
    signon_identity_store_credentials_with_info (identity,
                                                 identity_info,
                                                 signon_store_identity_cb, 
                                                 main_loop);
    g_main_loop_run(main_loop);
    
    g_object_unref(identity);
    signon_identity_info_free(identity_info);
}

static void signon_remove_identity_cb(SignonIdentity *self,
                                                    const GError *error,
                                                    gpointer user_data)
{
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_main_loop_quit (user_data);
        return;
    }

    g_print("Identity removed\n");
    g_main_loop_quit (user_data);
}


static void remove_auth_identity(GMainLoop* main_loop, gint identity_id)
{
    SignonIdentity* identity = signon_identity_new_from_db(identity_id);
    signon_identity_remove (identity, 
                            signon_remove_identity_cb, 
                            main_loop);
    g_main_loop_run(main_loop);
    
    g_object_unref(identity);
}

static void auth_session_process_cb (GObject *source_object,
                                      GAsyncResult *res,
                                      gpointer user_data)
{
    g_debug("%s", G_STRFUNC);
    SignonAuthSession *auth_session = SIGNON_AUTH_SESSION (source_object);
    GVariant *v_reply;
    char *str_reply = NULL;
    GError *error = NULL;

    v_reply = signon_auth_session_process_finish (auth_session, res, &error);
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_error_free(error);
        g_main_loop_quit (user_data);
        return;
    }

    str_reply = g_variant_print (v_reply, TRUE);
    g_print("Got response: %s\n", str_reply);
    g_free (str_reply);
    g_variant_unref(v_reply);

    g_main_loop_quit (user_data);
}


static void get_google_token(GMainLoop* main_loop, gint identity_id,
                             const gchar* client_id, 
                             const gchar* client_secret)
{
    if (!client_id || !client_secret) {
        g_print("Must provide a client ID and secret (get them at https://code.google.com/apis/console/ )\n");
        exit(1);
    }
    
    SignonIdentity* identity = signon_identity_new_from_db(identity_id);
    SignonAuthSession* session = signon_identity_create_session(identity, "oauth", NULL);
    
    GVariantBuilder builder;
    GVariant* session_data;
    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add (&builder, "{sv}",
                           "ClientId", g_variant_new_string (client_id));
    g_variant_builder_add (&builder, "{sv}",
                           "ClientSecret", g_variant_new_string (client_secret));
    g_variant_builder_add (&builder, "{sv}",
                           "UiPolicy", g_variant_new_uint32 (SIGNON_POLICY_DEFAULT));
    g_variant_builder_add (&builder, "{sv}",
                           "ResponseType", g_variant_new_string ("code"));
    g_variant_builder_add (&builder, "{sv}",
                           "AuthHost", g_variant_new_string ("accounts.google.com"));
    g_variant_builder_add (&builder, "{sv}",
                           "AuthPath", g_variant_new_string ("/o/oauth2/auth"));
    g_variant_builder_add (&builder, "{sv}",
                           "RedirectUri", g_variant_new_string("https://localhost"));
    g_variant_builder_add (&builder, "{sv}",
                           "Scope", g_variant_new_string ("email"));
    g_variant_builder_add (&builder, "{sv}",
                           "ForceClientAuthViaRequestBody", g_variant_new_boolean(TRUE));
    g_variant_builder_add (&builder, "{sv}",
                           "TokenHost", g_variant_new_string("accounts.google.com"));
    g_variant_builder_add (&builder, "{sv}",
                           "TokenPath", g_variant_new_string("/o/oauth2/token"));
    session_data = g_variant_builder_end (&builder);

    signon_auth_session_process_async (session,
                                       session_data,
                                       "oauth2",
                                       NULL,
                                       auth_session_process_cb,
                                       main_loop);
    
    g_print("Geting token\n");
    g_main_loop_run (main_loop);

    g_object_unref(session);
    g_object_unref(identity);
} 

static void get_password(GMainLoop* main_loop, gint identity_id)
{
    SignonIdentity* identity = signon_identity_new_from_db(identity_id);
    SignonAuthSession* session = signon_identity_create_session(identity, "password", NULL);
    
    GVariantBuilder builder;
    GVariant* session_data;
    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
    session_data = g_variant_builder_end (&builder);

    signon_auth_session_process_async (session,
                                       session_data,
                                       "password",
                                       NULL,
                                       auth_session_process_cb,
                                       main_loop);
    
    g_print("Geting password\n");
    g_main_loop_run (main_loop);

    g_object_unref(session);
    g_object_unref(identity);
}

static void append_acl_cb(SignonIdentity *self, SignonIdentityInfo *info, const GError *error, gpointer user_data)
{
    AclModifyUserData *am_user_data = (AclModifyUserData *)user_data;
    SignonIdentityInfo *new_info;

    if (error) {
        g_warning("%s: %s", G_STRFUNC, error->message);
        goto clean_user_data;
    }

    new_info = signon_identity_info_copy(info);
    signon_identity_info_access_control_list_append(new_info, am_user_data->security_context);
    signon_identity_store_credentials_with_info(self, new_info, signon_store_identity_cb, am_user_data->main_loop);
    signon_identity_info_free(new_info);

clean_user_data:
    g_free(am_user_data);
}

static void append_acl(GMainLoop* main_loop, gint identity_id, SignonSecurityContext* security_context)
{
    AclModifyUserData *user_data = g_new0(AclModifyUserData, 1);
    user_data->main_loop = main_loop;
    user_data->security_context = security_context;

    SignonIdentity* identity = signon_identity_new_from_db(identity_id);
    signon_identity_query_info(identity, append_acl_cb, user_data);

    g_main_loop_run (main_loop);
    g_object_unref(identity);
}

static void remove_acl_cb(SignonIdentity *self, SignonIdentityInfo *info, const GError *error, gpointer user_data)
{
    AclModifyUserData *am_user_data = (AclModifyUserData *)user_data;

    if (error) {
        g_warning("%s: %s", G_STRFUNC, error->message);
        goto clean_user_data;
    }

    SignonSecurityContextList *new_list = signon_security_context_list_copy(signon_identity_info_get_access_control_list(info));
    SignonSecurityContextList *list_iter = new_list;

    gboolean list_changed = FALSE;
    while(list_iter != NULL) {
        SignonSecurityContext *curr_context = list_iter->data;
        if (g_strcmp0(signon_security_context_get_system_context(curr_context), am_user_data->security_context->sys_ctx) == 0
                && g_strcmp0(signon_security_context_get_application_context(curr_context), am_user_data->security_context->app_ctx) == 0) {
            signon_security_context_free(curr_context);
            new_list = g_list_remove_link(new_list, list_iter);
            list_changed = TRUE;
            break;
        }
        list_iter = g_list_next(list_iter);
    }

    if (list_changed) {
        signon_identity_info_set_access_control_list(info, new_list);
        signon_identity_store_credentials_with_info(self, info, signon_store_identity_cb, am_user_data->main_loop);
    } else {
        signon_security_context_list_free(new_list);
        g_main_loop_quit (am_user_data->main_loop);
    }

clean_user_data:
    signon_security_context_free(am_user_data->security_context);
    g_free(am_user_data);
}

static void remove_acl(GMainLoop* main_loop, gint identity_id, SignonSecurityContext* security_context)
{
    AclModifyUserData *am_user_data = g_new0(AclModifyUserData, 1);
    am_user_data->main_loop = main_loop;
    am_user_data->security_context = security_context;

    SignonIdentity* identity = signon_identity_new_from_db(identity_id);
    signon_identity_query_info(identity, remove_acl_cb, am_user_data);

    g_main_loop_run (main_loop);
    g_object_unref(identity);
}

SignonSecurityContext *create_security_context_from_args(const gchar *sys_ctx, const gchar *app_ctx) {
    if (sys_ctx && app_ctx) {
        return signon_security_context_new_from_values(sys_ctx, app_ctx);
    }
    return NULL;
}

int
main (int argc, char *argv[])
{
   
    GError *error = NULL;
    GOptionContext *context;
    GMainLoop* main_loop = NULL;
    
    gboolean query_methods = FALSE;
    gchar* query_mechanisms_method = NULL;
    gboolean query_identities = FALSE;
    gchar* create_identity_caption = NULL;
    gchar* create_identity_method = NULL;
    gchar* create_identity_realms = NULL;
    gint remove_identity_id = 0;
    
    GOptionEntry main_entries[] =
    {
        { "query-methods", 0, 0, G_OPTION_ARG_NONE, &query_methods, "Query available authentication methods", NULL},
        { "query-mechanisms", 0, 0, G_OPTION_ARG_STRING, &query_mechanisms_method, "Query available mechanisms for an authentication method", "method"},
        { "query-identities", 0, 0, G_OPTION_ARG_NONE, &query_identities, "Query available authentication identities", NULL},
        { "create-identity", 0, 0, G_OPTION_ARG_STRING, &create_identity_caption, "Create a new authentication identity", "caption"},
        { "identity-method", 0, 0, G_OPTION_ARG_STRING, &create_identity_method, "Method to use when creating identity", "method"},
        { "identity-realms", 0, 0, G_OPTION_ARG_STRING, &create_identity_realms, "A comma-separated list of allowed realms for the identity", "realms"},
        { "remove-identity", 0, 0, G_OPTION_ARG_INT, &remove_identity_id, "Remove an authentication identity", "id"},
        { NULL }
    };

    gchar* client_id = NULL;
    gchar* client_secret = NULL;
    gint google_identity_id = 0;

    GOptionEntry oauth_entries[] =
    {
        { "get-google-token", 0, 0, G_OPTION_ARG_INT, &google_identity_id, "Get an OAuth2 access token from Google", "identity-id"},
        { "client-id", 0, 0, G_OPTION_ARG_STRING, &client_id, "Client ID", "id" },
        { "client-secret", 0, 0, G_OPTION_ARG_STRING, &client_secret, "Client secret", "secret" },
        { NULL }
    };

    gint password_identity_id = 0;

    GOptionEntry password_entries[] =
    {
        { "get-password", 0, 0, G_OPTION_ARG_INT, &password_identity_id, "Get an identity's username and password using 'password' plugin", "identity-id"},
        { NULL }
    };

    gint add_acl_ctx_id = 0;
    gint remove_acl_ctx_id = 0;
    gchar *acl_sys_ctx = NULL;
    gchar *acl_app_ctx = NULL;

    GOptionEntry acl_entries[] =
    {
        { "add-context", 0, 0, G_OPTION_ARG_INT, &add_acl_ctx_id, "Add security context to identity", "identity-id"},
        { "remove-context", 0, 0, G_OPTION_ARG_INT, &remove_acl_ctx_id, "Remove security context from identity", "identity-id"},
        { "system-context", 0, 0, G_OPTION_ARG_STRING, &acl_sys_ctx, "System context", "system-context"},
        { "application-context", 0, 0, G_OPTION_ARG_STRING, &acl_app_ctx, "Application context", "application-context"},
        { NULL }
    };
    
    
#if !GLIB_CHECK_VERSION (2, 36, 0)
    g_type_init ();
#endif   
    
    context = g_option_context_new ("- gSSO application example");
    g_option_context_add_main_entries (context, main_entries, NULL);
    GOptionGroup* oauth_group = g_option_group_new("oauth", "OAuth-specific options", "OAuth-specific options", NULL, NULL);
    g_option_group_add_entries(oauth_group, oauth_entries);
    g_option_context_add_group (context, oauth_group);

    GOptionGroup* password_group = g_option_group_new("password", "Password-specific options", "Password-specific options", NULL, NULL);
    g_option_group_add_entries(password_group, password_entries);
    g_option_context_add_group (context, password_group);

    GOptionGroup* acl_group = g_option_group_new("acl", "ACL-specific options", "ACL-specific options", NULL, NULL);
    g_option_group_add_entries(acl_group, acl_entries);
    g_option_context_add_group (context, acl_group);
    
    if (!g_option_context_parse (context, &argc, &argv, &error)) {
        g_print ("option parsing failed: %s\n", error->message);
        g_option_context_free(context);
        exit (1);
    }
    g_option_context_free(context);
    
    main_loop = g_main_loop_new(NULL, FALSE);
    
    if (query_methods) {
        query_auth_methods(main_loop);
    } else if (query_mechanisms_method) {
        query_auth_mechanisms(main_loop, query_mechanisms_method);
    } else if (query_identities) {
        query_auth_identities(main_loop);
    } else if (create_identity_caption) {
        create_auth_identity(main_loop, create_identity_caption, create_identity_method, create_identity_realms);
    } else if (remove_identity_id > 0) {
        remove_auth_identity(main_loop, remove_identity_id);
    } else if (google_identity_id > 0) {
        get_google_token(main_loop, google_identity_id, client_id, client_secret);
    } else if (password_identity_id > 0) {
        get_password(main_loop, password_identity_id);
    } else if (add_acl_ctx_id > 0 || remove_acl_ctx_id) {
        SignonSecurityContext *sec_ctx = create_security_context_from_args(acl_sys_ctx, acl_app_ctx);
        if (sec_ctx) {
            if (add_acl_ctx_id > 0) {
                append_acl(main_loop, add_acl_ctx_id, sec_ctx);
            } else {
                remove_acl(main_loop, remove_acl_ctx_id, sec_ctx);
            }
        } else {
            g_print("Must provide security context with --system-context and --application-context options\n");
        }
    }
        
    g_main_loop_unref(main_loop);
    if (client_id)
        g_free (client_id);
    if (client_secret)
        g_free(client_secret);
    if (query_mechanisms_method)
        g_free(query_mechanisms_method);
    if (create_identity_caption)
        g_free(create_identity_caption);
    if (create_identity_method)
        g_free(create_identity_method);
    if (create_identity_realms)
        g_free(create_identity_realms);
    if (acl_sys_ctx)
        g_free(acl_sys_ctx);
    if (acl_app_ctx)
        g_free(acl_app_ctx);
}
