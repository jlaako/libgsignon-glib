/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libgsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2012-2014 Intel Corporation.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@nokia.com>
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

#ifndef _SIGNON_IDENTITY_H_
#define _SIGNON_IDENTITY_H_

#include <libgsignon-glib/signon-auth-session.h>
#include <libgsignon-glib/signon-identity-info.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define SIGNON_TYPE_IDENTITY             (signon_identity_get_type ())
#define SIGNON_IDENTITY(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), SIGNON_TYPE_IDENTITY, SignonIdentity))
#define SIGNON_IDENTITY_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), SIGNON_TYPE_IDENTITY, SignonIdentityClass))
#define SIGNON_IS_IDENTITY(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SIGNON_TYPE_IDENTITY))
#define SIGNON_IDENTITY_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), SIGNON_TYPE_IDENTITY, SignonIdentityClass))

typedef struct _SignonIdentityClass SignonIdentityClass;
typedef struct _SignonIdentityPrivate SignonIdentityPrivate;

/**
 * _SignonIdentityClass: (skip):
 * @parent_class: reference to a parent class
 *
 * Opaque struct. Use the accessor functions below.
 */
struct _SignonIdentityClass
{
    GObjectClass parent_class;
};

/**
 * _SignonIdentity: (skip):
 *
 * Opaque struct. Use the accessor functions below.
 */
struct _SignonIdentity
{
    GObject parent_instance;
    SignonIdentityPrivate *priv;
};

/**
 * SignonIdentityVoidCb:
 * @self: the #SignonIdentity.
 * @error: a #GError if an error occurred, or %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * Generic callback to be passed to several #SignonIdentity methods.
 */
typedef void (*SignonIdentityVoidCb) (SignonIdentity *self,
                                      const GError *error,
                                      gpointer user_data);

/**
 * SignonIdentityRemovedCb:
 *
 * Callback to be passed to signon_identity_remove().
 */
typedef SignonIdentityVoidCb SignonIdentityRemovedCb;
/**
 * SignonIdentityCredentialsUpdatedCb:
 *
 * Callback to be passed to signon_identity_request_credentials_update().
 */
typedef SignonIdentityVoidCb SignonIdentityCredentialsUpdatedCb;
/**
 * SignonIdentitySignedOutCb:
 *
 * Callback to be passed to signon_identity_signout().
 */
typedef SignonIdentityVoidCb SignonIdentitySignedOutCb;
/**
 * SignonIdentityReferenceAddedCb:
 *
 * Callback to be passed to signon_identity_add_reference().
 */
typedef SignonIdentityVoidCb SignonIdentityReferenceAddedCb;
/**
 * SignonIdentityReferenceRemovedCb:
 *
 * Callback to be passed to signon_identity_remove_reference().
 */
typedef SignonIdentityVoidCb SignonIdentityReferenceRemovedCb;

GType signon_identity_get_type (void) G_GNUC_CONST;

SignonIdentity *signon_identity_new_from_db (guint32 id);
SignonIdentity *signon_identity_new (void);

SignonIdentity *signon_identity_new_with_context_from_db (guint32 id,
                                                          const gchar *application_context);
SignonIdentity *signon_identity_new_with_context (const gchar *application_context);

const GError *signon_identity_get_last_error (SignonIdentity *identity);

SignonAuthSession *signon_identity_create_session(SignonIdentity *self,
                                                  const gchar *method,
                                                  GError **error);

/**
 * SignonIdentityStoreCredentialsCb:
 * @self: the #SignonIdentity.
 * @id: the numeric ID of the identity in the database.
 * @error: a #GError if an error occurred, or %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * Callback to be passed to signon_identity_store_credentials_with_args() or
 * signon_identity_store_credentials_with_info().
 */
typedef void (*SignonIdentityStoreCredentialsCb) (SignonIdentity *self,
                                                  guint32 id,
                                                  const GError *error,
                                                  gpointer user_data);

void signon_identity_store_credentials_with_info(SignonIdentity *self,
                                                 const SignonIdentityInfo *info,
                                                 SignonIdentityStoreCredentialsCb cb,
                                                 gpointer user_data);

void signon_identity_store_credentials_with_args(SignonIdentity *self,
                        const gchar *username,
                        const gchar *secret,
                        const gboolean store_secret,
                        GHashTable *methods,
                        const gchar *caption,
                        const gchar* const *realms,
                        const SignonSecurityContext *owner,
                        GList *access_control_list,
                        SignonIdentityType type,
                        SignonIdentityStoreCredentialsCb cb,
                        gpointer user_data);

/**
 * SignonIdentityVerifyCb:
 * @self: the #SignonIdentity.
 * @valid: whether the verification succeeded.
 * @error: a #GError if an error occurred, or %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * Callback to be passed to signon_identity_verify_user().
 */
typedef void (*SignonIdentityVerifyCb) (SignonIdentity *self,
                                        gboolean valid,
                                        const GError *error,
                                        gpointer user_data);

void signon_identity_verify_user(SignonIdentity *self,
                                 GVariant *args,
                                 SignonIdentityVerifyCb cb,
                                 gpointer user_data);

/**
 * SignonIdentityInfoCb:
 * @self: the #SignonIdentity.
 * @info: (transfer none): the #SignonIdentityInfo for @self.
 * @error: a #GError if an error occurred, or %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * Callback to be passed to signon_identity_query_info().
 */
typedef void (*SignonIdentityInfoCb) (SignonIdentity *self,
                                      SignonIdentityInfo *info,
                                      const GError *error,
                                      gpointer user_data);

void signon_identity_query_info(SignonIdentity *self,
                                SignonIdentityInfoCb cb,
                                gpointer user_data);

void signon_identity_remove(SignonIdentity *self,
                            SignonIdentityRemovedCb cb,
                            gpointer user_data);

void signon_identity_request_credentials_update(SignonIdentity *self,
                                                const gchar *message,
                                                SignonIdentityCredentialsUpdatedCb cb,
                                                gpointer user_data);

void signon_identity_signout(SignonIdentity *self,
                             SignonIdentitySignedOutCb cb,
                             gpointer user_data);

void signon_identity_add_reference(SignonIdentity *self,
                                   const gchar *reference,
                                   SignonIdentityReferenceAddedCb cb,
                                   gpointer user_data);

void signon_identity_remove_reference(SignonIdentity *self,
                                      const gchar *reference,
                                      SignonIdentityReferenceRemovedCb cb,
                                      gpointer user_data);

/**
 * SignonIdentitySessionReadyCb:
 * @self: the #SignonAuthSession.
 * @error: a #GError if an error occurred, or %NULL otherwise.
 * @connection: a #GDBusConnection for the session.
 * @bus_name: a D-Bus bus name for the session.
 * @object_path: a D-Bus object path for the session.
 *
 * Callback to be passed to signon_identity_get_auth_session().
 */
typedef void (*SignonIdentitySessionReadyCb) (SignonAuthSession *self,
                                              GError *error,
                                              GDBusConnection *connection,
                                              const gchar *bus_name,
                                              const gchar *object_path);
void signon_identity_get_auth_session(SignonIdentity *self,
                                      SignonAuthSession *session,
                                      const gchar *method,
                                      SignonIdentitySessionReadyCb cb);
                                         

G_END_DECLS

#endif /* _SIGNON_IDENTITY_H_ */
