/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libgsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2011-2012 Canonical Ltd.
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
 * SECTION:signon-identity-info
 * @title: SignonIdentityInfo
 * @short_description: data contained in a SignonIdentity.
 *
 * #SignonIdentityInfo represents data contained in a database record for an identity
 * and provides getters and setters for individual items.
 * 
 * See #SignonIdentity for a detailed discussion
 * of what each item means and how and when it's used. 
 */

#include "signon-identity-info.h"

#include "signon-internals.h"
#include "signon-utils.h"

G_DEFINE_BOXED_TYPE (SignonIdentityInfo, signon_identity_info,
                     (GBoxedCopyFunc)signon_identity_info_copy,
                     (GBoxedFreeFunc)signon_identity_info_free);


static GVariant *
signon_variant_new_string (const gchar *string)
{
    return g_variant_new_string (string != NULL ? string : "");
}

static const gchar *identity_info_get_secret (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);

    return info->secret;
}

static void identity_info_set_id (SignonIdentityInfo *info, gint id)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (id >= 0);

    info->id = id;
}

static void identity_methods_copy (gpointer key,
                                   gpointer value,
                                   gpointer user_data)
{
    g_hash_table_insert ((GHashTable *) user_data,
                         g_strdup ((const gchar *) key),
                         g_strdupv ((gchar **) value));
}

/**
 * signon_identity_info_set_methods:
 * @info: the #SignonIdentityInfo.
 * @methods: (transfer none): (element-type utf8 GStrv): methods.
 *
 * Set authentication methods that are allowed to be used with this identity.
 */
void signon_identity_info_set_methods (SignonIdentityInfo *info,
                                       GHashTable *methods)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (methods != NULL);

    DEBUG("%s", G_STRFUNC);

    GHashTable *new_methods =
        g_hash_table_new_full (g_str_hash,
                               g_str_equal,
                               g_free,
                               (GDestroyNotify) g_strfreev);
    g_hash_table_foreach (methods, identity_methods_copy, new_methods);
    g_hash_table_unref (info->methods);
    info->methods = new_methods;
}

/**
 * signon_identity_info_own_methods:
 * @info: the #SignonIdentityInfo.
 * @methods: (transfer none): (element-type utf8 GStrv): methods.
 *
 * Set authentication methods that are allowed to be used with this identity.
 *
 * This function will just increment reference count of hash table, so
 * it should be constructed with #g_hash_table_new_full.
 */
void signon_identity_info_own_methods (SignonIdentityInfo *info,
                                       GHashTable *methods)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (methods != NULL);

    DEBUG("%s", G_STRFUNC);

    g_hash_table_ref (methods);
    info->methods = methods;
}

SignonIdentityInfo *
signon_identity_info_new_from_variant (GVariant *variant)
{
    GVariant *method_map;
    GVariant *owner;
    GVariant *acl;

    if (!variant)
        return NULL;

    SignonIdentityInfo *info = signon_identity_info_new ();

    DEBUG("%s: ", G_STRFUNC);

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_ID,
                      "u",
                      &info->id);

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_USERNAME,
                      "s",
                      &info->username);

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_SECRET,
                      "s",
                      &info->secret);

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_STORESECRET,
                      "b",
                      &info->store_secret);

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_CAPTION,
                      "s",
                      &info->caption);

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_REALMS,
                      "^as",
                      &info->realms);

    /* get the methods */
    if (g_variant_lookup (variant,
                          SIGNOND_IDENTITY_INFO_AUTHMETHODS,
                          "@a{sas}",
                          &method_map))
    {
        GVariantIter iter;
        gchar *method;
        gchar **mechanisms;

        g_variant_iter_init (&iter, method_map);
        while (g_variant_iter_next (&iter, "{s^as}", &method, &mechanisms))
        {
            g_hash_table_insert (info->methods, method, mechanisms);
        }
        g_variant_unref (method_map);
    }

    if (g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_OWNER,
                      "@(ss)",
                      &owner))
    {
        info->owner = signon_security_context_deconstruct_variant (owner);
        g_variant_unref (owner);
    }

    if (g_variant_lookup (variant,
                          SIGNOND_IDENTITY_INFO_ACL,
                          "@a(ss)",
                          &acl))
    {
        info->access_control_list =
            signon_security_context_list_deconstruct_variant (acl);
        g_variant_unref (acl);
    }

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_TYPE,
                      "i",
                      &info->type);

    return info;
}

GVariant *
signon_identity_info_to_variant (const SignonIdentityInfo *self)
{
    GVariantBuilder builder;
    GVariantBuilder method_builder;
    GVariant *method_map;
    GHashTableIter iter;
    const gchar *method;
    const gchar **mechanisms;

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

    g_variant_builder_add (&builder, "{sv}",
                           SIGNOND_IDENTITY_INFO_ID,
                           g_variant_new_uint32 (self->id));

    if (self->username != NULL) {
        g_variant_builder_add (&builder, "{sv}",
                               SIGNOND_IDENTITY_INFO_USERNAME,
                               signon_variant_new_string (self->username));
    }

    if (self->secret != NULL) {
        g_variant_builder_add (&builder, "{sv}",
                               SIGNOND_IDENTITY_INFO_SECRET,
                               signon_variant_new_string (self->secret));
    }

    if (self->caption != NULL) {
        g_variant_builder_add (&builder, "{sv}",
                               SIGNOND_IDENTITY_INFO_CAPTION,
                               signon_variant_new_string (self->caption));
    }

    g_variant_builder_add (&builder, "{sv}",
                           SIGNOND_IDENTITY_INFO_STORESECRET,
                           g_variant_new_boolean (self->store_secret));

    if (g_hash_table_size(self->methods) > 0) {
        g_variant_builder_init (&method_builder,
                                (const GVariantType *)"a{sas}");
        g_hash_table_iter_init (&iter, self->methods);
        while (g_hash_table_iter_next (&iter,
                                       (gpointer)&method,
                                       (gpointer)&mechanisms))
        {
            g_variant_builder_add (&method_builder, "{s^as}",
                                   method,
                                   mechanisms);
        }
        method_map = g_variant_builder_end (&method_builder);

        g_variant_builder_add (&builder, "{sv}",
                               SIGNOND_IDENTITY_INFO_AUTHMETHODS,
                               method_map);
    }

    if (self->realms != NULL)
    {
        g_variant_builder_add (&builder, "{sv}",
                               SIGNOND_IDENTITY_INFO_REALMS,
                               g_variant_new_strv ((const gchar * const *)
                                                   self->realms,
                                                   -1));
    }

    if (self->owner != NULL)
    {
        g_variant_builder_add (&builder, "{sv}",
                               SIGNOND_IDENTITY_INFO_OWNER,
                               signon_security_context_build_variant (
                                                                  self->owner));
    }

    if (self->access_control_list != NULL)
    {
        g_variant_builder_add (&builder, "{sv}",
                               SIGNOND_IDENTITY_INFO_ACL,
                               signon_security_context_list_build_variant (
                                                    self->access_control_list));
    }

    g_variant_builder_add (&builder, "{sv}",
                           SIGNOND_IDENTITY_INFO_TYPE,
                           g_variant_new_int32 (self->type));

    return g_variant_builder_end (&builder);
}

/*
 * Public methods:
 */

/**
 * signon_identity_info_new:
 *
 * Creates a new #SignonIdentityInfo item.
 *
 * Returns: a new #SignonIdentityInfo item.
 */
SignonIdentityInfo *signon_identity_info_new ()
{
    SignonIdentityInfo *info = g_slice_new0 (SignonIdentityInfo);
    info->methods = g_hash_table_new_full (g_str_hash,
                                           g_str_equal,
                                           g_free,
                                           (GDestroyNotify) g_strfreev);
    info->store_secret = FALSE;

    return info;
}

/**
 * signon_identity_info_free:
 * @info: the #SignonIdentityInfo.
 *
 * Destroys the given #SignonIdentityInfo item.
 */
void signon_identity_info_free (SignonIdentityInfo *info)
{
    if (info == NULL) return;

    g_free (info->username);
    g_free (info->secret);
    g_free (info->caption);

    g_hash_table_unref (info->methods);

    g_strfreev (info->realms);
    signon_security_context_free (info->owner);
    signon_security_context_list_free (info->access_control_list);

    g_slice_free (SignonIdentityInfo, info);
}

/**
 * signon_identity_info_copy:
 * @other: the #SignonIdentityInfo.
 *
 * Get a newly-allocated copy of @info.
 *
 * Returns: a copy of the given #SignonIdentityInfo, or %NULL on failure.
 */
SignonIdentityInfo *signon_identity_info_copy (const SignonIdentityInfo *other)
{
    g_return_val_if_fail (other != NULL, NULL);
    SignonIdentityInfo *info = signon_identity_info_new ();

    identity_info_set_id (info, signon_identity_info_get_id (other));

    signon_identity_info_set_username (info,
        signon_identity_info_get_username (other));

    signon_identity_info_set_secret (info, identity_info_get_secret(other),
        signon_identity_info_get_storing_secret (other));

    signon_identity_info_set_caption (info,
        signon_identity_info_get_caption(other));

    signon_identity_info_set_methods (info,
        signon_identity_info_get_methods (other));

    signon_identity_info_set_realms (info,
        signon_identity_info_get_realms (other));

    signon_identity_info_set_owner (info,
        signon_identity_info_get_owner (other));

    signon_identity_info_set_access_control_list (info,
        signon_identity_info_get_access_control_list (other));

    signon_identity_info_set_identity_type (info,
        signon_identity_info_get_identity_type (other));

    return info;
}

/**
 * signon_identity_info_get_id:
 * @info: the #SignonIdentityInfo.
 *
 * Get the numeric identity ID of @info.
 *
 * Returns: the numeric ID of the identity.
 */
gint signon_identity_info_get_id (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, -1);
    return info->id;
}

/**
 * signon_identity_info_get_username:
 * @info: the #SignonIdentityInfo.
 *
 * Get the username associated with an identity.
 *
 * Returns: the username, or %NULL.
 */
const gchar *signon_identity_info_get_username (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->username;
}

/**
 * signon_identity_info_get_storing_secret:
 * @info: the #SignonIdentityInfo.
 *
 * Get whether the secret of @info should be stored by gSSO in the secret database.
 *
 * Returns: %TRUE if gSSO must store the secret, %FALSE otherwise.
 */
gboolean signon_identity_info_get_storing_secret (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, FALSE);
    return info->store_secret;
}

/**
 * signon_identity_info_get_caption:
 * @info: the #SignonIdentityInfo.
 *
 * Get the display name of @info.
 *
 * Returns: the display name for the identity.
 */
const gchar *signon_identity_info_get_caption (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->caption;
}

/**
 * signon_identity_info_get_methods:
 * @info: the #SignonIdentityInfo.
 *
 * Get a hash table of the methods and mechanisms of @info. See 
 * signon_identity_info_set_methods().
 *
 * Returns: (transfer none): (element-type utf8 GStrv): the table of allowed
 * methods and mechanisms.
 */
GHashTable *signon_identity_info_get_methods (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->methods;
}

/**
 * signon_identity_info_get_realms:
 * @info: the #SignonIdentityInfo.
 *
 * Get an array of the allowed realms of @info.
 *
 * Returns: (transfer none): a %NULL terminated array of realms.
 */
const gchar* const *signon_identity_info_get_realms (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return (const gchar* const *)info->realms;
}

/**
 * signon_identity_info_get_owner:
 * @info: the #SignonIdentityInfo.
 *
 * Get identity owner's security context. 
 * 
 * Returns: (transfer none): a security context.
 */
const SignonSecurityContext *signon_identity_info_get_owner (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->owner;
}

/**
 * signon_identity_info_get_access_control_list:
 * @info: the #SignonIdentityInfo.
 *
 * Get an access control list associated with an identity. 
 *
 * Returns: (transfer none): a list of ACL security contexts.
 */
SignonSecurityContextList *signon_identity_info_get_access_control_list (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->access_control_list;
}

/**
 * signon_identity_info_get_identity_type:
 * @info: the #SignonIdentityInfo.
 *
 * Get the type of the identity.
 *
 * Returns: the type of the identity.
 */
SignonIdentityType signon_identity_info_get_identity_type (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, -1);
    return (SignonIdentityType)info->type;
}


static void _replace_string (gchar **dst, const gchar *src)
{
    gchar *new_str = g_strdup (src);
    g_free (*dst);
    *dst = new_str;
}

/**
 * signon_identity_info_set_username:
 * @info: the #SignonIdentityInfo.
 * @username: the username.
 *
 * Sets the username for the identity.
 *
 */
void signon_identity_info_set_username (SignonIdentityInfo *info,
                                        const gchar *username)
{
    g_return_if_fail (info != NULL);

    _replace_string (&info->username, username);
}

/**
 * signon_identity_info_set_secret:
 * @info: the #SignonIdentityInfo.
 * @secret: the secret.
 * @store_secret: whether signond should store the secret in its DB.
 *
 * Sets the secret (password) for the identity, and whether the gSSO daemon
 * should remember it.
 *
 */
void signon_identity_info_set_secret (SignonIdentityInfo *info,
                                      const gchar *secret,
                                      gboolean store_secret)
{
    g_return_if_fail (info != NULL);

    _replace_string (&info->secret, secret);
    info->store_secret = store_secret;
}

/**
 * signon_identity_info_set_caption:
 * @info: the #SignonIdentityInfo.
 * @caption: the caption.
 *
 * Sets the caption (display name) for the identity.
 *
 */
void signon_identity_info_set_caption (SignonIdentityInfo *info,
                                       const gchar *caption)
{
    g_return_if_fail (info != NULL);

    _replace_string (&info->caption, caption);
}

/**
 * signon_identity_info_set_method:
 * @info: the #SignonIdentityInfo.
 * @method: an authentication method.
 * @mechanisms: a %NULL-terminated list of mechanisms.
 *
 * Adds a method to the list of allowed authentication methods. 
 */
void signon_identity_info_set_method (SignonIdentityInfo *info, const gchar *method,
                                      const gchar* const *mechanisms)
{
    g_return_if_fail (info != NULL);

    g_return_if_fail (info->methods != NULL);
    g_return_if_fail (method != NULL);
    g_return_if_fail (mechanisms != NULL);

    g_hash_table_replace (info->methods,
                          g_strdup(method), g_strdupv((gchar **)mechanisms));
}

/**
 * signon_identity_info_remove_method:
 * @info: the #SignonIdentityInfo.
 * @method: an authentication method.
 *
 * Remove @method from the list of allowed authentication methods.
 */
void signon_identity_info_remove_method (SignonIdentityInfo *info, const gchar *method)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (info->methods != NULL);

    g_hash_table_remove (info->methods, method);
}

/**
 * signon_identity_info_set_realms:
 * @info: the #SignonIdentityInfo.
 * @realms: a %NULL-terminated list of realms.
 *
 * Specify what realms this identity can be used in. 
 */
void signon_identity_info_set_realms (SignonIdentityInfo *info,
                                      const gchar* const *realms)
{
    g_return_if_fail (info != NULL);

    gchar **new_realms = g_strdupv ((gchar **) realms);

    if (info->realms) g_strfreev (info->realms);

    info->realms = new_realms;
}

/**
 * signon_identity_info_set_owner:
 * @info: the #SignonIdentityInfo.
 * @owner: (transfer none): a security context of owner.
 *
 * Set identity owner's security context. 
 */
void signon_identity_info_set_owner (SignonIdentityInfo *info,
                                     const SignonSecurityContext *owner)
{
    g_return_if_fail (info != NULL);

    SignonSecurityContext *new_owner = signon_security_context_copy (owner);

    if (info->owner) signon_security_context_free (info->owner);

    info->owner = new_owner;
}

/**
 * signon_identity_info_set_owner_from_values:
 * @info: the #SignonIdentityInfo.
 * @system_context: owner's system context.
 * @application_context: owner's application context.
 *
 * Set identity owner's security context. 
 */
void signon_identity_info_set_owner_from_values (
                                               SignonIdentityInfo *info,
                                               const gchar *system_context,
                                               const gchar *application_context)
{
    g_return_if_fail (info != NULL &&
                      system_context != NULL &&
                      application_context != NULL);

    if (info->owner) signon_security_context_free (info->owner);

    info->owner = signon_security_context_new_from_values(system_context,
                                                          application_context);
}

/**
 * signon_identity_info_set_access_control_list:
 * @info: the #SignonIdentityInfo.
 * @access_control_list: (transfer none): a list of ACL security contexts.
 *
 * Set an access control list associated with an identity. 
 */
void signon_identity_info_set_access_control_list (SignonIdentityInfo *info,
                                 SignonSecurityContextList *access_control_list)
{
    g_return_if_fail (info != NULL);

    SignonSecurityContextList *new_acl =
        signon_security_context_list_copy (access_control_list);

    if (info->access_control_list)
        signon_security_context_list_free (info->access_control_list);

    info->access_control_list = new_acl;
}

/**
 * signon_identity_info_access_control_list_append:
 * @info: the #SignonIdentityInfo.
 * @security_context: (transfer full): a security context to be appended.
 *
 * Appends a new #SignonSecurityContext item to the access control list.
 */
void signon_identity_info_access_control_list_append (
                                        SignonIdentityInfo *info,
                                        SignonSecurityContext *security_context)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (security_context != NULL);

    info->access_control_list = g_list_append (info->access_control_list,
                                               security_context);
}

/**
 * signon_identity_info_set_identity_type:
 * @info: the #SignonIdentityInfo.
 * @type: the type of the identity.
 *
 * Specifies the type of this identity.
 */
void signon_identity_info_set_identity_type (SignonIdentityInfo *info,
                                             SignonIdentityType type)
{
    g_return_if_fail (info != NULL);
    info->type = (gint) type;
}
