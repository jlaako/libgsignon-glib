/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libgsignon-glib
 *
 * Copyright (C) 2012-2013 Intel Corporation.
 *
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
 * SECTION:signon-security-context
 * @title: SignonSecurityContext
 * @short_description: representation of a security context.
 *
 * The #SignonSecurityContext represents a security context within
 * system and also within application. Security contexts are used:
 * 
 * - within identities to specify the owner of the identity, and 
 * users of the identity (items on the access control list). See #SignonIdentity.
 * - by gSSO daemon to identify the application accessing the gSSO service and
 * to determine if the application is an identity's owner, or is on the identity's access
 * control list, and make access control decisions accordingly.
 * 
 * #SignonSecurityContext contains two strings: a system context and an 
 * application context.
 *
 * System context can be a binary path, SMACK-label, or MSSF token. Specific 
 * interpretation of the system context value is performed by a gSSO extension module.
 * The default gSSO extension expects binary paths.
 * 
 * Application context identifies a script or a webpage within an application,
 * and it's used for providing access control to runtime environments (when making an access
 * control decision requires not only a binary identifier, but also information
 * about what the binary is doing). 
 * 
 * System context and application context can contain a wildcard
 * operator "*" to match 'any', while "" matches 'none' when a default
 * gSSO extension is used. The system context is always evaluated first 
 * and if a match is found, only then the application context is evaluated.
 * Check the documentation of a platform specific extension to determine
 * any particular match rules used by a custom ACM (Access Control Manager).
 */

#include "signon-security-context.h"

G_DEFINE_BOXED_TYPE (SignonSecurityContext, signon_security_context,
                     (GBoxedCopyFunc) signon_security_context_copy,
                     (GBoxedFreeFunc) signon_security_context_free);

/**
 * signon_security_context_new:
 *
 * Allocates a new security context item.
 *
 * Returns: (transfer full): allocated #SignonSecurityContext.
 */
SignonSecurityContext *
signon_security_context_new (void)
{
    SignonSecurityContext *ctx;

    ctx = g_slice_new0 (SignonSecurityContext);
    ctx->sys_ctx = g_strdup ("");
    ctx->app_ctx = g_strdup ("");

    return ctx;
}

/**
 * signon_security_context_new_from_values:
 * @system_context: system security context (such as SMACK/MSSF label/token).
 * @application_context: application security context (such as a script name).
 *
 * Allocates and initializes a new security context item.
 *
 * Returns: (transfer full): allocated #SignonSecurityContext.
 */
SignonSecurityContext *
signon_security_context_new_from_values (const gchar *system_context,
                                         const gchar *application_context)
{
    SignonSecurityContext *ctx;

    g_return_val_if_fail (system_context != NULL, NULL);

    ctx = g_slice_new0 (SignonSecurityContext);
    ctx->sys_ctx = g_strdup (system_context);
    if (application_context)
        ctx->app_ctx = g_strdup (application_context);
    else
        ctx->app_ctx = g_strdup ("");

    return ctx;
}

/**
 * signon_security_context_copy:
 * @src_ctx: source security context to copy.
 *
 * Copy a security context item.
 *
 * Returns: (transfer full): a copy of the #SignonSecurityContext item.
 */
SignonSecurityContext *
signon_security_context_copy (const SignonSecurityContext *src_ctx)
{
    if (!src_ctx)
        return NULL;

    return signon_security_context_new_from_values (src_ctx->sys_ctx,
                                                    src_ctx->app_ctx);
}

/**
 * signon_security_context_free:
 * @ctx: #SignonSecurityContext to be freed.
 *
 * Frees a security context item.
 */
void
signon_security_context_free (SignonSecurityContext *ctx)
{
    if (ctx == NULL) return;

    g_free (ctx->sys_ctx);
    g_free (ctx->app_ctx);
    g_slice_free (SignonSecurityContext, ctx);
}

/**
 * signon_security_context_set_system_context:
 * @ctx: #SignonSecurityContext item.
 * @system_context: system security context.
 *
 * Sets the system context part (such as SMACK label or MSSF token) of the
 * #SignonSecurityContext.
 */
void
signon_security_context_set_system_context (SignonSecurityContext *ctx,
                                            const gchar *system_context)
{
    g_return_if_fail (ctx != NULL);

    g_free (ctx->sys_ctx);
    ctx->sys_ctx = g_strdup (system_context);
}

/**
 * signon_security_context_get_system_context:
 * @ctx: #SignonSecurityContext item.
 * 
 * Get the system context part (such as SMACK label or MSSF token) of the
 * #SignonSecurityContext.
 *
 * Returns: (transfer none): system context.
 */
const gchar *
signon_security_context_get_system_context (const SignonSecurityContext *ctx)
{
    g_return_val_if_fail (ctx != NULL, NULL);

    return ctx->sys_ctx;
}

/**
 * signon_security_context_set_application_context:
 * @ctx: #SignonSecurityContext item.
 * @application_context: application security context.
 *
 * Sets the application context part (such as a script name or a web page) of
 * the #SignonSecurityContext.
 */
void
signon_security_context_set_application_context (SignonSecurityContext *ctx,
                                              const gchar *application_context)
{
    g_return_if_fail (ctx != NULL);

    g_free (ctx->app_ctx);
    ctx->app_ctx = g_strdup (application_context);
}

/**
 * signon_security_context_get_application_context:
 * @ctx: #SignonSecurityContext item.
 *
 * Get the application context part (such as script name or a web page) of
 * the #SignonSecurityContext.
 *
 * Returns: (transfer none): application context.
 */
const gchar *
signon_security_context_get_application_context (
                                               const SignonSecurityContext *ctx)
{
    g_return_val_if_fail (ctx != NULL, NULL);

    return ctx->app_ctx;
}

/**
 * signon_security_context_build_variant:
 * @ctx: #SignonSecurityContext item.
 *
 * Build a GVariant of type "(ss)" from a #SignonSecurityContext item.
 *
 * Returns: (transfer full): GVariant construct of a #SignonSecurityContext.
 */
GVariant *
signon_security_context_build_variant (const SignonSecurityContext *ctx)
{
    GVariant *variant;

    g_return_val_if_fail (ctx != NULL, NULL);

    variant = g_variant_new ("(ss)",
                             ctx->sys_ctx ? ctx->sys_ctx : "",
                             ctx->app_ctx ? ctx->app_ctx : "");

    return variant;
}

/**
 * signon_security_context_deconstruct_variant:
 * @variant: GVariant item with a #SignonSecurityContext construct.
 *
 * Builds a #SignonSecurityContext item from a GVariant of type "(ss)".
 *
 * Returns: (transfer full): #SignonSecurityContext item.
 */
SignonSecurityContext *
signon_security_context_deconstruct_variant (GVariant *variant)
{
    gchar *sys_ctx = NULL;
    gchar *app_ctx = NULL;
    SignonSecurityContext *ctx;

    g_return_val_if_fail (variant != NULL, NULL);

    g_variant_get (variant, "(ss)", &sys_ctx, &app_ctx);
    ctx = signon_security_context_new_from_values (sys_ctx, app_ctx);
    g_free (sys_ctx);
    g_free (app_ctx);
    return ctx;
}

/**
 * signon_security_context_list_build_variant:
 * @list: (element-type SignonSecurityContext): #GList item of #SignonSecurityContext.
 *
 * Builds a GVariant of type "a(ss)" from a GList of #SignonSecurityContext
 * items.
 *
 * Returns: (transfer full): GVariant construct of a #GList.
 */
GVariant *
signon_security_context_list_build_variant (const GList *list)
{
    GVariantBuilder builder;
    GVariant *variant;
    SignonSecurityContext *ctx;

    g_variant_builder_init (&builder, G_VARIANT_TYPE_ARRAY);
    for ( ; list != NULL; list = g_list_next (list))
    {
        ctx = (SignonSecurityContext *) list->data;
        g_variant_builder_add_value (&builder,
                                   signon_security_context_build_variant (ctx));
    }
    variant = g_variant_builder_end (&builder);

    return variant;
}

/**
 * signon_security_context_list_deconstruct_variant:
 * @variant: GVariant item with a list of security context tuples.
 *
 * Builds a GList of #SignonSecurityContext items from a GVariant of type
 * "a(ss)".
 *
 * Returns: (transfer full) (element-type SignonSecurityContext): #GList item.
 */
GList *
signon_security_context_list_deconstruct_variant (GVariant *variant)
{
    GList *list = NULL;
    GVariantIter iter;
    GVariant *value;

    g_return_val_if_fail (variant != NULL, NULL);

    g_variant_iter_init (&iter, variant);
    while ((value = g_variant_iter_next_value (&iter)))
    {
        list = g_list_append (
            list, signon_security_context_deconstruct_variant (value));
        g_variant_unref (value);
    }

    return list;
}
