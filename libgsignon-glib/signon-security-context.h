/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libgsignon-glib
 *
 * Copyright (C) 2012 Intel Corporation.
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

#ifndef _SIGNON_SECURITY_CONTEXT_H_
#define _SIGNON_SECURITY_CONTEXT_H_

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

typedef struct _SignonSecurityContext SignonSecurityContext;

/**
 * SignonSecurityContext:
 * @sys_ctx: system context, such as SMACK-label, MSSF token or just a
 *           binary path.
 * @app_ctx: application context, such as a script or a web page.
 *
 * Security context descriptor used for access control checks. 
 */
struct _SignonSecurityContext
{
    gchar *sys_ctx;
    gchar *app_ctx;
};

GType signon_security_context_get_type (void) G_GNUC_CONST;

SignonSecurityContext * signon_security_context_new ();
SignonSecurityContext * signon_security_context_new_from_values (
                                            const gchar *system_context,
                                            const gchar *application_context);
void signon_security_context_free (SignonSecurityContext *ctx);
SignonSecurityContext * signon_security_context_copy (
                                        const SignonSecurityContext *src_ctx);
void signon_security_context_set_system_context (SignonSecurityContext *ctx,
                                                 const gchar *system_context);
const gchar * signon_security_context_get_system_context (
                                            const SignonSecurityContext *ctx);
void signon_security_context_set_application_context (
                                            SignonSecurityContext *ctx,
                                            const gchar *application_context);
const gchar * signon_security_context_get_application_context (
                                            const SignonSecurityContext *ctx);
GVariant * signon_security_context_build_variant (
                                            const SignonSecurityContext *ctx);
SignonSecurityContext * signon_security_context_deconstruct_variant (
                                                            GVariant *variant);

GVariant * signon_security_context_list_build_variant (const GList *list);
GList * signon_security_context_list_deconstruct_variant (GVariant *variant);

G_END_DECLS

#endif  /* _SIGNON_SECURITY_CONTEXT_H_ */

