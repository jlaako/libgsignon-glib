/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libgsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2011 Canonical Ltd.
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

#ifndef _SIGNON_IDENTITY_INFO_H_
#define _SIGNON_IDENTITY_INFO_H_

#include <glib-object.h>

#include "signon-security-context.h"

G_BEGIN_DECLS

/**
 * SignonIdentityInfo:
 *
 * Opaque struct. Use the accessor functions below.
 */
typedef struct _SignonIdentityInfo SignonIdentityInfo;

/**
 * SignonIdentityType:
 * @SIGNON_IDENTITY_TYPE_OTHER: an identity that is not an app, web or network
 * @SIGNON_IDENTITY_TYPE_APP: an application identity
 * @SIGNON_IDENTITY_TYPE_WEB: a web identity
 * @SIGNON_IDENTITY_TYPE_NETWORK: a network server identity
 *
 * Identity types used in #SignonIdentityInfo.
 */
typedef enum {
    SIGNON_IDENTITY_TYPE_OTHER = 0,
    SIGNON_IDENTITY_TYPE_APP = 1 << 0,
    SIGNON_IDENTITY_TYPE_WEB = 1 << 1,
    SIGNON_IDENTITY_TYPE_NETWORK = 1 << 2
} SignonIdentityType;

GType signon_identity_info_get_type (void) G_GNUC_CONST;

SignonIdentityInfo *signon_identity_info_new (void);
void signon_identity_info_free (SignonIdentityInfo *info);

SignonIdentityInfo *signon_identity_info_copy (const SignonIdentityInfo *other);

gint signon_identity_info_get_id (const SignonIdentityInfo *info);
const gchar *signon_identity_info_get_username (const SignonIdentityInfo *info);
gboolean signon_identity_info_get_storing_secret (
                                                const SignonIdentityInfo *info);
const gchar *signon_identity_info_get_caption (const SignonIdentityInfo *info);
GHashTable *signon_identity_info_get_methods (const SignonIdentityInfo *info);
const gchar* const *signon_identity_info_get_realms (
                                                const SignonIdentityInfo *info);
const SignonSecurityContext *signon_identity_info_get_owner (
                                                const SignonIdentityInfo *info);
GList *signon_identity_info_get_access_control_list (
                                                const SignonIdentityInfo *info);
SignonIdentityType signon_identity_info_get_identity_type (
                                                const SignonIdentityInfo *info);

void signon_identity_info_set_username (SignonIdentityInfo *info,
                                        const gchar *username);
void signon_identity_info_set_secret (SignonIdentityInfo *info,
                                      const gchar *secret,
                                      gboolean store_secret);
void signon_identity_info_set_caption (SignonIdentityInfo *info,
                                       const gchar *caption);
void signon_identity_info_set_methods (SignonIdentityInfo *info,
                                       GHashTable *methods);
void signon_identity_info_own_methods (SignonIdentityInfo *info,
                                       GHashTable *methods);
void signon_identity_info_set_method (SignonIdentityInfo *info,
                                      const gchar *method,
                                      const gchar* const *mechanisms);
void signon_identity_info_remove_method (SignonIdentityInfo *info,
                                         const gchar *method);
void signon_identity_info_set_realms (SignonIdentityInfo *info,
                                      const gchar* const *realms);
void signon_identity_info_set_owner (SignonIdentityInfo *info,
                                     const SignonSecurityContext *owner);
void signon_identity_info_set_owner_from_values (SignonIdentityInfo *info,
                                            const gchar *system_context,
                                            const gchar *application_context);
void signon_identity_info_set_access_control_list (SignonIdentityInfo *info,
                                GList *access_control_list);
void signon_identity_info_access_control_list_append (SignonIdentityInfo *info,
                                    SignonSecurityContext *security_context);
void signon_identity_info_set_identity_type (SignonIdentityInfo *info,
                                             SignonIdentityType type);

G_END_DECLS

#endif /* _SIGNON_IDENTITY_INFO_H_ */
