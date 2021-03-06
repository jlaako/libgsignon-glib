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
#ifndef _SIGNON_UTILS_H_
#define _SIGNON_UTILS_H_

#include <glib-object.h>

G_BEGIN_DECLS

#define SIGNON_IS_NOT_CANCELLED(error) \
        (error == NULL || \
        error->domain != G_IO_ERROR || \
        error->code != G_IO_ERROR_CANCELLED)

const GVariantType *signon_gtype_to_variant_type (GType type);
GValue *signon_gvalue_new (GType type);
void signon_gvalue_free (gpointer val);

GHashTable *signon_hash_table_from_variant (GVariant *variant);
GVariant *signon_hash_table_to_variant (GHashTable *hash_table);

G_END_DECLS

#endif //_SIGNON_UTILS_H_
