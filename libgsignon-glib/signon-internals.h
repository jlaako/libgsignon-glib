/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libgsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2012 Canonical Ltd.
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

#ifndef _SIGNONINTERNALS_H_
#define _SIGNONINTERNALS_H_

#include "signon-security-context.h"

#ifndef SIGNON_TRACE
#define SIGNON_TRACE
#endif

#ifdef SIGNON_TRACE
    #define DEBUG(format...) g_debug (G_STRLOC ": " format)
#else
    #define DEBUG(...) do {} while (0)
#endif

/*
 * Common DBUS definitions
 * */
#define SIGNOND_SERVICE_PREFIX     "com.google.code.AccountsSSO.gSingleSignOn"
#define SIGNOND_SERVICE            SIGNOND_SERVICE_PREFIX

#define SIGNOND_DAEMON_OBJECTPATH  "/com/google/code/AccountsSSO/gSingleSignOn"
#define SIGNOND_DAEMON_INTERFACE       SIGNOND_SERVICE_PREFIX ".AuthService"
#define SIGNOND_IDENTITY_INTERFACE     SIGNOND_SERVICE_PREFIX ".Identity"
#define SIGNOND_AUTH_SESSION_INTERFACE SIGNOND_SERVICE_PREFIX ".AuthSession"

#define SIGNOND_ERR_PREFIX SIGNOND_SERVICE_PREFIX ".Error."

/*
 * Common server/client identity info strings
 * */
#define SIGNOND_IDENTITY_INFO_ID                    "Id"
#define SIGNOND_IDENTITY_INFO_USERNAME              "UserName"
#define SIGNOND_IDENTITY_INFO_SECRET                "Secret"
#define SIGNOND_IDENTITY_INFO_STORESECRET           "StoreSecret"
#define SIGNOND_IDENTITY_INFO_CAPTION               "Caption"
#define SIGNOND_IDENTITY_INFO_REALMS                "Realms"
#define SIGNOND_IDENTITY_INFO_AUTHMETHODS           "AuthMethods"
#define SIGNOND_IDENTITY_INFO_OWNER                 "Owner"
#define SIGNOND_IDENTITY_INFO_ACL                   "ACL"
#define SIGNOND_IDENTITY_INFO_TYPE                  "Type"
#define SIGNOND_IDENTITY_INFO_REFCOUNT              "RefCount"
#define SIGNOND_IDENTITY_INFO_VALIDATED             "Validated"
#define SIGNOND_IDENTITY_INFO_USERNAME_IS_SECRET    "UserNameSecret"

/*
 * Common server/client sides error names and messages
 * */
#define SIGNOND_UNKNOWN_ERR_NAME SIGNOND_ERR_PREFIX "Unknown"
#define SIGNOND_INTERNAL_SERVER_ERR_NAME SIGNOND_ERR_PREFIX "InternalServer"
#define SIGNOND_INTERNAL_COMMUNICATION_ERR_NAME \
    SIGNOND_ERR_PREFIX "InternalCommunication"
#define SIGNOND_PERMISSION_DENIED_ERR_NAME \
    SIGNOND_ERR_PREFIX "PermissionDenied"
#define SIGNOND_METHOD_OR_MECHANISM_NOT_ALLOWED_ERR_NAME \
    SIGNOND_ERR_PREFIX "MethodOrMechanismNotAllowed"
#define SIGNOND_ENCRYPTION_FAILED_ERR_NAME \
    SIGNOND_ERR_PREFIX "EncryptionFailed"
#define SIGNOND_METHOD_NOT_KNOWN_ERR_NAME SIGNOND_ERR_PREFIX "MethodNotKnown"
#define SIGNOND_SERVICE_NOT_AVAILABLE_ERR_NAME \
    SIGNOND_ERR_PREFIX "ServiceNotAvailable"
#define SIGNOND_INVALID_QUERY_ERR_NAME SIGNOND_ERR_PREFIX "InvalidQuery"
#define SIGNOND_METHOD_NOT_AVAILABLE_ERR_NAME \
    SIGNOND_ERR_PREFIX "MethodNotAvailable"
#define SIGNOND_IDENTITY_NOT_FOUND_ERR_NAME \
    SIGNOND_ERR_PREFIX "IdentityNotFound"
#define SIGNOND_STORE_FAILED_ERR_NAME SIGNOND_ERR_PREFIX "StoreFailed"
#define SIGNOND_REMOVE_FAILED_ERR_NAME SIGNOND_ERR_PREFIX "RemoveFailed"
#define SIGNOND_SIGNOUT_FAILED_ERR_NAME SIGNOND_ERR_PREFIX "SignOutFailed"
#define SIGNOND_IDENTITY_OPERATION_CANCELED_ERR_NAME \
    SIGNOND_ERR_PREFIX "IdentityOperationCanceled"
#define SIGNOND_CREDENTIALS_NOT_AVAILABLE_ERR_NAME \
    SIGNOND_ERR_PREFIX "CredentialsNotAvailable"
#define SIGNOND_REFERENCE_NOT_FOUND_ERR_NAME \
    SIGNOND_ERR_PREFIX "ReferenceNotFound"
#define SIGNOND_MECHANISM_NOT_AVAILABLE_ERR_NAME \
    SIGNOND_ERR_PREFIX "MechanismNotAvailable"
#define SIGNOND_MISSING_DATA_ERR_NAME SIGNOND_ERR_PREFIX "MissingData"
#define SIGNOND_INVALID_CREDENTIALS_ERR_NAME \
    SIGNOND_ERR_PREFIX "InvalidCredentials"
#define SIGNOND_NOT_AUTHORIZED_ERR_NAME SIGNOND_ERR_PREFIX "NotAuthorized"
#define SIGNOND_WRONG_STATE_ERR_NAME SIGNOND_ERR_PREFIX "WrongState"
#define SIGNOND_OPERATION_NOT_SUPPORTED_ERR_NAME \
    SIGNOND_ERR_PREFIX "OperationNotSupported"
#define SIGNOND_NO_CONNECTION_ERR_NAME SIGNOND_ERR_PREFIX "NoConnection"
#define SIGNOND_NETWORK_ERR_NAME SIGNOND_ERR_PREFIX "Network"
#define SIGNOND_SSL_ERR_NAME SIGNOND_ERR_PREFIX "Ssl"
#define SIGNOND_RUNTIME_ERR_NAME SIGNOND_ERR_PREFIX "Runtime"
#define SIGNOND_SESSION_CANCELED_ERR_NAME SIGNOND_ERR_PREFIX "SessionCanceled"
#define SIGNOND_TIMED_OUT_ERR_NAME SIGNOND_ERR_PREFIX "TimedOut"
#define SIGNOND_USER_INTERACTION_ERR_NAME SIGNOND_ERR_PREFIX "UserInteraction"
#define SIGNOND_OPERATION_FAILED_ERR_NAME SIGNOND_ERR_PREFIX "OperationFailed"
#define SIGNOND_TOS_NOT_ACCEPTED_ERR_NAME SIGNOND_ERR_PREFIX "TOSNotAccepted"
#define SIGNOND_FORGOT_PASSWORD_ERR_NAME SIGNOND_ERR_PREFIX "ForgotPassword"
#define SIGNOND_INCORRECT_DATE_ERR_NAME SIGNOND_ERR_PREFIX "IncorrectDate"
#define SIGNOND_USER_ERROR_ERR_NAME SIGNOND_ERR_PREFIX "User"


#include "signon-identity-info.h"

G_BEGIN_DECLS

struct _SignonIdentityInfo
{
    gint id;
    gchar *username;
    gchar *secret;
    gchar *caption;
    gboolean store_secret;
    GHashTable *methods;
    gchar **realms;
    SignonSecurityContext *owner;
    GList *access_control_list;
    gint type;
};

G_GNUC_INTERNAL
SignonIdentityInfo *
signon_identity_info_new_from_variant (GVariant *variant);

G_GNUC_INTERNAL
GVariant *
signon_identity_info_to_variant (const SignonIdentityInfo *self);

G_END_DECLS

#endif

