/* Copyright 2026 TigerVNC Team
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */

/*
 * CredentialManager — Linux libsecret implementation
 *
 * Stores VNC credentials using the freedesktop.org Secret Service API
 * via libsecret. Works with GNOME Keyring, KWallet (with secret-service
 * backend), and other compatible secret services.
 *
 * Build requirement: libsecret-1 (pkg-config: libsecret-1)
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libsecret/secret.h>

#include <core/LogWriter.h>
#include <core/string.h>

#include "CredentialManager.h"

static core::LogWriter vlog("CredentialManager");

/* Schema definition — credentials are keyed by server (host:port) and username */
static const SecretSchema kTigerVncSchema = {
  "org.tigervnc.Credentials",
  SECRET_SCHEMA_NONE,
  {
    { "server", SECRET_SCHEMA_ATTRIBUTE_STRING },
    { "username", SECRET_SCHEMA_ATTRIBUTE_STRING },
    { "NULL", 0 },
  }
};

static std::string makeServerKey(const std::string& serverHost, int serverPort)
{
  return core::format("%s:%d", serverHost.c_str(), serverPort);
}

bool CredentialManager::loadCredentials(const std::string& serverHost,
                                        int serverPort,
                                        std::string& username,
                                        std::string& password)
{
  std::string server = makeServerKey(serverHost, serverPort);
  GError* error = nullptr;

  /* Get a connection to the Secret Service */
  SecretService* service = secret_service_get_sync(
      SECRET_SERVICE_LOAD_COLLECTIONS, nullptr, &error);

  if (error) {
    vlog.info("Failed to connect to secret service: %s", error->message);
    g_error_free(error);
    return false;
  }

  /* Build search attributes — only match on server key */
  GHashTable* searchAttrs = g_hash_table_new(g_str_hash, g_str_equal);
  g_hash_table_insert(searchAttrs, (gpointer)"server", (gpointer)server.c_str());

  /* Search for items matching this server */
  GList* items = secret_service_search_sync(
      service,
      &kTigerVncSchema,
      searchAttrs,
      static_cast<SecretSearchFlags>(
          SECRET_SEARCH_ALL | SECRET_SEARCH_LOAD_SECRETS),
      nullptr,  // cancellable
      &error);

  g_hash_table_unref(searchAttrs);

  if (error) {
    vlog.info("secret_service_search_sync failed: %s", error->message);
    g_error_free(error);
    g_object_unref(service);
    return false;
  }

  if (!items) {
    g_object_unref(service);
    return false;
  }

  /* Use the first matching item */
  SecretItem* item = static_cast<SecretItem*>(items->data);

  /* Retrieve the password (secret value) */
  SecretValue* secret = secret_item_get_secret(item);
  if (secret) {
    password = secret_value_get(secret, nullptr);
    secret_value_unref(secret);
  } else {
    password.clear();
  }

  /* Retrieve the username from item attributes */
  GHashTable* itemAttrs = secret_item_get_attributes(item);
  if (itemAttrs) {
    const gchar* storedUser = static_cast<const gchar*>(
        g_hash_table_lookup(itemAttrs, "username"));
    if (storedUser)
      username = storedUser;
    else
      username.clear();
    g_hash_table_unref(itemAttrs);
  } else {
    username.clear();
  }

  g_list_free_full(items, g_object_unref);
  g_object_unref(service);
  return true;
}

bool CredentialManager::saveCredentials(const std::string& serverHost,
                                        int serverPort,
                                        const std::string& username,
                                        const std::string& password)
{
  std::string server = makeServerKey(serverHost, serverPort);
  GError* error = nullptr;

  std::string label = core::format("TigerVNC: %s", server.c_str());

  gboolean ok = secret_password_store_sync(
      &kTigerVncSchema,
      SECRET_COLLECTION_DEFAULT,
      label.c_str(),
      password.c_str(),
      nullptr,     // cancellable
      &error,
      "server", server.c_str(),
      "username", username.c_str(),
      nullptr);

  if (!ok) {
    vlog.info("secret_password_store_sync failed: %s",
              error ? error->message : "unknown error");
    if (error)
      g_error_free(error);
    return false;
  }

  return true;
}

bool CredentialManager::deleteCredentials(const std::string& serverHost,
                                          int serverPort)
{
  std::string server = makeServerKey(serverHost, serverPort);
  GError* error = nullptr;

  gboolean ok = secret_password_clear_sync(
      &kTigerVncSchema,
      nullptr,     // cancellable
      &error,
      "server", server.c_str(),
      nullptr);

  if (!ok && error) {
    /* It's acceptable if the item doesn't exist */
    if (error->code != SECRET_ERROR_NO_SUCH_OBJECT) {
      vlog.info("secret_password_clear_sync failed: %s", error->message);
    }
    g_error_free(error);
    return false;
  }

  return true;
}
