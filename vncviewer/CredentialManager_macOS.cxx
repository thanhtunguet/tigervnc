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
 * CredentialManager — macOS Keychain implementation
 *
 * Stores VNC credentials as generic passwords in the user's default
 * keychain (typically ~/Library/Keychains/login.keychain-db).
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <cstring>
#include <vector>

#include <Security/Security.h>

#include <core/LogWriter.h>
#include <core/string.h>

#include "CredentialManager.h"

static core::LogWriter vlog("CredentialManager");

static const char* kServiceName = "TigerVNC";

static std::string makeAccount(const std::string& serverHost, int serverPort)
{
  return core::format("%s:%d", serverHost.c_str(), serverPort);
}

bool CredentialManager::loadCredentials(const std::string& serverHost,
                                        int serverPort,
                                        std::string& username,
                                        std::string& password)
{
  std::string account = makeAccount(serverHost, serverPort);

  void* passwordData = nullptr;
  UInt32 passwordLength = 0;

  OSStatus status = SecKeychainFindGenericPassword(
      nullptr,                       // default keychain
      strlen(kServiceName), kServiceName, // service name length and pointer
      account.size(), account.c_str(),    // account name length and pointer
      &passwordLength,
      &passwordData,
      nullptr);                      // item reference (unused)

  if (status != errSecSuccess) {
    if (status != errSecItemNotFound)
      vlog.info("Keychain lookup failed with status %d", (int)status);
    return false;
  }

  password.assign(static_cast<const char*>(passwordData), passwordLength);
  SecKeychainItemFreeContent(nullptr, passwordData);

  /* Retrieve the account name (which we stored as username) by re-fetching
   * the item reference. We use SecItemCopyMatching to get attributes. */
  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
      nullptr, 0,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);

  CFStringRef cfService = CFStringCreateWithCString(
      nullptr, kServiceName, kCFStringEncodingUTF8);
  CFStringRef cfAccount = CFStringCreateWithCString(
      nullptr, account.c_str(), kCFStringEncodingUTF8);

  CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(query, kSecAttrService, cfService);
  CFDictionarySetValue(query, kSecAttrAccount, cfAccount);
  CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);

  CFTypeRef result = nullptr;
  status = SecItemCopyMatching(query, &result);

  CFRelease(cfService);
  CFRelease(cfAccount);
  CFRelease(query);

  if (status == errSecSuccess && result) {
    CFDictionaryRef attrs = static_cast<CFDictionaryRef>(result);
    CFStringRef label = static_cast<CFStringRef>(
        CFDictionaryGetValue(attrs, kSecAttrLabel));
    if (label) {
      CFIndex len = CFStringGetLength(label);
      CFIndex maxSize = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
      std::vector<char> buf(maxSize);
      if (CFStringGetCString(label, buf.data(), maxSize, kCFStringEncodingUTF8))
        username = buf.data();
    }
    CFRelease(result);
  } else {
    /* Fallback: username is not stored separately; leave empty */
    username.clear();
  }

  return true;
}

bool CredentialManager::saveCredentials(const std::string& serverHost,
                                        int serverPort,
                                        const std::string& username,
                                        const std::string& password)
{
  std::string account = makeAccount(serverHost, serverPort);

  /* First try to update an existing item */
  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
      nullptr, 0,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);

  CFStringRef cfService = CFStringCreateWithCString(
      nullptr, kServiceName, kCFStringEncodingUTF8);
  CFStringRef cfAccount = CFStringCreateWithCString(
      nullptr, account.c_str(), kCFStringEncodingUTF8);

  CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(query, kSecAttrService, cfService);
  CFDictionarySetValue(query, kSecAttrAccount, cfAccount);

  CFDataRef cfPassword = CFDataCreate(
      nullptr,
      reinterpret_cast<const UInt8*>(password.data()),
      password.size());

  CFDictionarySetValue(query, kSecValueData, cfPassword);

  /* Store username as the label attribute */
  if (!username.empty()) {
    CFStringRef cfUsername = CFStringCreateWithCString(
        nullptr, username.c_str(), kCFStringEncodingUTF8);
    CFDictionarySetValue(query, kSecAttrLabel, cfUsername);
    CFRelease(cfUsername);
  }

  OSStatus status = SecItemUpdate(query, query);

  if (status == errSecItemNotFound) {
    /* Item doesn't exist — create it */
    status = SecKeychainAddGenericPassword(
        nullptr,                              // default keychain
        strlen(kServiceName), kServiceName,   // service name length and pointer
        account.size(), account.c_str(),      // account name length and pointer
        password.size(), password.data(),     // password data length and pointer
        nullptr);                             // item reference (unused)

    /* If we have a username, update the label separately */
    if (status == errSecSuccess && !username.empty()) {
      CFMutableDictionaryRef searchQuery = CFDictionaryCreateMutable(
          nullptr, 0,
          &kCFTypeDictionaryKeyCallBacks,
          &kCFTypeDictionaryValueCallBacks);
      CFDictionarySetValue(searchQuery, kSecClass, kSecClassGenericPassword);
      CFDictionarySetValue(searchQuery, kSecAttrService, cfService);
      CFDictionarySetValue(searchQuery, kSecAttrAccount, cfAccount);

      CFStringRef cfUsername = CFStringCreateWithCString(
          nullptr, username.c_str(), kCFStringEncodingUTF8);
      CFMutableDictionaryRef updateAttrs = CFDictionaryCreateMutable(
          nullptr, 0,
          &kCFTypeDictionaryKeyCallBacks,
          &kCFTypeDictionaryValueCallBacks);
      CFDictionarySetValue(updateAttrs, kSecAttrLabel, cfUsername);

      SecItemUpdate(searchQuery, updateAttrs);

      CFRelease(cfUsername);
      CFRelease(searchQuery);
      CFRelease(updateAttrs);
    }
  }

  CFRelease(cfService);
  CFRelease(cfAccount);
  CFRelease(cfPassword);
  CFRelease(query);

  if (status != errSecSuccess) {
    vlog.info("Keychain store failed with status %d", (int)status);
    return false;
  }

  return true;
}

bool CredentialManager::deleteCredentials(const std::string& serverHost,
                                          int serverPort)
{
  std::string account = makeAccount(serverHost, serverPort);

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
      nullptr, 0,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);

  CFStringRef cfService = CFStringCreateWithCString(
      nullptr, kServiceName, kCFStringEncodingUTF8);
  CFStringRef cfAccount = CFStringCreateWithCString(
      nullptr, account.c_str(), kCFStringEncodingUTF8);

  CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(query, kSecAttrService, cfService);
  CFDictionarySetValue(query, kSecAttrAccount, cfAccount);

  OSStatus status = SecItemDelete(query);

  CFRelease(cfService);
  CFRelease(cfAccount);
  CFRelease(query);

  if (status != errSecSuccess && status != errSecItemNotFound) {
    vlog.info("Keychain delete failed with status %d", (int)status);
    return false;
  }

  return true;
}
