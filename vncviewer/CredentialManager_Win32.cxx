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
 * CredentialManager — Windows Credential Manager implementation
 *
 * Stores VNC credentials as GENERIC credentials using CredWrite/CredRead.
 * Credentials are stored in the user's roaming credential store.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <windows.h>
#include <wincred.h>

#include <core/LogWriter.h>
#include <core/string.h>

#include "CredentialManager.h"

#pragma comment(lib, "credui.lib")

static core::LogWriter vlog("CredentialManager");

static const wchar_t* kTargetPrefix = L"TigerVNC/";

static std::wstring makeTarget(const std::string& serverHost, int serverPort)
{
  std::string target = core::format("TigerVNC/%s:%d",
                                    serverHost.c_str(), serverPort);
  /* Convert UTF-8 to wide string */
  int len = MultiByteToWideChar(CP_UTF8, 0, target.c_str(), -1, nullptr, 0);
  std::wstring wTarget(len, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, target.c_str(), -1, &wTarget[0], len);
  /* Remove the trailing null terminator */
  wTarget.pop_back();
  return wTarget;
}

static std::string wstrToUtf8(const std::wstring& wstr)
{
  int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1,
                                nullptr, 0, nullptr, nullptr);
  std::string str(len, '\0');
  WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], len,
                      nullptr, nullptr);
  str.pop_back();
  return str;
}

bool CredentialManager::loadCredentials(const std::string& serverHost,
                                        int serverPort,
                                        std::string& username,
                                        std::string& password)
{
  std::wstring target = makeTarget(serverHost, serverPort);

  PCREDENTIALW cred = nullptr;
  BOOL ok = CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &cred);
  if (!ok) {
    DWORD err = GetLastError();
    if (err != ERROR_NOT_FOUND)
      vlog.info("CredRead failed with error %lu", err);
    return false;
  }

  /* Password is stored as the credential blob */
  if (cred->CredentialBlob && cred->CredentialBlobSize > 0)
    password.assign(reinterpret_cast<const char*>(cred->CredentialBlob),
                    cred->CredentialBlobSize);
  else
    password.clear();

  /* Username is stored in the credential's UserName field.
   * Windows stores username as DOMAIN\username or just username.
   * We strip any domain prefix. */
  if (cred->UserName) {
    std::wstring wUser(cred->UserName);
    size_t backslash = wUser.find(L'\\');
    if (backslash != std::wstring::npos)
      wUser = wUser.substr(backslash + 1);
    username = wstrToUtf8(wUser);
  } else {
    username.clear();
  }

  CredFree(cred);
  return true;
}

bool CredentialManager::saveCredentials(const std::string& serverHost,
                                        int serverPort,
                                        const std::string& username,
                                        const std::string& password)
{
  std::wstring target = makeTarget(serverHost, serverPort);

  /* Convert username from UTF-8 to wide */
  std::wstring wUsername;
  if (!username.empty()) {
    int len = MultiByteToWideChar(CP_UTF8, 0, username.c_str(), -1,
                                  nullptr, 0);
    wUsername.resize(len);
    MultiByteToWideChar(CP_UTF8, 0, username.c_str(), -1, &wUsername[0], len);
    wUsername.pop_back();
  }

  CREDENTIALW cred = {};
  cred.Type = CRED_TYPE_GENERIC;
  cred.TargetName = const_cast<LPWSTR>(target.c_str());
  cred.UserName = wUsername.empty() ? nullptr : const_cast<LPWSTR>(wUsername.c_str());
  cred.CredentialBlobSize = static_cast<DWORD>(password.size());
  cred.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(password.data()));
  cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

  BOOL ok = CredWriteW(&cred, 0);
  if (!ok) {
    DWORD err = GetLastError();
    vlog.info("CredWrite failed with error %lu", err);
    return false;
  }

  return true;
}

bool CredentialManager::deleteCredentials(const std::string& serverHost,
                                          int serverPort)
{
  std::wstring target = makeTarget(serverHost, serverPort);

  BOOL ok = CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0);
  if (!ok) {
    DWORD err = GetLastError();
    if (err != ERROR_NOT_FOUND) {
      vlog.info("CredDelete failed with error %lu", err);
      return false;
    }
  }

  return true;
}
