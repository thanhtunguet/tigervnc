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

#ifndef __CREDENTIAL_MANAGER_H__
#define __CREDENTIAL_MANAGER_H__

#include <string>

/**
 * CredentialManager provides OS-native secure credential storage.
 *
 * Platform implementations:
 *   - macOS: Keychain Services
 *   - Windows: Credential Manager (CredRead/CredWrite)
 *   - Linux: libsecret (GNOME Keyring / KWallet via Secret Service)
 *
 * Credentials are stored per-server, keyed by "host:port".
 */
class CredentialManager
{
public:
  /**
   * Retrieve stored credentials for a server.
   *
   * @param serverHost  Server hostname or IP
   * @param serverPort  Server port number
   * @param username    Output: stored username (empty if not found)
   * @param password    Output: stored password (empty if not found)
   * @return true if credentials were found and loaded
   */
  static bool loadCredentials(const std::string& serverHost,
                              int serverPort,
                              std::string& username,
                              std::string& password);

  /**
   * Store credentials for a server.
   *
   * @param serverHost  Server hostname or IP
   * @param serverPort  Server port number
   * @param username    Username to store
   * @param password    Password to store
   * @return true if credentials were stored successfully
   */
  static bool saveCredentials(const std::string& serverHost,
                              int serverPort,
                              const std::string& username,
                              const std::string& password);

  /**
   * Delete stored credentials for a server.
   *
   * @param serverHost  Server hostname or IP
   * @param serverPort  Server port number
   * @return true if credentials were deleted (or didn't exist)
   */
  static bool deleteCredentials(const std::string& serverHost,
                                int serverPort);
};

#endif // __CREDENTIAL_MANAGER_H__
