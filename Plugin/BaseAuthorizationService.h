/**
 * Advanced authorization plugin for Orthanc
 * Copyright (C) 2017-2023 Osimis S.A., Belgium
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 **/

#pragma once

#include "IAuthorizationService.h"


namespace OrthancPlugins
{
  class CachedAuthorizationService;

  class BaseAuthorizationService : public IAuthorizationService
  {
    friend CachedAuthorizationService;
  protected:
    virtual bool IsGrantedInternal(unsigned int& validity,
                                   OrthancPluginHttpMethod method,
                                   const AccessedResource& access,
                                   const Token* token,
                                   const std::string& tokenValue) = 0;
    
    virtual bool GetUserProfileInternal(unsigned int& validity,
                                        Json::Value& profile /* out */,
                                        const Token* token,
                                        const std::string& tokenValue) = 0;

    virtual bool HasUserPermissionInternal(unsigned int& validity,
                                           const std::string& permission,
                                           const Token* token,
                                           const std::string& tokenValue) = 0;

  public:
    virtual ~BaseAuthorizationService()
    {
    }
    
    virtual bool IsGranted(unsigned int& validity,
                           OrthancPluginHttpMethod method,
                           const AccessedResource& access,
                           const Token& token,
                           const std::string& tokenValue)
    {
      return IsGrantedInternal(validity, method, access, &token, tokenValue);
    }
    
    virtual bool IsGrantedToAnonymousUser(unsigned int& validity,
                                          OrthancPluginHttpMethod method,
                                          const AccessedResource& access)
    {
      return IsGrantedInternal(validity, method, access, NULL, "");
    }

    virtual bool GetUserProfile(unsigned int& validity,
                                Json::Value& profile /* out */,
                                const Token& token,
                                const std::string& tokenValue)
    {
      return GetUserProfileInternal(validity, profile, &token, tokenValue);
    }

    virtual bool GetAnonymousUserProfile(unsigned int& validity /* out */,
                                         Json::Value& profile /* out */)
    {
      return GetUserProfileInternal(validity, profile, NULL, "");
    }

    virtual bool HasUserPermission(unsigned int& validity /* out */,
                                   const std::set<std::string>& anyOfPermissions,
                                   const Token& token,
                                   const std::string& tokenValue)
    {
      if (anyOfPermissions.size() == 0)
      {
        return true;
      }

      for (std::set<std::string>::const_iterator it = anyOfPermissions.begin(); it != anyOfPermissions.end(); ++it)
      {
        if (HasUserPermissionInternal(validity, *it, &token, tokenValue))
        {
          return true;
        }
      }
      return false;
    }

    virtual bool HasAnonymousUserPermission(unsigned int& validity /* out */,
                                            const std::set<std::string>& anyOfPermissions)
    {
      if (anyOfPermissions.size() == 0)
      {
        return true;
      }

      for (std::set<std::string>::const_iterator it = anyOfPermissions.begin(); it != anyOfPermissions.end(); ++it)
      {
        if (HasUserPermissionInternal(validity, *it, NULL, ""))
        {
          return true;
        }
      }
      return false;
    }
  };
}
