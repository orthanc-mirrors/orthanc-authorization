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

#include "AccessedResource.h"
#include "Token.h"

#include <orthanc/OrthancCPlugin.h>
#include <boost/noncopyable.hpp>
#include <json/json.h>

namespace OrthancPlugins
{
  // NOTE: This interface must be thread-safe
  class IAuthorizationService : public boost::noncopyable
  {
  public:
    struct OrthancResource
    {
      std::string dicomUid;
      std::string orthancId;
      std::string url;
      std::string level;
    };

    struct CreatedToken
    {
      std::string url;
      std::string token;
    };

    virtual ~IAuthorizationService()
    {
    }
    
    virtual bool IsGranted(unsigned int& validity /* out */,
                           OrthancPluginHttpMethod method,
                           const AccessedResource& access,
                           const Token& token,
                           const std::string& tokenValue) = 0;
    
    virtual bool IsGrantedToAnonymousUser(unsigned int& validity /* out */,
                                          OrthancPluginHttpMethod method,
                                          const AccessedResource& access) = 0;

    virtual bool GetUserProfile(unsigned int& validity /* out */,
                                Json::Value& profile /* out */,
                                const Token& token,
                                const std::string& tokenValue) = 0;

    virtual bool GetAnonymousUserProfile(unsigned int& validity /* out */,
                                         Json::Value& profile /* out */) = 0;

    virtual bool HasUserPermission(unsigned int& validity /* out */,
                                   const std::set<std::string>& anyOfPermissions,
                                   const Token& token,
                                   const std::string& tokenValue) = 0;

    virtual bool HasAnonymousUserPermission(unsigned int& validity /* out */,
                                            const std::set<std::string>& anyOfPermissions) = 0;

    virtual bool CreateToken(CreatedToken& response,
                             const std::string& tokenType, 
                             const std::string& id, 
                             const std::vector<OrthancResource>& resources,
                             const std::string& expirationDateString) = 0;

    virtual bool HasUserProfile() const = 0;
    virtual bool HasCreateToken() const = 0;
    virtual bool HasTokenValidation() const = 0;
  };
}
