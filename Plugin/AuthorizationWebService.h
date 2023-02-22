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

#include "BaseAuthorizationService.h"
#include <Compatibility.h>

namespace OrthancPlugins
{
  class AuthorizationWebService : public BaseAuthorizationService
  {
  private:
    std::string url_;
    std::string username_;
    std::string password_;
    std::string identifier_;
    std::string userProfileUrl_;

  protected:
    virtual bool IsGrantedInternal(unsigned int& validity,
                           OrthancPluginHttpMethod method,
                           const AccessedResource& access,
                           const Token* token,
                           const std::string& tokenValue) ORTHANC_OVERRIDE;
    
    virtual bool GetUserProfileInternal(unsigned int& validity,
                                Json::Value& profile /* out */,
                                const Token* token,
                                const std::string& tokenValue) ORTHANC_OVERRIDE;

    virtual bool HasUserPermissionInternal(unsigned int& validity,
                                   const std::string& permission,
                                   const Token* token,
                                   const std::string& tokenValue) ORTHANC_OVERRIDE;
  
  public:
    AuthorizationWebService(const std::string& url) :
      url_(url)
    {
    }

    void SetCredentials(const std::string& username,
                        const std::string& password);

    void SetIdentifier(const std::string& webServiceIdentifier);

    void SetUserProfileUrl(const std::string& url);
  };
}
