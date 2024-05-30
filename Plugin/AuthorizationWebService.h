/**
 * Advanced authorization plugin for Orthanc
 * Copyright (C) 2017-2023 Osimis S.A., Belgium
 * Copyright (C) 2024-2024 Orthanc Team SRL, Belgium
 * Copyright (C) 2021-2024 Sebastien Jodogne, ICTEAM UCLouvain, Belgium
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
    std::string username_;
    std::string password_;
    std::string identifier_;
    std::string userProfileUrl_;
    std::string tokenValidationUrl_;
    std::string tokenDecoderUrl_;
    std::string tokenCreationBaseUrl_;

  protected:
    virtual bool IsGrantedInternal(unsigned int& validity,
                           OrthancPluginHttpMethod method,
                           const AccessedResource& access,
                           const Token* token,
                           const std::string& tokenValue) ORTHANC_OVERRIDE;
    
    virtual bool GetUserProfileInternal(unsigned int& validity,
                                        UserProfile& profile /* out */,
                                        const Token* token,
                                        const std::string& tokenValue) ORTHANC_OVERRIDE;

    virtual bool HasUserPermissionInternal(unsigned int& validity,
                                           const std::string& permission,
                                           const UserProfile& profile) ORTHANC_OVERRIDE;
  
  public:
    AuthorizationWebService(const std::string& tokenValidationUrl, 
                            const std::string& tokenCreationBaseUrl, 
                            const std::string& userProfileUrl,
                            const std::string& tokenDecoderUrl) :
      userProfileUrl_(userProfileUrl),
      tokenValidationUrl_(tokenValidationUrl),
      tokenDecoderUrl_(tokenDecoderUrl),
      tokenCreationBaseUrl_(tokenCreationBaseUrl)
    {
    }

    void SetCredentials(const std::string& username,
                        const std::string& password);

    void SetIdentifier(const std::string& webServiceIdentifier);

    virtual bool HasUserProfile() const
    {
      return !userProfileUrl_.empty();
    }

    virtual bool HasCreateToken() const
    {
      return !tokenCreationBaseUrl_.empty();
    }

    virtual bool HasTokenValidation() const
    {
      return !tokenValidationUrl_.empty();
    }

    virtual bool CreateToken(IAuthorizationService::CreatedToken& response,
                             const std::string& tokenType, 
                             const std::string& id, 
                             const std::vector<IAuthorizationService::OrthancResource>& resources,
                             const std::string& expirationDateString,
                             const uint64_t& validityDuration) ORTHANC_OVERRIDE;

    virtual bool DecodeToken(DecodedToken& response,
                             const std::string& tokenKey, 
                             const std::string& tokenValue);

    static void ToJson(Json::Value& output, const UserProfile& profile);
    
    static void FromJson(UserProfile& profile, const Json::Value& input);

  };
}
