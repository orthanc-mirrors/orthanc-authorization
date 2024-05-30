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

#include "CachedAuthorizationService.h"
#include "AuthorizationWebService.h"

#include <OrthancException.h>
#include <Toolbox.h>

#include <boost/lexical_cast.hpp>

namespace OrthancPlugins
{
  std::string CachedAuthorizationService::ComputeKey(OrthancPluginHttpMethod method,
                                                     const AccessedResource& access,
                                                     const Token* token,
                                                     const std::string& tokenValue) const
  {
    if (token != NULL)
    {
      return (boost::lexical_cast<std::string>(method) + "|" +
              boost::lexical_cast<std::string>(access.GetLevel()) + "|" +
              access.GetOrthancId() + "|" + token->GetKey() + "|" + tokenValue);
    }
    else
    {
      return (boost::lexical_cast<std::string>(method) + "|" +
              boost::lexical_cast<std::string>(access.GetLevel()) + "|" +
              access.GetOrthancId() + "|anonymous");
    }
  }
    

  std::string CachedAuthorizationService::ComputeKey(const std::string& permission,
                                                     const Token* token,
                                                     const std::string& tokenValue) const
  {
    if (token != NULL)
    {
      return (permission + "|" + token->GetKey() + "|" + tokenValue);
    }
    else
    {
      return (permission + "|anonymous");
    }
  }


  CachedAuthorizationService::CachedAuthorizationService(BaseAuthorizationService* decorated /* takes ownership */,
                                                         ICacheFactory& factory) :
    decorated_(decorated),
    cache_(factory.Create())
  {
    if (decorated_.get() == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }
  }


  bool CachedAuthorizationService::IsGrantedInternal(unsigned int& validity,
                                                     OrthancPluginHttpMethod method,
                                                     const AccessedResource& access,
                                                     const Token* token,
                                                     const std::string& tokenValue)
  {
    assert(decorated_.get() != NULL);

    std::string key = ComputeKey(method, access, token, tokenValue);
    std::string value;

    if (cache_->Retrieve(value, key))
    {
      // Return the previously cached value
      return (value == "1");
    }        
        
    bool granted = decorated_->IsGrantedInternal(validity, method, access, token, tokenValue);

    if (granted)
    {
      if (validity > 0)
      {
        cache_->Store(key, "1", validity);
      }
        
      return true;
    }
    else
    {
      if (validity > 0)
      {
        cache_->Store(key, "0", validity);
      }
        
      return false;
    }
  }

  
  bool CachedAuthorizationService::GetUserProfileInternal(unsigned int& validityNotUsed,
                                                          UserProfile& profile /* out */,
                                                          const Token* token,
                                                          const std::string& tokenValue)
  {
    assert(decorated_.get() != NULL);

    std::string key = ComputeKey("user-profile", token, tokenValue);
    std::string serializedProfile;

    if (cache_->Retrieve(serializedProfile, key))
    {
      // Return the previously cached profile
      Json::Value jsonProfile;
      
      Orthanc::Toolbox::ReadJson(jsonProfile, serializedProfile);
      
      AuthorizationWebService::FromJson(profile, jsonProfile);

      profile.tokenKey = token->GetKey();
      profile.tokenType = token->GetType();
      profile.tokenValue = tokenValue;

      return true;
    }        
    else
    {
      unsigned int validity;

      if (decorated_->GetUserProfileInternal(validity, profile, token, tokenValue))
      {
        Json::Value jsonProfile;

        AuthorizationWebService::ToJson(jsonProfile, profile);
        Orthanc::Toolbox::WriteFastJson(serializedProfile, jsonProfile);

        cache_->Store(key, serializedProfile, validity);
        
        return true;
      }
    }

    return false;
  }

  bool CachedAuthorizationService::HasUserPermissionInternal(unsigned int& validity,
                                                             const std::string& permission,
                                                             const UserProfile& profile)
  {
    assert(decorated_.get() != NULL);

    Token token(profile.tokenType, profile.tokenKey);
    std::string key = ComputeKey(permission, &token, profile.tokenValue);
    std::string value;

    if (cache_->Retrieve(value, key))
    {
      // Return the previously cached value
      return (value == "1");
    }        
        
    bool granted = decorated_->HasUserPermissionInternal(validity, permission, profile);

    if (granted)
    {
      if (validity > 0)
      {
        cache_->Store(key, "1", validity);
      }
        
      return true;
    }
    else
    {
      if (validity > 0)
      {
        cache_->Store(key, "0", validity);
      }
        
      return false;
    }
  }



}
