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
#include "ICacheFactory.h"

#include <Compatibility.h>  // For std::unique_ptr<>

#include <memory>

namespace OrthancPlugins
{
  /**
   * Decorator design pattern to add a cache around an IAuthorizationService
   **/
  class CachedAuthorizationService : public BaseAuthorizationService
  {
  private:
    std::unique_ptr<BaseAuthorizationService>  decorated_;
    std::unique_ptr<ICache>   cache_;

    std::string ComputeKey(OrthancPluginHttpMethod method,
                           const AccessedResource& access,
                           const Token& token,
                           const std::string& tokenValue) const;

    std::string ComputeKey(const std::string& permission,
                           const Token& token,
                           const std::string& tokenValue) const;

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
    CachedAuthorizationService(BaseAuthorizationService* decorated /* takes ownership */,
                               ICacheFactory& factory);

 };
}
