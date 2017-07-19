/**
 * Advanced authorization plugin for Orthanc
 * Copyright (C) 2017 Osimis, Belgium
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
#include "ICacheFactory.h"

#include <memory>

namespace OrthancPlugins
{
  /**
   * Decorator design pattern to add a cache around an IAuthorizationService
   **/
  class CachedAuthorizationService : public IAuthorizationService
  {
  private:
    std::auto_ptr<IAuthorizationService>  decorated_;
    std::auto_ptr<ICache>   cache_;

    std::string ComputeKey(OrthancPluginHttpMethod method,
                           const AccessedResource& access,
                           const Token& token,
                           const std::string& tokenValue) const;
    
  public:
    CachedAuthorizationService(IAuthorizationService* decorated /* takes ownership */,
                               ICacheFactory& factory);

    virtual bool IsGranted(unsigned int& validity,
                           OrthancPluginHttpMethod method,
                           const AccessedResource& access,
                           const Token& token,
                           const std::string& tokenValue);
    
    virtual bool IsGranted(unsigned int& validity,
                           OrthancPluginHttpMethod method,
                           const AccessedResource& access);
  };
}