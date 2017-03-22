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

#include "AccessedResource.h"

#include <boost/noncopyable.hpp>
#include <list>

namespace OrthancPlugins
{
  // NOTE: This interface must be thread-safe 
  class IAuthorizationParser : public boost::noncopyable
  {
  public:
    typedef std::list<AccessedResource>  AccessedResources;
    
    virtual ~IAuthorizationParser()
    {
    }

    virtual void Invalidate(Orthanc::ResourceType level,
                            const std::string& id) = 0;

    virtual bool Parse(AccessedResources& target,
                       const std::string& uri) = 0;
  };
}
