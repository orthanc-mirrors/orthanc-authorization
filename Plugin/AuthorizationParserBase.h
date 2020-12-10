/**
 * Advanced authorization plugin for Orthanc
 * Copyright (C) 2017-2020 Osimis S.A., Belgium
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

#include "IAuthorizationParser.h"
#include "ResourceHierarchyCache.h"

#include <Compatibility.h>  // For std::unique_ptr<>

namespace OrthancPlugins
{
  class AuthorizationParserBase : public IAuthorizationParser
  {
  private:
    std::unique_ptr<ResourceHierarchyCache>  resourceHierarchy_;

    void AddResourceInternal(AccessedResources& target,
                             Orthanc::ResourceType level,
                             const std::string& orthancId);
    
  protected:
    void AddOrthancInstance(AccessedResources& target,
                            const std::string& orthancId);

    void AddOrthancSeries(AccessedResources& target,
                          const std::string& orthancId);

    void AddOrthancStudy(AccessedResources& target,
                         const std::string& orthancId);

    void AddOrthancPatient(AccessedResources& target,
                           const std::string& orthancId);

    void AddDicomStudy(AccessedResources& target,
                       const std::string& studyDicomUid);
    
    void AddDicomSeries(AccessedResources& target,
                        const std::string& studyDicomUid,
                        const std::string& seriesDicomUid);

    void AddDicomInstance(AccessedResources& target,
                          const std::string& studyDicomUid,
                          const std::string& seriesDicomUid,
                          const std::string& instanceDicomUid);

  public:
    explicit AuthorizationParserBase(ICacheFactory& factory);

    virtual void Invalidate(Orthanc::ResourceType level,
                            const std::string& id) ORTHANC_OVERRIDE
    {
      resourceHierarchy_->Invalidate(level, id);
    }
  };
}
