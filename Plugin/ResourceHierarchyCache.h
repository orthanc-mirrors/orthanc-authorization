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

#include "ICacheFactory.h"
#include "Enumerations.h"
#include "OrthancResource.h"

#include <orthanc/OrthancCPlugin.h>
#include <memory>

namespace OrthancPlugins
{
  class ResourceHierarchyCache : public boost::noncopyable
  {
  private:
    OrthancPluginContext   *context_;
    std::auto_ptr<ICache>   cache_;   // Maps resources to their parents
    std::auto_ptr<ICache>   orthancToDicom_;
    std::auto_ptr<ICache>   dicomToOrthanc_;

    std::string ComputeKey(Orthanc::ResourceType level,
                           const std::string identifier) const;
    
    std::string ComputeKey(const OrthancResource& resource) const
    {
      return ComputeKey(resource.GetLevel(), resource.GetIdentifier());
    }

    void LinkParent(const OrthancResource& child,
                    const OrthancResource& parent);

    bool LookupParent(std::string& target,
                      const OrthancResource& resource);

    bool LookupParent(std::string& target,
                      Orthanc::ResourceType level,
                      const std::string& identifier)
    {
      return LookupParent(target, OrthancResource(level, identifier));
    }

  public:
    ResourceHierarchyCache(OrthancPluginContext* context,
                           ICacheFactory& factory);

    void Invalidate(Orthanc::ResourceType level,
                    const std::string& identifier);

    bool LookupStudy(std::string& patient,
                     const std::string& study)
    {
      return LookupParent(patient, Orthanc::ResourceType_Study, study);
    }

    bool LookupSeries(std::string& patient,
                      std::string& study,
                      const std::string& series);

    bool LookupInstance(std::string& patient,
                        std::string& study,
                        std::string& series,
                        const std::string& instance);

    bool LookupDicomUid(std::string& target,
                        Orthanc::ResourceType level,
                        const std::string& orthancId);

    bool LookupOrthancId(std::string& target,
                         Orthanc::ResourceType level,
                         const std::string& dicomUid);
  };
}