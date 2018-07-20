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

#include "ResourceHierarchyCache.h"

#include <Core/Logging.h>
#include <Core/OrthancException.h>

#include <boost/lexical_cast.hpp>

namespace OrthancPlugins
{
  std::string ResourceHierarchyCache::ComputeKey(Orthanc::ResourceType level,
                                                 const std::string identifier) const
  {
    return boost::lexical_cast<std::string>(level) + "|" + identifier;
  }
    

  void ResourceHierarchyCache::LinkParent(const OrthancResource& child,
                                          const OrthancResource& parent)
  {
    LOG(INFO) << "Linking " << Orthanc::EnumerationToString(child.GetLevel())
              << " \"" << child.GetIdentifier() << "\" to its parent "
              << Orthanc::EnumerationToString(parent.GetLevel())
              << " \"" << parent.GetIdentifier() << "\"";
        
    cache_->Store(ComputeKey(child), parent.GetIdentifier(), 0 /* no expiration */);
  }


  bool ResourceHierarchyCache::LookupParent(std::string& target,
                                            const OrthancResource& resource)
  {
    std::string key = ComputeKey(resource);
      
    if (cache_->Retrieve(target, key))
    {
      // The parent was already stored in the cache
      return true;
    }

    // Not in the cache, reading the resource from the Orthanc store
    std::string dicomUid;
    OrthancResource parent;
    std::list<OrthancResource> children;

    if (!resource.GetHierarchy(dicomUid, parent, children, context_))
    {
      // The resource is non-existing (*)
      return false;
    }

    orthancToDicom_->Store(key, dicomUid, 0 /* no expiration */);
    dicomToOrthanc_->Store(ComputeKey(resource.GetLevel(), dicomUid),
                           resource.GetIdentifier(), 0 /* no expiration */);

    for (std::list<OrthancResource>::const_iterator
           it = children.begin(); it != children.end(); ++it)
    {
      // Cache the relation of the resource with its children
      LinkParent(*it, resource);
    }

    if (parent.IsValid())
    {
      LinkParent(resource, parent);
      target = parent.GetIdentifier();
      return true;
    }
    else
    {
      // We reached the patient level, or the resource was removed
      // from Orthanc since (*)
      return false;
    }
  }


  ResourceHierarchyCache::ResourceHierarchyCache(OrthancPluginContext* context,
                                                 ICacheFactory& factory) :
    context_(context),
    cache_(factory.Create()),
    orthancToDicom_(factory.Create()),
    dicomToOrthanc_(factory.Create())
  {
    if (cache_.get() == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }
  }

  
  void ResourceHierarchyCache::Invalidate(Orthanc::ResourceType level,
                                          const std::string& identifier)
  {
    LOG(INFO) << "Invalidating " << Orthanc::EnumerationToString(level)
              << " resource with ID: " << identifier;

    std::string key = ComputeKey(level, identifier);
    cache_->Invalidate(key);
    orthancToDicom_->Invalidate(key);
  }


  bool ResourceHierarchyCache::LookupSeries(std::string& patient,
                                            std::string& study,
                                            const std::string& series)
  {
    if (LookupParent(study, Orthanc::ResourceType_Series, series))
    {
      return LookupStudy(patient, study);
    }
    else
    {
      return false;
    }
  }

  
  bool ResourceHierarchyCache::LookupInstance(std::string& patient,
                                              std::string& study,
                                              std::string& series,
                                              const std::string& instance)
  {
    if (LookupParent(series, Orthanc::ResourceType_Instance, instance))
    {
      return LookupSeries(patient, study, series);
    }
    else
    {
      return false;
    }
  }


  bool ResourceHierarchyCache::LookupDicomUid(std::string& target,
                                              Orthanc::ResourceType level,
                                              const std::string& orthancId)
  {
    std::string key = ComputeKey(level, orthancId);

    if (orthancToDicom_->Retrieve(target, key))
    {
      return true;
    }

    OrthancResource resource(level, orthancId);

    if (resource.GetDicomUid(target, context_))
    {
      orthancToDicom_->Store(key, target, 0 /* no expiration */);
      return true;
    }
    else
    {
      return false;
    }
  }

  
  bool ResourceHierarchyCache::LookupOrthancId(std::string& target,
                                               Orthanc::ResourceType level,
                                               const std::string& dicomUid)
  {
    std::string key = ComputeKey(level, dicomUid);

    if (dicomToOrthanc_->Retrieve(target, key))
    {
      return true;
    }

    OrthancResource resource(level, dicomUid);

    if (OrthancResource::LookupOrthancId(target, context_, level, dicomUid))
    {
      dicomToOrthanc_->Store(key, target, 0 /* no expiration */);
      return true;
    }
    else
    {
      return false;
    }
  }
}
