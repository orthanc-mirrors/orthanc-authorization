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

#include "AuthorizationParserBase.h"

#include "../Resources/Orthanc/Core/OrthancException.h"

namespace OrthancPlugins
{
  void AuthorizationParserBase::AddResourceInternal(AccessedResources& target,
                                                    Orthanc::ResourceType level,
                                                    const std::string& orthancId)
  {
    std::string dicomUid;

    if (resourceHierarchy_->LookupDicomUid(dicomUid, level, orthancId))
    {
      target.push_back(AccessedResource(level, orthancId, dicomUid));
    }
  }
    

  void AuthorizationParserBase::AddOrthancInstance(AccessedResources& target,
                                                   const std::string& orthancId)
  {
    std::string patient, study, series;
    if (!resourceHierarchy_->LookupInstance(patient, study, series, orthancId))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
    }

    AddResourceInternal(target, Orthanc::ResourceType_Patient, patient);
    AddResourceInternal(target, Orthanc::ResourceType_Study, study);
    AddResourceInternal(target, Orthanc::ResourceType_Series, series);
    AddResourceInternal(target, Orthanc::ResourceType_Instance, orthancId);
  }

  
  void AuthorizationParserBase::AddOrthancSeries(AccessedResources& target,
                                                 const std::string& orthancId)
  {
    std::string patient, study;
    if (!resourceHierarchy_->LookupSeries(patient, study, orthancId))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
    }

    AddResourceInternal(target, Orthanc::ResourceType_Patient, patient);
    AddResourceInternal(target, Orthanc::ResourceType_Study, study);
    AddResourceInternal(target, Orthanc::ResourceType_Series, orthancId);
  }

  
  void AuthorizationParserBase::AddOrthancStudy(AccessedResources& target,
                                                const std::string& orthancId)
  {
    std::string patient;
    if (!resourceHierarchy_->LookupStudy(patient, orthancId))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
    }

    AddResourceInternal(target, Orthanc::ResourceType_Patient, patient);
    AddResourceInternal(target, Orthanc::ResourceType_Study, orthancId);
  }

  
  void AuthorizationParserBase::AddOrthancPatient(AccessedResources& target,
                                                  const std::string& orthancId)
  {
    AddResourceInternal(target, Orthanc::ResourceType_Patient, orthancId);
  }

  
  void AuthorizationParserBase::AddDicomStudy(AccessedResources& target,
                                              const std::string& studyDicomUid)
  {
    std::string patient, study;

    if (!resourceHierarchy_->LookupOrthancId(study, Orthanc::ResourceType_Study, studyDicomUid) ||
        !resourceHierarchy_->LookupStudy(patient, study))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
    }

    AddResourceInternal(target, Orthanc::ResourceType_Patient, patient);
    target.push_back(AccessedResource(Orthanc::ResourceType_Study, study, studyDicomUid));
  }

  
  void AuthorizationParserBase::AddDicomSeries(AccessedResources& target,
                                               const std::string& studyDicomUid,
                                               const std::string& seriesDicomUid)
  {
    std::string series;

    if (!resourceHierarchy_->LookupOrthancId(series, Orthanc::ResourceType_Series, seriesDicomUid))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
    }

    AddDicomStudy(target, studyDicomUid);
    target.push_back(AccessedResource(Orthanc::ResourceType_Series, series, seriesDicomUid));
  }

  
  void AuthorizationParserBase::AddDicomInstance(AccessedResources& target,
                                                 const std::string& studyDicomUid,
                                                 const std::string& seriesDicomUid,
                                                 const std::string& instanceDicomUid)
  {
    std::string instance;

    if (!resourceHierarchy_->LookupOrthancId
        (instance, Orthanc::ResourceType_Instance, instanceDicomUid))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_UnknownResource);
    }

    AddDicomSeries(target, studyDicomUid, seriesDicomUid);
    target.push_back(AccessedResource(Orthanc::ResourceType_Instance, instance, instanceDicomUid));
  }

  
  AuthorizationParserBase::AuthorizationParserBase(OrthancPluginContext* context,
                                                   ICacheFactory& factory)
  {
    resourceHierarchy_.reset(new ResourceHierarchyCache(context, factory));

    if (resourceHierarchy_.get() == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }
  }
}
    
