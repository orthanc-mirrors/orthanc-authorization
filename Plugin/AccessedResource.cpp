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

#include "AccessedResource.h"

#include "../Resources/Orthanc/Core/OrthancException.h"

namespace OrthancPlugins
{
  AccessedResource::AccessedResource(AccessLevel level,
                                     const std::string& orthancId,
                                     const std::string& dicomUid) :
    level_(level),
    orthancId_(orthancId),
    dicomUid_(dicomUid)
  {
    if (level_ == AccessLevel_System &&
        !dicomUid.empty())
    {
      // The "DICOM UID" makes no sense for custom Orthanc URIs
      throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);        
    }
  }


  AccessedResource::AccessedResource(Orthanc::ResourceType level,
                                     const std::string& orthancId,
                                     const std::string& dicomUid) :
    orthancId_(orthancId),
    dicomUid_(dicomUid)
  {
    switch (level)
    {
      case Orthanc::ResourceType_Patient:
        level_ = AccessLevel_Patient;
        break;

      case Orthanc::ResourceType_Study:
        level_ = AccessLevel_Study;
        break;

      case Orthanc::ResourceType_Series:
        level_ = AccessLevel_Series;
        break;

      case Orthanc::ResourceType_Instance:
        level_ = AccessLevel_Instance;
        break;

      default:
        throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
    }
  }


  const std::string& AccessedResource::GetDicomUid() const
  {
    if (level_ == AccessLevel_System)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadSequenceOfCalls);        
    }
    else
    {
      return dicomUid_;
    }
  }
}
