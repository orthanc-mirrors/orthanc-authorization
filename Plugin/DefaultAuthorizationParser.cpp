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

#include "DefaultAuthorizationParser.h"

#include <OrthancException.h>
#include <HttpServer/HttpToolbox.h>

namespace OrthancPlugins
{
  DefaultAuthorizationParser::DefaultAuthorizationParser(ICacheFactory& factory,
                                                         const std::string& dicomWebRoot) :
    AuthorizationParserBase(factory),
    resourcesPattern_("^/(patients|studies|series|instances)/([a-f0-9-]+)(|/.*)$"),
    seriesPattern_("^/(web-viewer/series|web-viewer/is-stable-series|wsi/pyramids|wsi/tiles)/([a-f0-9-]+)(|/.*)$"),
    instancesPattern_("^/web-viewer/instances/[a-z0-9]+-([a-f0-9-]+)_[0-9]+$"),
    osimisViewerSeries_("^/osimis-viewer/series/([a-f0-9-]+)(|/.*)$"),
    osimisViewerImages_("^/osimis-viewer/(images|custom-command)/([a-f0-9-]+)(|/.*)$"),
    osimisViewerStudies_("^/osimis-viewer/studies/([a-f0-9-]+)(|/.*)$")
  {
    std::string tmp = dicomWebRoot;
    while (!tmp.empty() &&
           tmp[tmp.size() - 1] == '/')
    {
      tmp = tmp.substr(0, tmp.size() - 1);
    }

    dicomWebStudies_ = boost::regex(
      "^" + tmp + "/studies/([.0-9]+)(|/series)(|/)$");
      
    dicomWebSeries_ = boost::regex(
      "^" + tmp + "/studies/([.0-9]+)/series/([.0-9]+)(|/instances)(|/)$");
      
    dicomWebInstances_ = boost::regex(
      "^" + tmp + "/studies/([.0-9]+)/series/([.0-9]+)/instances/([.0-9]+)(|/|/frames/.*)$");

    dicomWebQidoRsFind_ = boost::regex(
      "^" + tmp + "/(studies|series|instances)$");
  }


  bool DefaultAuthorizationParser::Parse(AccessedResources& target,
                                         const std::string& uri,
                                         const std::map<std::string, std::string>& getArguments)
  {
    // The mutex below should not be necessary, but we prefer to
    // ensure thread safety in boost::regex
    boost::mutex::scoped_lock lock(mutex_);

    boost::smatch what;

    if (boost::regex_match(uri, what, resourcesPattern_))
    {
      AccessLevel level = StringToAccessLevel(what[1]);

      switch (level)
      {
        case AccessLevel_Instance:
          AddOrthancInstance(target, what[2]);
          break;

        case AccessLevel_Series:
          AddOrthancSeries(target, what[2]);
          break;

        case AccessLevel_Study:
          AddOrthancStudy(target, what[2]);
          break;

        case AccessLevel_Patient:
          AddOrthancPatient(target, what[2]);
          break;

        default:
          throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
      }

      return true;
    }
    else if (boost::regex_match(uri, what, seriesPattern_))
    {
      AddOrthancSeries(target, what[2]);
      return true;
    }
    else if (boost::regex_match(uri, what, instancesPattern_))
    {
      AddOrthancInstance(target, what[1]);
      return true;
    }
    else if (boost::regex_match(uri, what, dicomWebStudies_))
    {
      AddDicomStudy(target, what[1]);
      return true;
    }
    else if (boost::regex_match(uri, what, dicomWebSeries_))
    {
      AddDicomSeries(target, what[1], what[2]);
      return true;
    }
    else if (boost::regex_match(uri, what, dicomWebInstances_))
    {
      AddDicomInstance(target, what[1], what[2], what[3]);
      return true;
    }
    else if (boost::regex_match(uri, what, osimisViewerSeries_))
    {
      AddOrthancSeries(target, what[1]);
      return true;
    }
    else if (boost::regex_match(uri, what, osimisViewerStudies_))
    {
      AddOrthancStudy(target, what[1]);
      return true;
    }
    else if (boost::regex_match(uri, what, osimisViewerImages_))
    {
      AddOrthancInstance(target, what[2]);
      return true;
    }
    else if (boost::regex_match(uri, what, dicomWebQidoRsFind_))
    {
      std::string studyInstanceUid, seriesInstanceUid, sopInstanceUid, patientId;

      studyInstanceUid = Orthanc::HttpToolbox::GetArgument(getArguments, "0020000D", "");
      seriesInstanceUid = Orthanc::HttpToolbox::GetArgument(getArguments, "0020000E", "");
      sopInstanceUid = Orthanc::HttpToolbox::GetArgument(getArguments, "00080018", "");
      patientId = Orthanc::HttpToolbox::GetArgument(getArguments, "00100010", "");

      if (!sopInstanceUid.empty() && !seriesInstanceUid.empty() && !studyInstanceUid.empty())
      {
        AddDicomInstance(target, studyInstanceUid, seriesInstanceUid, sopInstanceUid);
        return true;
      }
      else if (!seriesInstanceUid.empty() && !studyInstanceUid.empty())
      {
        AddDicomSeries(target, studyInstanceUid, seriesInstanceUid);
        return true;
      }
      else if (!studyInstanceUid.empty())
      {
        AddDicomStudy(target, studyInstanceUid);
        return true;
      }
      else if (!patientId.empty())
      {
        AddDicomPatient(target, patientId);
        return true;
      }
    }

    // Unknown type of resource: Consider it as a system access

    // Remove the trailing slashes if need be
    std::string s = uri;
    while (!s.empty() &&
            s[s.length() - 1] == '/')
    {
      s = s.substr(0, s.length() - 1);
    }
        
    target.push_back(AccessedResource(AccessLevel_System, s, ""));
    return true;
  }
}
