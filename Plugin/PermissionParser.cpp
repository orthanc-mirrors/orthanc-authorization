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

#include "PermissionParser.h"

#include <Toolbox.h>
#include <OrthancException.h>
#include <Logging.h>

namespace OrthancPlugins
{
  PermissionPattern::PermissionPattern(const OrthancPluginHttpMethod& method, const std::string& patternRegex, const std::string& permissions) :
    method(method),
    pattern(patternRegex)
  {
    if (!permissions.empty())
    {
      std::vector<std::string> permissionsVector;
      Orthanc::Toolbox::TokenizeString(permissionsVector, permissions, '|');

      for (size_t i = 0; i < permissionsVector.size(); ++i)
      {
        this->permissions.insert(permissionsVector[i]);
      }
    }
  }


  static void Replace(std::string& text, const std::string& findText, const std::string& replaceText)
  {
    size_t pos = text.find(findText);
    if (pos != std::string::npos)
    {
      text = text.replace(pos, findText.size(), replaceText);
    }
  }


  static void StripLeadingAndTrailingSlashes(std::string& text)
  {
    if (text.size() > 1 && text[0] == '/')
    {
      text = text.substr(1, text.size() -1);
    }
    if (text.size() > 1 && text[text.size() - 1] == '/')
    {
      text = text.substr(0, text.size() -1);
    }
  }


  PermissionParser::PermissionParser(const std::string& dicomWebRoot, const std::string& oe2Root) :
    dicomWebRoot_(dicomWebRoot),
    oe2Root_(oe2Root)
  {
  }

  void PermissionParser::Add(const Json::Value& configuration, const IAuthorizationParser* authorizationParser)
  {
    if (configuration.type() != Json::arrayValue)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadParameterType, "Permissions should be an array.");
    }

    for (Json::ArrayIndex i = 0; i < configuration.size(); ++i)
    {
      const Json::Value& permission = configuration[i];
      if (permission.type() != Json::arrayValue || permission.size() < 3)
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_BadParameterType, "Permissions elements should be an array of min size 3.");
      }

      if (permission[1].asString() == "SINGLE_RESOURCE_PATTERNS")
      {
        std::vector<boost::regex> singleResourcePatterns;
        authorizationParser->GetSingleResourcePatterns(singleResourcePatterns);

        for (std::vector<boost::regex>::const_iterator it = singleResourcePatterns.begin(); it != singleResourcePatterns.end(); ++it)
        {
          Add(permission[0].asString(),    // 0 = HTTP method
              it->str(),                   // 1 = pattern
              permission[2].asString()     // 2 = list of | separated permissions (no space)
                                           // 3 = optional comment
          );
        }
      }
      else
      {
        Add(permission[0].asString(),    // 0 = HTTP method
            permission[1].asString(),    // 1 = pattern
            permission[2].asString()     // 2 = list of | separated permissions (no space)
                                         // 3 = optional comment
        );
      }
    }

  }

  void PermissionParser::Add(const std::string& method,
                             const std::string& patternRegex,
                             const std::string& permission)
  {
    std::string lowerCaseMethod;
    Orthanc::Toolbox::ToLowerCase(lowerCaseMethod, method);
    OrthancPluginHttpMethod parsedMethod = OrthancPluginHttpMethod_Get;

    if (lowerCaseMethod == "post")
    {
      parsedMethod = OrthancPluginHttpMethod_Post;
    }
    else if (lowerCaseMethod == "put")
    {
      parsedMethod = OrthancPluginHttpMethod_Put;
    }
    else if (lowerCaseMethod == "delete")
    {
      parsedMethod = OrthancPluginHttpMethod_Delete;
    }
    else if (lowerCaseMethod == "get")
    {
      parsedMethod = OrthancPluginHttpMethod_Get;
    }
    else
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange, std::string("Invalid HTTP method ") + method);
    }

    std::string regex = patternRegex;
    std::string strippedDicomWebRoot = dicomWebRoot_;

    StripLeadingAndTrailingSlashes(strippedDicomWebRoot);
    Replace(regex, "DICOM_WEB_ROOT", strippedDicomWebRoot);

    LOG(WARNING) << "Authorization plugin: adding a new permission pattern: " << lowerCaseMethod << " " << regex << " - " << permission;

    permissionsPattern_.push_back(PermissionPattern(parsedMethod, regex, permission));
  }

  bool PermissionParser::Parse(std::set<std::string>& permissions,
                               std::string& matchedPattern,
                               const OrthancPluginHttpMethod& method,
                               const std::string& uri) const
  {
    // The mutex below should not be necessary, but we prefer to
    // ensure thread safety in boost::regex
    boost::mutex::scoped_lock lock(mutex_);


    for (std::list<PermissionPattern>::const_iterator it = permissionsPattern_.begin();
      it != permissionsPattern_.end(); ++it)
    {
      if (method == it->method)
      {
        boost::smatch what;
        if (boost::regex_match(uri, what, it->pattern))
        {
          matchedPattern = it->pattern.expression();
          permissions = it->permissions;
          return true;
        }
      }
    }

    return false;
  }
}
