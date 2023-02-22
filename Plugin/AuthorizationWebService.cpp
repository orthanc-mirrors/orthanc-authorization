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

#include "AuthorizationWebService.h"

#include "../Resources/Orthanc/Plugins/OrthancPluginCppWrapper.h"

#include <Logging.h>
#include <Toolbox.h>
#include <HttpClient.h>
#include <algorithm>

namespace OrthancPlugins
{
  static const char* GRANTED = "granted";
  static const char* VALIDITY = "validity";
  static const char* PERMISSIONS = "permissions";


  bool AuthorizationWebService::IsGrantedInternal(unsigned int& validity,
                                                  OrthancPluginHttpMethod method,
                                                  const AccessedResource& access,
                                                  const Token* token,
                                                  const std::string& tokenValue)
  {
    Json::Value body = Json::objectValue;
      
    switch (method)
    {
      case OrthancPluginHttpMethod_Get:
        body["method"] ="get";
        break;
          
      case OrthancPluginHttpMethod_Post:
        body["method"] ="post";
        break;
          
      case OrthancPluginHttpMethod_Put:
        body["method"] ="put";
        break;
          
      case OrthancPluginHttpMethod_Delete:
        body["method"] ="delete";
        break;
          
      default:
        throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
    }

    body["level"] = EnumerationToString(access.GetLevel());

    if (access.GetLevel() == AccessLevel_System)
    {
      body["uri"] = access.GetOrthancId();
    }
    else
    {
      body["orthanc-id"] = access.GetOrthancId();
      body["dicom-uid"] = access.GetDicomUid();
    }

    if (token != NULL)
    {
      body["token-key"] = token->GetKey();
      body["token-value"] = tokenValue;
    }

    if (!identifier_.empty())
    {
      body["identifier"] = identifier_;
    }
    else
    {
      body["identifier"] = Json::nullValue;
    }

    Orthanc::WebServiceParameters authWebservice;
    authWebservice.SetUrl(url_);

    if (!username_.empty())
    {
      authWebservice.SetCredentials(username_, password_);
    }

    std::string bodyAsString;
    Orthanc::Toolbox::WriteFastJson(bodyAsString, body);

    Orthanc::HttpClient authClient(authWebservice, "");
    authClient.AssignBody(bodyAsString);
    authClient.SetMethod(Orthanc::HttpMethod_Post);
    authClient.AddHeader("Content-Type", "application/json");
    authClient.AddHeader("Expect", "");
    authClient.SetTimeout(10);

    if (token != NULL &&
        token->GetType() == TokenType_HttpHeader)
    {
      // If the token source is a HTTP header, forward it also as a
      // HTTP header except if it is the Authorization header that might conflict with username_ and password_
      std::string lowerTokenKey;
      Orthanc::Toolbox::ToLowerCase(lowerTokenKey, token->GetKey());
      
      if (!(lowerTokenKey == "authorization" && !username_.empty()))
      {
        authClient.AddHeader(token->GetKey(), tokenValue);
      }
    }
      
    Json::Value answer;
    authClient.ApplyAndThrowException(answer);

    if (answer.type() != Json::objectValue ||
        !answer.isMember(GRANTED) ||
        answer[GRANTED].type() != Json::booleanValue ||
        (answer.isMember(VALIDITY) &&
         answer[VALIDITY].type() != Json::intValue))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol,
                                      "Syntax error in the result of the Web service");
    }

    validity = 0;
    if (answer.isMember(VALIDITY))
    {
      int tmp = answer[VALIDITY].asInt();
      if (tmp < 0)
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol,
                                        "A validity duration cannot be negative");
      }

      validity = static_cast<unsigned int>(tmp);
    }

    return answer[GRANTED].asBool();
  }
    

  void AuthorizationWebService::SetCredentials(const std::string& username,
                                               const std::string& password)
  {
    username_ = username;
    password_ = password;
  }

  void AuthorizationWebService::SetUserProfileUrl(const std::string& url)
  {
    userProfileUrl_ = url;
  }

  void AuthorizationWebService::SetIdentifier(const std::string& webServiceIdentifier)
  {
    identifier_ = webServiceIdentifier;
  }

  bool AuthorizationWebService::GetUserProfileInternal(unsigned int& validity,
                                                       Json::Value& profile /* out */,
                                                       const Token* token,
                                                       const std::string& tokenValue)
  {
    if (userProfileUrl_.empty())
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadRequest, "Can not get user profile if the 'WebServiceUserProfileUrl' is not configured");
    }

    Orthanc::WebServiceParameters authWebservice;
    authWebservice.SetUrl(userProfileUrl_);

    if (!username_.empty())
    {
      authWebservice.SetCredentials(username_, password_);
    }

    Json::Value body;

    if (token != NULL)
    {
      body["token-key"] = token->GetKey();
      body["token-value"] = tokenValue;
    }

    if (!identifier_.empty())
    {
      body["identifier"] = identifier_;
    }
    else
    {
      body["identifier"] = Json::nullValue;
    }

    std::string bodyAsString;
    Orthanc::Toolbox::WriteFastJson(bodyAsString, body);

    try
    {
      Orthanc::HttpClient authClient(authWebservice, "");
      authClient.AssignBody(bodyAsString);
      authClient.SetMethod(Orthanc::HttpMethod_Post);
      authClient.AddHeader("Content-Type", "application/json");
      authClient.AddHeader("Expect", "");
      authClient.SetTimeout(10);

      authClient.ApplyAndThrowException(profile);

      if (profile.isMember("validity"))
      {
        validity = profile["validity"].asInt();
      }
      else
      {
        validity = 0;
      }

      return true;
    }
    catch (Orthanc::OrthancException& ex)
    {
      return false;
    }
  }

  bool AuthorizationWebService::HasUserPermissionInternal(unsigned int& validity,
                                                          const std::string& permission,
                                                          const Token* token,
                                                          const std::string& tokenValue)
  {
    Json::Value profile;


    if (GetUserProfileInternal(validity, profile, token, tokenValue))
    {
      if (profile.type() != Json::objectValue ||
          !profile.isMember(PERMISSIONS) ||
          !profile.isMember(VALIDITY) ||
          profile[PERMISSIONS].type() != Json::arrayValue ||
          profile[VALIDITY].type() != Json::intValue)
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol,
                                        "Syntax error in the result of the Web service");
      }

      validity = profile[VALIDITY].asUInt();

      Json::Value& permissions = profile[PERMISSIONS];
      for (Json::ArrayIndex i = 0; i < permissions.size(); ++i)
      {
        if (permission == permissions[i].asString())
        {
          return true;
        }
      }
    }

    return false;
  }

}
