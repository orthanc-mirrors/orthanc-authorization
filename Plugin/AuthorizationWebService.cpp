/**
 * Advanced authorization plugin for Orthanc
 * Copyright (C) 2017-2023 Osimis S.A., Belgium
 * Copyright (C) 2024-2024 Orthanc Team SRL, Belgium
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
#include "SerializationToolbox.h"

namespace OrthancPlugins
{
  static const char* GRANTED = "granted";
  static const char* VALIDITY = "validity";
  static const char* PERMISSIONS = "permissions";
  static const char* AUTHORIZED_LABELS = "authorized-labels";
  static const char* USER_NAME = "name";
  

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
      body["server-id"] = identifier_;
    }
    else
    {
      body["server-id"] = Json::nullValue;
    }

    if (access.GetLabels().size() > 0)
    {
      Orthanc::SerializationToolbox::WriteSetOfStrings(body, access.GetLabels(), "labels");
    }

    Orthanc::WebServiceParameters authWebservice;

    if (!username_.empty())
    {
      authWebservice.SetCredentials(username_, password_);
    }

    std::string bodyAsString;
    Orthanc::Toolbox::WriteFastJson(bodyAsString, body);

    Orthanc::HttpClient authClient(authWebservice, "");
    authClient.SetUrl(tokenValidationUrl_);
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

  void AuthorizationWebService::SetIdentifier(const std::string& webServiceIdentifier)
  {
    identifier_ = webServiceIdentifier;
  }


  bool AuthorizationWebService::DecodeToken(DecodedToken& response,
                                            const std::string& tokenKey, 
                                            const std::string& tokenValue)
  {
    if (tokenDecoderUrl_.empty())
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadRequest, "Can not create tokens if the 'WebServiceTokenValidationUrl' is not configured");
    }
    Orthanc::WebServiceParameters authWebservice;

    if (!username_.empty())
    {
      authWebservice.SetCredentials(username_, password_);
    }

    Json::Value body;

    body["token-key"] = tokenKey;
    body["token-value"] = tokenValue;

    std::string bodyAsString;
    Orthanc::Toolbox::WriteFastJson(bodyAsString, body);

    Json::Value tokenResponse;
    try
    {
      Orthanc::HttpClient authClient(authWebservice, "");
      authClient.SetUrl(tokenDecoderUrl_);
      authClient.AssignBody(bodyAsString);
      authClient.SetMethod(Orthanc::HttpMethod_Post);
      authClient.AddHeader("Content-Type", "application/json");
      authClient.AddHeader("Expect", "");
      authClient.SetTimeout(10);

      authClient.ApplyAndThrowException(tokenResponse);

      if (tokenResponse.isMember("redirect-url"))
      {
        response.redirectUrl = tokenResponse["redirect-url"].asString();
      }

      if (tokenResponse.isMember("error-code"))
      {
        response.errorCode = tokenResponse["error-code"].asString();
      }

      if (tokenResponse.isMember("token-type"))
      {
        response.tokenType = tokenResponse["token-type"].asString();
      }

      return true;
    }
    catch (Orthanc::OrthancException& ex)
    {
      return false;
    }

  }

  bool AuthorizationWebService::CreateToken(IAuthorizationService::CreatedToken& response,
                                            const std::string& tokenType, 
                                            const std::string& id, 
                                            const std::vector<IAuthorizationService::OrthancResource>& resources,
                                            const std::string& expirationDateString,
                                            const uint64_t& validityDuration)
  {
    if (tokenCreationBaseUrl_.empty())
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadRequest, "Can not create tokens if the 'WebServiceTokenCreationBaseUrl' is not configured");
    }
    std::string url = Orthanc::Toolbox::JoinUri(tokenCreationBaseUrl_, tokenType);

    Orthanc::WebServiceParameters authWebservice;

    if (!username_.empty())
    {
      authWebservice.SetCredentials(username_, password_);
    }

    Json::Value body;

    if (!id.empty())
    {
      body["id"] = id;
    }

    body["resources"] = Json::arrayValue;
    for (size_t i = 0; i < resources.size(); ++i)
    {
      Json::Value resource;
      if (!resources[i].dicomUid.empty())
      {
        resource["dicom-uid"] = resources[i].dicomUid;
      }
      if (!resources[i].orthancId.empty())
      {
        resource["orthanc-id"] = resources[i].orthancId;
      }
      if (!resources[i].url.empty())
      {
        resource["url"] = resources[i].url;
      }
      if (!resources[i].level.empty())
      {
        resource["level"] = resources[i].level;
      }

      body["resources"].append(resource);
    }

    body["type"] = tokenType;
    if (!expirationDateString.empty())
    {
      body["expiration-date"] = expirationDateString;
    }
    if (validityDuration > 0)
    {
      body["validity-duration"] = Json::UInt64(validityDuration);
    }

    std::string bodyAsString;
    Orthanc::Toolbox::WriteFastJson(bodyAsString, body);

    Json::Value tokenResponse;
    try
    {
      Orthanc::HttpClient authClient(authWebservice, "");
      authClient.SetUrl(url);
      authClient.AssignBody(bodyAsString);
      authClient.SetMethod(Orthanc::HttpMethod_Put);
      authClient.AddHeader("Content-Type", "application/json");
      authClient.AddHeader("Expect", "");
      authClient.SetTimeout(10);

      authClient.ApplyAndThrowException(tokenResponse);

      response.token = tokenResponse["token"].asString();
      response.url = tokenResponse["url"].asString();

      return true;
    }
    catch (Orthanc::OrthancException& ex)
    {
      return false;
    }

  }

  void AuthorizationWebService::ToJson(Json::Value& jsonProfile, const UserProfile& profile)
  {
    jsonProfile = Json::objectValue;
    jsonProfile[USER_NAME] = profile.name;
    Orthanc::SerializationToolbox::WriteSetOfStrings(jsonProfile, profile.authorizedLabels, AUTHORIZED_LABELS);
    Orthanc::SerializationToolbox::WriteSetOfStrings(jsonProfile, profile.permissions, PERMISSIONS);
  }
    
  void AuthorizationWebService::FromJson(UserProfile& profile, const Json::Value& jsonProfile)
  {
    if (jsonProfile.type() != Json::objectValue ||
        !jsonProfile.isMember(PERMISSIONS) ||
        !jsonProfile.isMember(AUTHORIZED_LABELS) ||
        !jsonProfile.isMember(USER_NAME) ||
        jsonProfile[PERMISSIONS].type() != Json::arrayValue ||
        jsonProfile[AUTHORIZED_LABELS].type() != Json::arrayValue ||
        jsonProfile[USER_NAME].type() != Json::stringValue)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat,
                                      "Syntax error in the result of the Auth Web service, the format of the UserProfile is invalid");
    }

    profile.name = jsonProfile[USER_NAME].asString();

    for (Json::ArrayIndex i = 0; i < jsonProfile[PERMISSIONS].size(); ++i)
    {
      profile.permissions.insert(jsonProfile[PERMISSIONS][i].asString());
    }
    for (Json::ArrayIndex i = 0; i < jsonProfile[AUTHORIZED_LABELS].size(); ++i)
    {
      profile.authorizedLabels.insert(jsonProfile[AUTHORIZED_LABELS][i].asString());
    }
  }



  bool AuthorizationWebService::GetUserProfileInternal(unsigned int& validity,
                                                       UserProfile& profile /* out */,
                                                       const Token* token,
                                                       const std::string& tokenValue)
  {
    if (userProfileUrl_.empty())
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadRequest, "Can not get user profile if the 'WebServiceUserProfileUrl' is not configured");
    }

    Orthanc::WebServiceParameters authWebservice;

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
      authClient.SetUrl(userProfileUrl_);
      authClient.AssignBody(bodyAsString);
      authClient.SetMethod(Orthanc::HttpMethod_Post);
      authClient.AddHeader("Content-Type", "application/json");
      authClient.AddHeader("Expect", "");
      authClient.SetTimeout(10);

      Json::Value jsonProfile;
      authClient.ApplyAndThrowException(jsonProfile);

      if (!jsonProfile.isMember(VALIDITY) ||
        jsonProfile[VALIDITY].type() != Json::intValue)
      {
        throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat,
                                        "Syntax error in the result of the Auth Web service, the format of the UserProfile is invalid");
      }
      validity = jsonProfile[VALIDITY].asUInt();
      profile.tokenKey = token->GetKey();
      profile.tokenType = token->GetType();
      profile.tokenValue = tokenValue;

      FromJson(profile, jsonProfile);

      if (profile.authorizedLabels.size() == 0)
      {
        LOG(WARNING) << "The UserProfile for '" << profile.name << "' does not contain any authorized labels";
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
                                                          const UserProfile& profile)
  {
    const std::set<std::string>& permissions = profile.permissions;
    for (std::set<std::string>::const_iterator it = permissions.begin(); it != permissions.end(); ++it)
    {
      if (permission == *it)
      {
        return true;
      }
    }

    return false;
  }

}
