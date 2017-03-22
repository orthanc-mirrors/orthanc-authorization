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

#include "AuthorizationWebService.h"

#include "../Resources/Orthanc/Core/Logging.h"
#include "../Resources/Orthanc/Plugins/Samples/Common/OrthancPluginCppWrapper.h"

namespace OrthancPlugins
{
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

    MemoryBuffer answerBody(context_);
    MemoryBuffer answerHeaders(context_);
    uint16_t httpStatus = 0;

    uint32_t headersCount = 0;
    const char* headersKeys[1];
    const char* headersValues[1];
      
    if (token != NULL &&
        token->GetType() == TokenType_HttpHeader)
    {
      // If the token source is a HTTP header, forward it also as a
      // HTTP header
      headersCount = 1;
      headersKeys[0] = token->GetKey().c_str();
      headersValues[0] = tokenValue.c_str();
    }

    std::string flatBody = body.toStyledString();
      
    if (OrthancPluginHttpClient(context_, *answerBody, *answerHeaders,
                                &httpStatus, OrthancPluginHttpMethod_Post,
                                url_.c_str(), headersCount, headersKeys, headersValues,
                                flatBody.c_str(), flatBody.size(),
                                username_.empty() ? NULL : username_.c_str(),
                                password_.empty() ? NULL : password_.c_str(),
                                10 /* timeout */, NULL, NULL, NULL, 0)
        != OrthancPluginErrorCode_Success)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol);        
    }

    Json::Value answer;
    answerBody.ToJson(answer);

    static const char* GRANTED = "granted";
    static const char* VALIDITY = "validity";
      
    if (answer.type() != Json::objectValue ||
        !answer.isMember(GRANTED) ||
        answer[GRANTED].type() != Json::booleanValue ||
        (answer.isMember(VALIDITY) &&
         answer[VALIDITY].type() != Json::intValue))
    {
      LOG(ERROR) << "Syntax error in the result of the Web service";
      throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol);
    }

    validity = 0;
    if (answer.isMember(VALIDITY))
    {
      int tmp = answer[VALIDITY].asInt();
      if (tmp < 0)
      {
        LOG(ERROR) << "A validity duration cannot be negative";
        throw Orthanc::OrthancException(Orthanc::ErrorCode_NetworkProtocol);          
      }

      validity = static_cast<unsigned int>(tmp);
    }

    return answer[GRANTED].asBool();
  }
    

  AuthorizationWebService::AuthorizationWebService(OrthancPluginContext* context,
                                                   const std::string& url) :
    context_(context),
    url_(url)
  {
    if (context_ == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
    }
  }

    
  void AuthorizationWebService::SetCredentials(const std::string& username,
                                               const std::string& password)
  {
    username_ = username;
    password_ = password;
  }
}
