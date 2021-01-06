/**
 * Advanced authorization plugin for Orthanc
 * Copyright (C) 2017-2021 Osimis S.A., Belgium
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

    MemoryBuffer answerBody;
    MemoryBuffer answerHeaders;
    uint16_t httpStatus = 0;

    uint32_t headersCount = 0;
    const char* headersKeys[2];
    const char* headersValues[2];
      
    if (token != NULL &&
        token->GetType() == TokenType_HttpHeader)
    {
      // If the token source is a HTTP header, forward it also as a
      // HTTP header
      headersKeys[headersCount] = token->GetKey().c_str();
      headersValues[headersCount] = tokenValue.c_str();
      headersCount++;
    }

    // set the correct content type for the outgoing
    headersKeys[headersCount] = "Content-Type";
    headersValues[headersCount] = "application/json";
    headersCount++;

    std::string flatBody = body.toStyledString();
      
    if (OrthancPluginHttpClient(GetGlobalContext(), *answerBody, *answerHeaders,
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
}
