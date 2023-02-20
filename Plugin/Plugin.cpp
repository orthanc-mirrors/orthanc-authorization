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

#include "AssociativeArray.h"
#include "DefaultAuthorizationParser.h"
#include "CachedAuthorizationService.h"
#include "AuthorizationWebService.h"
#include "MemoryCache.h"

#include "../Resources/Orthanc/Plugins/OrthancPluginCppWrapper.h"

#include <Compatibility.h>  // For std::unique_ptr<>
#include <Logging.h>
#include <Toolbox.h>


// Configuration of the authorization plugin
static std::unique_ptr<OrthancPlugins::IAuthorizationParser> authorizationParser_;
static std::unique_ptr<OrthancPlugins::IAuthorizationService> authorizationService_;
static std::set<std::string> uncheckedResources_;
static std::list<std::string> uncheckedFolders_;
static std::set<OrthancPlugins::Token> tokens_;
static std::set<OrthancPlugins::AccessLevel> uncheckedLevels_;


static int32_t FilterHttpRequests(OrthancPluginHttpMethod method,
                                  const char *uri,
                                  const char *ip,
                                  uint32_t headersCount,
                                  const char *const *headersKeys,
                                  const char *const *headersValues,
                                  uint32_t getArgumentsCount,
                                  const char *const *getArgumentsKeys,
                                  const char *const *getArgumentsValues)
{
  try
  {
    if (method == OrthancPluginHttpMethod_Get)
    {
      // Allow GET accesses to static resources
      if (uncheckedResources_.find(uri) != uncheckedResources_.end())
      {
        return 1;
      }

      for (std::list<std::string>::const_iterator
             it = uncheckedFolders_.begin(); it != uncheckedFolders_.end(); ++it)
      {
        if (Orthanc::Toolbox::StartsWith(uri, *it))
        {
          return 1;
        }
      }
    }

    if (authorizationParser_.get() != NULL &&
        authorizationService_.get() != NULL)
    {
      // Parse the resources that are accessed through this URI
      OrthancPlugins::IAuthorizationParser::AccessedResources accesses;
      OrthancPlugins::AssociativeArray getArguments(getArgumentsCount, getArgumentsKeys, getArgumentsValues, true);

      if (!authorizationParser_->Parse(accesses, uri, getArguments.GetMap()))
      {
        return 0;  // Unable to parse this URI
      }

      // Loop over all the accessed resources to ensure access is
      // granted to each of them
      for (OrthancPlugins::IAuthorizationParser::AccessedResources::const_iterator
             access = accesses.begin(); access != accesses.end(); ++access)
      {
        // Ignored the access levels that are unchecked
        // (cf. "UncheckedLevels" option)
        if (uncheckedLevels_.find(access->GetLevel()) == uncheckedLevels_.end())
        {
          LOG(INFO) << "Testing whether access to "
                    << OrthancPlugins::EnumerationToString(access->GetLevel())
                    << " \"" << access->GetOrthancId() << "\" is allowed";

          bool granted = false;
          unsigned int validity;  // ignored

          if (tokens_.empty())
          {
            granted = authorizationService_->IsGranted(validity, method, *access);
          }
          else
          {
            OrthancPlugins::AssociativeArray headers
              (headersCount, headersKeys, headersValues, false);

            // Loop over all the authorization tokens stored in the HTTP
            // headers, until finding one that is granted
            for (std::set<OrthancPlugins::Token>::const_iterator
                   token = tokens_.begin(); token != tokens_.end(); ++token)
            {
              std::string value;

              bool hasValue = false;
              switch (token->GetType())
              {
                case OrthancPlugins::TokenType_HttpHeader:
                  hasValue = headers.GetValue(value, token->GetKey());
                  break;

                case OrthancPlugins::TokenType_GetArgument:
                  hasValue = getArguments.GetValue(value, token->GetKey());
                  break;

                default:
                  throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
              }
              
              if (hasValue &&
                  authorizationService_->IsGranted(validity, method, *access, *token, value))
              {
                granted = true;
                break;
              }
            }
          }

          if (!granted)
          {
            return 0;
          }
        }
      }

      // Access is granted to all the resources
      return 1;
    }
      
    // By default, forbid access to all the resources
    return 0;
  }
  catch (std::runtime_error& e)
  {
    LOG(ERROR) << e.what();
    return OrthancPluginErrorCode_Success;  // Ignore error
  }
  catch (Orthanc::OrthancException& e)
  {
    LOG(ERROR) << e.What();
    return OrthancPluginErrorCode_Success;  // Ignore error
  }
  catch (...)
  {
    LOG(ERROR) << "Unhandled internal exception";
    return OrthancPluginErrorCode_Success;  // Ignore error
  }
}

  
#if !ORTHANC_PLUGINS_VERSION_IS_ABOVE(1, 2, 1)
static int32_t FilterHttpRequestsFallback(OrthancPluginHttpMethod method,
                                          const char *uri,
                                          const char *ip,
                                          uint32_t headersCount,
                                          const char *const *headersKeys,
                                          const char *const *headersValues)
{
  // Fallback wrapper function for Orthanc <= 1.2.0, where the GET
  // arguments were not available in the HTTP filters
  return FilterHttpRequests(method, uri, ip,
                            headersCount, headersKeys, headersValues,
                            0, NULL, NULL);
}
#endif


static OrthancPluginErrorCode OnChangeCallback(OrthancPluginChangeType changeType,
                                               OrthancPluginResourceType resourceType,
                                               const char* resourceId)
{
  try
  {
    if (authorizationParser_.get() == NULL)
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }
    
    if (changeType == OrthancPluginChangeType_Deleted)
    {
      switch (resourceType)
      {
        case OrthancPluginResourceType_Patient:
          authorizationParser_->Invalidate(Orthanc::ResourceType_Patient, resourceId);
          break;

        case OrthancPluginResourceType_Study:
          authorizationParser_->Invalidate(Orthanc::ResourceType_Study, resourceId);
          break;

        case OrthancPluginResourceType_Series:
          authorizationParser_->Invalidate(Orthanc::ResourceType_Series, resourceId);
          break;

        case OrthancPluginResourceType_Instance:
          authorizationParser_->Invalidate(Orthanc::ResourceType_Instance, resourceId);
          break;

        default:
          break;
      }
    }
       
    return OrthancPluginErrorCode_Success;
  }
  catch (std::runtime_error& e)
  {
    LOG(ERROR) << e.what();
    return OrthancPluginErrorCode_Success;  // Ignore error
  }
  catch (Orthanc::OrthancException& e)
  {
    LOG(ERROR) << e.What();
    return OrthancPluginErrorCode_Success;  // Ignore error
  }
  catch (...)
  {
    LOG(ERROR) << "Unhandled internal exception";
    return OrthancPluginErrorCode_Success;  // Ignore error
  }
}

void GetUserProfile(OrthancPluginRestOutput* output,
                    const char* /*url*/,
                    const OrthancPluginHttpRequest* request)
{
  OrthancPluginContext* context = OrthancPlugins::GetGlobalContext();

  if (request->method != OrthancPluginHttpMethod_Get)
  {
    OrthancPluginSendMethodNotAllowed(context, output, "GET");
  }
  else
  {
    OrthancPlugins::AssociativeArray headers
      (request->headersCount, request->headersKeys, request->headersValues, false);

    OrthancPlugins::AssociativeArray getArguments
      (request->getCount, request->getKeys, request->getValues, true);


    // Loop over all the authorization tokens stored in the HTTP
    // headers, until finding one that is granted
    for (std::set<OrthancPlugins::Token>::const_iterator
            token = tokens_.begin(); token != tokens_.end(); ++token)
    {
      Json::Value profile;

      std::string value;

      bool hasValue = false;
      switch (token->GetType())
      {
        case OrthancPlugins::TokenType_HttpHeader:
          hasValue = headers.GetValue(value, token->GetKey());
          break;

        case OrthancPlugins::TokenType_GetArgument:
          hasValue = getArguments.GetValue(value, token->GetKey());
          break;

        default:
          throw Orthanc::OrthancException(Orthanc::ErrorCode_ParameterOutOfRange);
      }
      
      if (hasValue)
      {
        authorizationService_->GetUserProfile(profile, *token, value);
        
        OrthancPlugins::AnswerJson(profile, output);
        break;
      }
    }

  }
}


extern "C"
{
  ORTHANC_PLUGINS_API int32_t OrthancPluginInitialize(OrthancPluginContext* context)
  {
    OrthancPlugins::SetGlobalContext(context);
    OrthancPluginLogWarning(context, "Initializing the authorization plugin");

    /* Check the version of the Orthanc core */
    if (OrthancPluginCheckVersion(context) == 0)
    {
      OrthancPlugins::ReportMinimalOrthancVersion(ORTHANC_PLUGINS_MINIMAL_MAJOR_NUMBER,
                                                  ORTHANC_PLUGINS_MINIMAL_MINOR_NUMBER,
                                                  ORTHANC_PLUGINS_MINIMAL_REVISION_NUMBER);
      return -1;
    }

#if ORTHANC_FRAMEWORK_VERSION_IS_ABOVE(1, 7, 2)
    Orthanc::Logging::InitializePluginContext(context);
#else
    Orthanc::Logging::Initialize(context);
#endif
    
    OrthancPluginSetDescription(context, "Advanced authorization plugin for Orthanc.");

    try
    {
      OrthancPlugins::OrthancConfiguration general;

      static const char* SECTION = "Authorization";
      if (general.IsSection(SECTION))
      {
        OrthancPlugins::OrthancConfiguration configuration;
        general.GetSection(configuration, "Authorization");

        // TODO - The size of the caches is set to 10,000 items. Maybe add a configuration option?
        OrthancPlugins::MemoryCache::Factory factory(10000);

        {
          std::string root;

          if (configuration.IsSection("DicomWeb"))
          {
            OrthancPlugins::OrthancConfiguration dicomWeb;
            dicomWeb.GetSection(configuration, "DicomWeb");
            root = dicomWeb.GetStringValue("Root", "");
          }

          if (root.empty())
          {
            root = "/dicom-web/";
          } 

          authorizationParser_.reset
            (new OrthancPlugins::DefaultAuthorizationParser(factory, root));
        }

        std::list<std::string> tmp;

        configuration.LookupListOfStrings(tmp, "TokenHttpHeaders", true);
        for (std::list<std::string>::const_iterator
               it = tmp.begin(); it != tmp.end(); ++it)
        {
          tokens_.insert(OrthancPlugins::Token(OrthancPlugins::TokenType_HttpHeader, *it));
        }

        configuration.LookupListOfStrings(tmp, "TokenGetArguments", true);

#if ORTHANC_PLUGINS_VERSION_IS_ABOVE(1, 3, 0)  
        for (std::list<std::string>::const_iterator
               it = tmp.begin(); it != tmp.end(); ++it)
        {
          tokens_.insert(OrthancPlugins::Token(OrthancPlugins::TokenType_GetArgument, *it));
        }
#else
        if (!tmp.empty())
        {
          throw Orthanc::OrthancException(
            Orthanc::ErrorCode_Plugin,
            "The option \"TokenGetArguments\" of the authorization plugin "
            "is only valid if compiled against Orthanc >= 1.3.0"
        }
#endif

        configuration.LookupSetOfStrings(uncheckedResources_, "UncheckedResources", false);
        configuration.LookupListOfStrings(uncheckedFolders_, "UncheckedFolders", false);

        std::string url;

        static const char* WEB_SERVICE = "WebService";
        if (!configuration.LookupStringValue(url, WEB_SERVICE))
        {
          throw Orthanc::OrthancException(
            Orthanc::ErrorCode_BadFileFormat,
            "Missing mandatory option \"" + std::string(WEB_SERVICE) +
            "\" for the authorization plugin");
        }

        std::set<std::string> standardConfigurations;
        if (configuration.LookupSetOfStrings(standardConfigurations, "StandardConfigurations", false))
        {
          if (standardConfigurations.find("osimis-web-viewer") != standardConfigurations.end())
          {
            uncheckedFolders_.push_back("/osimis-viewer/app/");
            uncheckedFolders_.push_back("/osimis-viewer/languages/");
            uncheckedResources_.insert("/osimis-viewer/config.js");

            tokens_.insert(OrthancPlugins::Token(OrthancPlugins::TokenType_HttpHeader, "token"));
            tokens_.insert(OrthancPlugins::Token(OrthancPlugins::TokenType_GetArgument, "token"));  // for download links
          }

          if (standardConfigurations.find("stone-webviewer") != standardConfigurations.end())
          {
            uncheckedFolders_.push_back("/stone-webviewer/");
            uncheckedResources_.insert("/system");        // for Stone to check that Orthanc is the server providing the data
            uncheckedResources_.insert("/tools/lookup");  // for Downloads  (we consider that having access to tools/lookup can not give information about other patients/studies since it only return IDs, no patient data)

            tokens_.insert(OrthancPlugins::Token(OrthancPlugins::TokenType_HttpHeader, "Authorization"));
          }

          if (standardConfigurations.find("orthanc-explorer-2") != standardConfigurations.end())
          {
            uncheckedFolders_.push_back("/ui/app/");
            uncheckedResources_.insert("/ui/api/pre-login-configuration");        // for the UI to know, i.e. if Keycloak is enabled or not
            uncheckedResources_.insert("/auth/user-profile");

            tokens_.insert(OrthancPlugins::Token(OrthancPlugins::TokenType_HttpHeader, "Authorization"));  // for basic-auth
            tokens_.insert(OrthancPlugins::Token(OrthancPlugins::TokenType_HttpHeader, "token"));          // for keycloak
          }

        }

        std::string checkedLevelString;
        if (configuration.LookupStringValue(checkedLevelString, "CheckedLevel"))
        {
          OrthancPlugins::AccessLevel checkedLevel = OrthancPlugins::StringToAccessLevel(checkedLevelString);
          if (checkedLevel == OrthancPlugins::AccessLevel_Instance) 
          {
            uncheckedLevels_.insert(OrthancPlugins::AccessLevel_Patient);
            uncheckedLevels_.insert(OrthancPlugins::AccessLevel_Study);
            uncheckedLevels_.insert(OrthancPlugins::AccessLevel_Series);
          }
          else if (checkedLevel == OrthancPlugins::AccessLevel_Series) 
          {
            uncheckedLevels_.insert(OrthancPlugins::AccessLevel_Patient);
            uncheckedLevels_.insert(OrthancPlugins::AccessLevel_Study);
            uncheckedLevels_.insert(OrthancPlugins::AccessLevel_Instance);
          }
          else if (checkedLevel == OrthancPlugins::AccessLevel_Study) 
          {
            uncheckedLevels_.insert(OrthancPlugins::AccessLevel_Patient);
            uncheckedLevels_.insert(OrthancPlugins::AccessLevel_Series);
            uncheckedLevels_.insert(OrthancPlugins::AccessLevel_Instance);
          }
          else if (checkedLevel == OrthancPlugins::AccessLevel_Patient) 
          {
            uncheckedLevels_.insert(OrthancPlugins::AccessLevel_Study);
            uncheckedLevels_.insert(OrthancPlugins::AccessLevel_Series);
            uncheckedLevels_.insert(OrthancPlugins::AccessLevel_Instance);
          }
        }

        if (configuration.LookupListOfStrings(tmp, "UncheckedLevels", false))
        {
          if (uncheckedLevels_.size() == 0)
          {
            for (std::list<std::string>::const_iterator
                  it = tmp.begin(); it != tmp.end(); ++it)
            {
              uncheckedLevels_.insert(OrthancPlugins::StringToAccessLevel(*it));
            }
          }
          else
          {
            LOG(ERROR) << "Authorization plugin: you may only provide one of 'CheckedLevel' or 'UncheckedLevels' configurations";
            return -1;
          }
        }

        std::unique_ptr<OrthancPlugins::AuthorizationWebService> webService(new OrthancPlugins::AuthorizationWebService(url));

        std::string webServiceIdentifier;
        if (configuration.LookupStringValue(webServiceIdentifier, "WebServiceIdentifier"))
        {
          webService->SetIdentifier(webServiceIdentifier);
        }

        std::string webServiceUsername;
        std::string webServicePassword;
        if (configuration.LookupStringValue(webServiceUsername, "WebServiceUsername") && configuration.LookupStringValue(webServicePassword, "WebServicePassword"))
        {
          webService->SetCredentials(webServiceUsername, webServicePassword);
        }

        std::string webServiceUserProfileUrl;
        if (configuration.LookupStringValue(webServiceUserProfileUrl, "WebServiceUserProfileUrl"))
        {
          webService->SetUserProfileUrl(webServiceUserProfileUrl);
        }

        authorizationService_.reset
          (new OrthancPlugins::CachedAuthorizationService
           (webService.release(), factory));

        OrthancPluginRegisterOnChangeCallback(context, OnChangeCallback);
        OrthancPlugins::RegisterRestCallback<GetUserProfile>("/auth/user-profile", true);
        
#if ORTHANC_PLUGINS_VERSION_IS_ABOVE(1, 2, 1)
        OrthancPluginRegisterIncomingHttpRequestFilter2(context, FilterHttpRequests);
#else
        OrthancPluginRegisterIncomingHttpRequestFilter(context, FilterHttpRequestsFallback);
#endif
      }
      else
      {
        LOG(WARNING) << "No section \"" << SECTION << "\" in the configuration file, "
                     << "the authorization plugin is disabled";
      }
    }
    catch (Orthanc::OrthancException& e)
    {
      LOG(ERROR) << e.What();
      return -1;
    }
    
    return 0;
  }


  ORTHANC_PLUGINS_API void OrthancPluginFinalize()
  {
    authorizationParser_.reset(NULL);
  }


  ORTHANC_PLUGINS_API const char* OrthancPluginGetName()
  {
    return "authorization";
  }


  ORTHANC_PLUGINS_API const char* OrthancPluginGetVersion()
  {
    return ORTHANC_PLUGIN_VERSION;
  }
}
