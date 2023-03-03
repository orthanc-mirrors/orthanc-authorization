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
#include "PermissionParser.h"
#include "MemoryCache.h"

#include "../Resources/Orthanc/Plugins/OrthancPluginCppWrapper.h"

#include <Compatibility.h>  // For std::unique_ptr<>
#include <Logging.h>
#include <Toolbox.h>
#include <EmbeddedResources.h>


// Configuration of the authorization plugin
static std::unique_ptr<OrthancPlugins::IAuthorizationParser> authorizationParser_;
static std::unique_ptr<OrthancPlugins::IAuthorizationService> authorizationService_;
static std::unique_ptr<OrthancPlugins::PermissionParser> permissionParser_;
static std::set<std::string> uncheckedResources_;
static std::list<std::string> uncheckedFolders_;
static std::set<OrthancPlugins::Token> tokens_;
static std::set<OrthancPlugins::AccessLevel> uncheckedLevels_;


static std::string JoinStrings(const std::set<std::string>& values)
{
  std::string out;
  std::set<std::string> copy = values;    // TODO: remove after upgrading to OrthancFramework 1.11.3+
  Orthanc::Toolbox::JoinStrings(out, copy, "|");
  return out;
}

struct TokenAndValue
{
  const OrthancPlugins::Token& token;
  std::string value;

  TokenAndValue(const OrthancPlugins::Token& token, const std::string& value) :
    token(token),
    value(value)
  {
  }
};


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
    unsigned int validity;  // ignored

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

    OrthancPlugins::AssociativeArray headers(headersCount, headersKeys, headersValues, false);
    OrthancPlugins::AssociativeArray getArguments(getArgumentsCount, getArgumentsKeys, getArgumentsValues, true);

    std::vector<TokenAndValue> authTokens;  // the tokens that are set in this request

    for (std::set<OrthancPlugins::Token>::const_iterator token = tokens_.begin(); token != tokens_.end(); ++token)
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
      
      if (hasValue)
      {
        authTokens.push_back(TokenAndValue(*token, value));
      }
    }

    // check if the user permissions grants him access
    if (permissionParser_.get() != NULL &&
      authorizationService_.get() != NULL) 
      // && uncheckedLevels_.find(OrthancPlugins::AccessLevel_UserPermissions) == uncheckedLevels_.end())
    {
      std::set<std::string> requiredPermissions;
      std::string matchedPattern;
      if (permissionParser_->Parse(requiredPermissions, matchedPattern, method, uri))
      {
        if (authTokens.empty())
        {
          LOG(INFO) << "Testing whether anonymous user has any of the required permissions '" << JoinStrings(requiredPermissions) << "'";
          if (authorizationService_->HasAnonymousUserPermission(validity, requiredPermissions))
          {
            LOG(INFO) << "Testing whether anonymous user has any of the required permissions '" << JoinStrings(requiredPermissions) << "' -> granted";
            return 1;
          }
          else
          {
            LOG(INFO) << "Testing whether anonymous user has any of the required permissions '" << JoinStrings(requiredPermissions) << "' -> not granted";
          }
        }
        else
        {
          for (size_t i = 0; i < authTokens.size(); ++i)
          {
            LOG(INFO) << "Testing whether user has the required permission '" << JoinStrings(requiredPermissions) << "' based on the '" << authTokens[i].token.GetKey() << "' HTTP header required to match '" << matchedPattern << "'";
            if (authorizationService_->HasUserPermission(validity, requiredPermissions, authTokens[i].token, authTokens[i].value))
            {
              LOG(INFO) << "Testing whether user has the required permission '" << JoinStrings(requiredPermissions) << "' based on the '" << authTokens[i].token.GetKey() << "' HTTP header required to match '" << matchedPattern << "' -> granted";
              return 1;
            }
            else
            {
              LOG(INFO) << "Testing whether user has the required permission '" << JoinStrings(requiredPermissions) << "' based on the '" << authTokens[i].token.GetKey() << "' HTTP header required to match '" << matchedPattern << "' -> not granted";
            }
          }
        }
      }
    }
    if (authorizationParser_.get() != NULL &&
        authorizationService_.get() != NULL)
    {
      // Parse the resources that are accessed through this URI
      OrthancPlugins::IAuthorizationParser::AccessedResources accesses;

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
          std::string msg = std::string("Testing whether access to ") + OrthancPlugins::EnumerationToString(access->GetLevel()) + " \"" + access->GetOrthancId() + "\" is allowed with a resource token";
          LOG(INFO) << msg;

          bool granted = false;

          if (authTokens.empty())
          {
            granted = authorizationService_->IsGrantedToAnonymousUser(validity, method, *access);
          }
          else
          {
            // Loop over all the authorization tokens in the request until finding one that is granted
            for (size_t i = 0; i < authTokens.size(); ++i)
            {
              if (authorizationService_->IsGranted(validity, method, *access, authTokens[i].token, authTokens[i].value))
              {
                granted = true;
                break;
              }
            }
          }

          if (!granted)
          {
            LOG(INFO) << msg << " -> not granted";
            return 0;
          }
          else
          {
            LOG(INFO) << msg << " -> granted";
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
      return OrthancPluginErrorCode_Success;
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

void CreateToken(OrthancPluginRestOutput* output,
                 const char* /*url*/,
                 const OrthancPluginHttpRequest* request)
{
  OrthancPluginContext* context = OrthancPlugins::GetGlobalContext();

  if (request->method != OrthancPluginHttpMethod_Put)
  {
    OrthancPluginSendMethodNotAllowed(context, output, "PUT");
  }
  else
  {
    // The filtering to this route is performed by this plugin as it is done for any other route before we get here.
    // Since the route contains the tokenType, we can allow/forbid creating them based on the url

    // simply forward the request to the auth-service
    std::string tokenType;
    if (request->groupsCount == 1)
    {
      tokenType = request->groups[0];
    }
    else
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_InternalError);
    }

    // convert from Orthanc flavored API to WebService API
    Json::Value body;
    if (!OrthancPlugins::ReadJson(body, request->body, request->bodySize))
    {
      throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "A JSON payload was expected");
    }

    std::string id;
    std::vector<OrthancPlugins::IAuthorizationService::OrthancResource> resources;
    std::string expirationDateString;
    uint64_t validityDuration;

    if (body.isMember("ID"))
    {
      id = body["ID"].asString();
    }

    for (Json::ArrayIndex i = 0; i < body["Resources"].size(); ++i)
    {
      const Json::Value& jsonResource = body["Resources"][i];
      OrthancPlugins::IAuthorizationService::OrthancResource resource;

      if (jsonResource.isMember("DicomUid"))
      {
        resource.dicomUid = jsonResource["DicomUid"].asString();
      }

      if (jsonResource.isMember("OrthancId"))
      {
        resource.orthancId = jsonResource["OrthancId"].asString();
      }

      if (jsonResource.isMember("Url"))
      {
        resource.url = jsonResource["Url"].asString();
      }

      resource.level = jsonResource["Level"].asString();
      resources.push_back(resource);
    }

    if (body.isMember("ExpirationDate"))
    {
      expirationDateString = body["ExpirationDate"].asString();
    }

    if (body.isMember("ValidityDuration"))
    {
      validityDuration = body["ValidityDuration"].asUInt64();
    }

    OrthancPlugins::IAuthorizationService::CreatedToken createdToken;
    if (authorizationService_->CreateToken(createdToken,
                                           tokenType,
                                           id,
                                           resources,
                                           expirationDateString,
                                           validityDuration))
    {
      Json::Value createdJsonToken;
      createdJsonToken["Token"] = createdToken.token;
      
      if (!createdToken.url.empty())
      {
        createdJsonToken["Url"] = createdToken.url;
      }
      else
      {
        createdJsonToken["Url"] = Json::nullValue;
      }

      OrthancPlugins::AnswerJson(createdJsonToken, output);
    }
    

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
        unsigned int validity; // not used
        authorizationService_->GetUserProfile(validity, profile, *token, value);
        
        OrthancPlugins::AnswerJson(profile, output);
        break;
      }
    }

  }
}

void MergeJson(Json::Value &a, const Json::Value &b) {                                                                        
                                                                                                                  
  if (!a.isObject() || !b.isObject())
  {
    return;
  }

  Json::Value::Members members = b.getMemberNames();

  for (size_t i = 0; i < members.size(); i++)
  {
    std::string key = members[i];
    
    if (!a[key].isNull() && a[key].type() == Json::objectValue && b[key].type() == Json::objectValue)
    {
      MergeJson(a[key], b[key]);
    } 
    else
    {
      a[key] = b[key];
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
      static const char* PLUGIN_SECTION = "Authorization";

      OrthancPlugins::OrthancConfiguration orthancFullConfiguration;

      // read default configuration
      std::string defaultConfigurationFileContent;
      Orthanc::EmbeddedResources::GetFileResource(defaultConfigurationFileContent, Orthanc::EmbeddedResources::DEFAULT_CONFIGURATION);
      Json::Value pluginJsonDefaultConfiguration;
      OrthancPlugins::ReadJsonWithoutComments(pluginJsonDefaultConfiguration, defaultConfigurationFileContent);
      Json::Value pluginJsonConfiguration = pluginJsonDefaultConfiguration[PLUGIN_SECTION];

      OrthancPlugins::OrthancConfiguration pluginProvidedConfiguration;

      if (orthancFullConfiguration.IsSection(PLUGIN_SECTION))
      {
        // get the configuration provided by the user
        orthancFullConfiguration.GetSection(pluginProvidedConfiguration, PLUGIN_SECTION);

        // merge it with the default configuration.  This is a way to apply the all default values in a single step
        MergeJson(pluginJsonConfiguration, pluginProvidedConfiguration.GetJson());

        // recreate a OrthancConfiguration object from the merged configuration
        OrthancPlugins::OrthancConfiguration pluginConfiguration(pluginJsonConfiguration, PLUGIN_SECTION);

        // TODO - The size of the caches is set to 10,000 items. Maybe add a configuration option?
        OrthancPlugins::MemoryCache::Factory factory(10000);

        std::string dicomWebRoot = "/dicom-web/";
        std::string oe2Root = "/ui/";

        if (orthancFullConfiguration.IsSection("DicomWeb"))
        {
          OrthancPlugins::OrthancConfiguration dicomWeb;
          dicomWeb.GetSection(orthancFullConfiguration, "DicomWeb");
          dicomWebRoot = dicomWeb.GetStringValue("Root", "/dicom-web/");
        }

        if (orthancFullConfiguration.IsSection("OrthancExplorer2"))
        {
          OrthancPlugins::OrthancConfiguration oe2;
          oe2.GetSection(orthancFullConfiguration, "OrthancExplorer2");
          oe2Root = oe2.GetStringValue("Root", "/ui/");
        }

        std::list<std::string> tmp;

        pluginConfiguration.LookupListOfStrings(tmp, "TokenHttpHeaders", true);
        for (std::list<std::string>::const_iterator
               it = tmp.begin(); it != tmp.end(); ++it)
        {
          tokens_.insert(OrthancPlugins::Token(OrthancPlugins::TokenType_HttpHeader, *it));
        }

        pluginConfiguration.LookupListOfStrings(tmp, "TokenGetArguments", true);

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

        pluginConfiguration.LookupSetOfStrings(uncheckedResources_, "UncheckedResources", false);
        pluginConfiguration.LookupListOfStrings(uncheckedFolders_, "UncheckedFolders", false);

        std::string urlTokenValidation;
        std::string urlTokenCreationBase;
        std::string urlUserProfile;
        std::string urlRoot;

        static const char* WEB_SERVICE_ROOT = "WebServiceRootUrl";
        static const char* WEB_SERVICE_TOKEN_VALIDATION = "WebServiceTokenValidationUrl";
        static const char* WEB_SERVICE_TOKEN_CREATION_BASE = "WebServiceTokenCreationBaseUrl";
        static const char* WEB_SERVICE_USER_PROFILE = "WebServiceUserProfileUrl";
        static const char* WEB_SERVICE_TOKEN_VALIDATION_LEGACY = "WebService";
        if (pluginConfiguration.LookupStringValue(urlRoot, WEB_SERVICE_ROOT))
        {
          urlTokenValidation = Orthanc::Toolbox::JoinUri(urlRoot, "/tokens/validate");
          urlTokenCreationBase = Orthanc::Toolbox::JoinUri(urlRoot, "/tokens/");
          urlUserProfile = Orthanc::Toolbox::JoinUri(urlRoot, "/user/get-profile");
        }
        else 
        {
          pluginConfiguration.LookupStringValue(urlTokenValidation, WEB_SERVICE_TOKEN_VALIDATION);
          if (urlTokenValidation.empty())
          {
            pluginConfiguration.LookupStringValue(urlTokenValidation, WEB_SERVICE_TOKEN_VALIDATION_LEGACY);
          }

          pluginConfiguration.LookupStringValue(urlTokenCreationBase, WEB_SERVICE_TOKEN_CREATION_BASE);
          pluginConfiguration.LookupStringValue(urlUserProfile, WEB_SERVICE_USER_PROFILE);
        }

        if (!urlTokenValidation.empty())
        {
          LOG(WARNING) << "Authorization plugin: url defined for Token Validation: " << urlTokenValidation;
          authorizationParser_.reset
            (new OrthancPlugins::DefaultAuthorizationParser(factory, dicomWebRoot));
        }
        else
        {
          LOG(WARNING) << "Authorization plugin: no url defined for Token Validation";
        }

        if (!urlUserProfile.empty())
        {
          LOG(WARNING) << "Authorization plugin: url defined for User Profile: " << urlUserProfile;
          
          static const char* PERMISSIONS = "Permissions";        
          if (!pluginConfiguration.GetJson().isMember(PERMISSIONS))
          {
            throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "Authorization plugin: Missing required \"" + std::string(PERMISSIONS) + 
              "\" option since you have defined the \"" + std::string(WEB_SERVICE_ROOT) + "\" option");
          }
          permissionParser_.reset
            (new OrthancPlugins::PermissionParser(dicomWebRoot, oe2Root));

          permissionParser_->Add(pluginConfiguration.GetJson()[PERMISSIONS]);
        }
        else
        {
          LOG(WARNING) << "Authorization plugin: no url defined for User Profile";
        }

        if (!urlTokenCreationBase.empty())
        {
          LOG(WARNING) << "Authorization plugin: base url defined for Token Creation : " << urlTokenCreationBase;
          // TODO Token Creation
        }
        else
        {
          LOG(WARNING) << "Authorization plugin: no base url defined for Token Creation";
        }

        if (authorizationParser_.get() == NULL && permissionParser_.get() == NULL)
        {
          throw Orthanc::OrthancException(Orthanc::ErrorCode_BadFileFormat, "Authorization plugin: No Token Validation or User Profile url defined");
        }

        std::set<std::string> standardConfigurations;
        if (pluginConfiguration.LookupSetOfStrings(standardConfigurations, "StandardConfigurations", false))
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
            uncheckedResources_.insert("/ui/api/configuration");
            uncheckedResources_.insert("/auth/user-profile");

            tokens_.insert(OrthancPlugins::Token(OrthancPlugins::TokenType_HttpHeader, "Authorization"));  // for basic-auth
            tokens_.insert(OrthancPlugins::Token(OrthancPlugins::TokenType_HttpHeader, "token"));          // for keycloak
          }

        }

        std::string checkedLevelString;
        if (pluginConfiguration.LookupStringValue(checkedLevelString, "CheckedLevel"))
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

        if (pluginConfiguration.LookupListOfStrings(tmp, "UncheckedLevels", false))
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

        std::unique_ptr<OrthancPlugins::AuthorizationWebService> webService(new OrthancPlugins::AuthorizationWebService(urlTokenValidation,
                                                                                                                        urlTokenCreationBase,
                                                                                                                        urlUserProfile));

        std::string webServiceIdentifier;
        if (pluginConfiguration.LookupStringValue(webServiceIdentifier, "WebServiceIdentifier"))
        {
          webService->SetIdentifier(webServiceIdentifier);
        }

        std::string webServiceUsername;
        std::string webServicePassword;
        if (pluginConfiguration.LookupStringValue(webServiceUsername, "WebServiceUsername") && pluginConfiguration.LookupStringValue(webServicePassword, "WebServicePassword"))
        {
          webService->SetCredentials(webServiceUsername, webServicePassword);
        }

        authorizationService_.reset
          (new OrthancPlugins::CachedAuthorizationService
           (webService.release(), factory));

        if (!urlTokenValidation.empty())
        {
          OrthancPluginRegisterOnChangeCallback(context, OnChangeCallback);
        }
        
        if (!urlUserProfile.empty())
        {
          OrthancPlugins::RegisterRestCallback<GetUserProfile>("/auth/user/profile", true);
        }

        if (!urlTokenCreationBase.empty())
        {
          OrthancPlugins::RegisterRestCallback<CreateToken>("/auth/tokens/(.*)", true);
        }
        
#if ORTHANC_PLUGINS_VERSION_IS_ABOVE(1, 2, 1)
        OrthancPluginRegisterIncomingHttpRequestFilter2(context, FilterHttpRequests);
#else
        OrthancPluginRegisterIncomingHttpRequestFilter(context, FilterHttpRequestsFallback);
#endif
      }
      else
      {
        LOG(WARNING) << "No section \"" << PLUGIN_SECTION << "\" in the configuration file, "
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
