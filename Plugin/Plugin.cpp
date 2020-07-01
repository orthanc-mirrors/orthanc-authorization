/**
 * Advanced authorization plugin for Orthanc
 * Copyright (C) 2017-2020 Osimis S.A., Belgium
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

#include <Logging.h>
#include <Toolbox.h>


// Configuration of the authorization plugin
static std::auto_ptr<OrthancPlugins::IAuthorizationParser> authorizationParser_;
static std::auto_ptr<OrthancPlugins::IAuthorizationService> authorizationService_;
static std::set<std::string> uncheckedResources_;
static std::list<std::string> uncheckedFolders_;
static std::list<OrthancPlugins::Token> tokens_;
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
      if (!authorizationParser_->Parse(accesses, uri))
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

            OrthancPlugins::AssociativeArray getArguments
              (getArgumentsCount, getArgumentsKeys, getArgumentsValues, true);

            // Loop over all the authorization tokens stored in the HTTP
            // headers, until finding one that is granted
            for (std::list<OrthancPlugins::Token>::const_iterator
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

    Orthanc::Logging::InitializePluginContext(context);
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
          tokens_.push_back(OrthancPlugins::Token(OrthancPlugins::TokenType_HttpHeader, *it));
        }

        configuration.LookupListOfStrings(tmp, "TokenGetArguments", true);

#if ORTHANC_PLUGINS_VERSION_IS_ABOVE(1, 3, 0)  
        for (std::list<std::string>::const_iterator
               it = tmp.begin(); it != tmp.end(); ++it)
        {
          tokens_.push_back(OrthancPlugins::Token(OrthancPlugins::TokenType_GetArgument, *it));
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

        if (configuration.LookupListOfStrings(tmp, "UncheckedLevels", false))
        {
          for (std::list<std::string>::const_iterator
                 it = tmp.begin(); it != tmp.end(); ++it)
          {
            uncheckedLevels_.insert(OrthancPlugins::StringToAccessLevel(*it));
          }
        }

        authorizationService_.reset
          (new OrthancPlugins::CachedAuthorizationService
           (new OrthancPlugins::AuthorizationWebService(url), factory));

        OrthancPluginRegisterOnChangeCallback(context, OnChangeCallback);
        
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
