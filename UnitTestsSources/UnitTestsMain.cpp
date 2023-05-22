/**
 * Orthanc - A Lightweight, RESTful DICOM Store
 * Copyright (C) 2012-2016 Sebastien Jodogne, Medical Physics
 * Department, University Hospital of Liege, Belgium
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


#include <gtest/gtest.h>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include "../Plugin/DefaultAuthorizationParser.h"
#include "../Plugin/AssociativeArray.h"
#include "../Plugin/AccessedResource.h"
#include "../Plugin/MemoryCache.h"
#include "../Plugin/PermissionParser.h"
#include "../Plugin/ResourceHierarchyCache.h"

using namespace OrthancPlugins;

std::string instanceOrthancId = "44444444-44444444-44444444-44444444-44444444";
std::string seriesOrthancId   = "33333333-33333333-33333333-33333333-33333333";
std::string studyOrthancId    = "22222222-22222222-22222222-22222222-22222222";
std::string patientOrthancId  = "11111111-11111111-11111111-11111111-11111111";

std::string instanceDicomUid = "4.4";
std::string seriesDicomUid   = "3.3";
std::string studyDicomUid    = "2.2";
std::string patientDicomUid  = "PATIENT.1";

bool IsAccessing(const IAuthorizationParser::AccessedResources& accesses, AccessLevel level, const std::string& orthancId)
{
  for (IAuthorizationParser::AccessedResources::const_iterator it = accesses.begin(); it != accesses.end(); ++it)
  {
    if (it->GetLevel() == level && it->GetOrthancId() == orthancId)
    {
      return true;
    }
  }
  return false;
}

namespace OrthancPlugins
{
  // The namespace is necessary for friend classes to work
  // http://code.google.com/p/googletest/wiki/AdvancedGuide#Private_Class_Members

TEST(DefaultAuthorizationParser, Parse)
{
  MemoryCache::Factory factory(10);
  DefaultAuthorizationParser parser(factory, "/dicom-web/");
  ResourceHierarchyCache* cache = parser.GetResourceHierarchy();

  cache->AddOrthancDicomMapping(Orthanc::ResourceType_Instance, instanceOrthancId, instanceDicomUid);
  cache->AddOrthancDicomMapping(Orthanc::ResourceType_Series, seriesOrthancId, seriesDicomUid);
  cache->AddOrthancDicomMapping(Orthanc::ResourceType_Study, studyOrthancId, studyDicomUid);
  cache->AddOrthancDicomMapping(Orthanc::ResourceType_Patient, patientOrthancId, patientDicomUid);

  cache->AddParentLink(Orthanc::ResourceType_Instance, instanceOrthancId, seriesOrthancId);
  cache->AddParentLink(Orthanc::ResourceType_Series, seriesOrthancId, studyOrthancId);
  cache->AddParentLink(Orthanc::ResourceType_Study, studyOrthancId, patientOrthancId);

  IAuthorizationParser::AccessedResources accesses;
  AssociativeArray noGetArguments(0, NULL, NULL, false);

  accesses.clear();
  parser.Parse(accesses, "/studies/22222222-22222222-22222222-22222222-22222222/", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/studies/22222222-22222222-22222222-22222222-22222222/instances", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/studies/22222222-22222222-22222222-22222222-22222222/archive", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/osimis-viewer/studies/22222222-22222222-22222222-22222222-22222222/archive", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/series/33333333-33333333-33333333-33333333-33333333/", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/series/33333333-33333333-33333333-33333333-33333333/media", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/series/33333333-33333333-33333333-33333333-33333333/modify", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/web-viewer/series/33333333-33333333-33333333-33333333-33333333", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/osimis-viewer/series/33333333-33333333-33333333-33333333-33333333", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/instances/44444444-44444444-44444444-44444444-44444444/file", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Instance, instanceOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/instances/44444444-44444444-44444444-44444444-44444444/preview", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Instance, instanceOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/web-viewer/instances/jpeg95-44444444-44444444-44444444-44444444-44444444_0", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Instance, instanceOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/osimis-viewer/images/44444444-44444444-44444444-44444444-44444444/0/high-quality", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Instance, instanceOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/system", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_System, "/system"));


  ///////////////////////// dicom-web
  accesses.clear();
  parser.Parse(accesses, "/dicom-web/studies/2.2", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/dicom-web/studies/2.2/series/3.3", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/dicom-web/studies/2.2/series/3.3/rendered", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/dicom-web/studies/2.2/series/3.3/metadata", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/dicom-web/studies/2.2/series/3.3/instances/4.4", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Instance, instanceOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/dicom-web/studies/2.2/series/3.3/instances/4.4/metadata", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Instance, instanceOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/dicom-web/studies/2.2/series/3.3/instances/4.4/frames/0", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Instance, instanceOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/dicom-web/studies/2.2/series/3.3/instances/4.4/frames/0/rendered", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Instance, instanceOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  accesses.clear();
  parser.Parse(accesses, "/dicom-web/studies/2.2/series/3.3/instances/4.4/bulk/7fe00010", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Instance, instanceOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));

  {
    accesses.clear();
    const char* getKeys[] = {"0020000D"};
    const char* getValues[] = {"2.2"};
    AssociativeArray getArguments(1, getKeys, getValues, false);
    parser.Parse(accesses, "/dicom-web/studies", getArguments.GetMap());
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));
  }
  {
    accesses.clear();
    const char* getKeys[] = {"0020000D", "0020000E"};
    const char* getValues[] = {"2.2", "3.3"};
    AssociativeArray getArguments(2, getKeys, getValues, false);
    parser.Parse(accesses, "/dicom-web/series", getArguments.GetMap());
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));
  }
  {
    accesses.clear();
    const char* getKeys[] = {"0020000D", "00080018", "0020000E"};
    const char* getValues[] = {"2.2", "4.4", "3.3", };
    AssociativeArray getArguments(3, getKeys, getValues, false);
    parser.Parse(accesses, "/dicom-web/studies", getArguments.GetMap());
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Instance, instanceOrthancId));
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));
  }
  {
    accesses.clear();
    const char* getKeys[] = {"StudyInstanceUID", "SOPInstanceUID", "SeriesInstanceUID"};
    const char* getValues[] = {"2.2", "4.4", "3.3", };
    AssociativeArray getArguments(3, getKeys, getValues, false);
    parser.Parse(accesses, "/dicom-web/studies", getArguments.GetMap());
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Instance, instanceOrthancId));
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Series, seriesOrthancId));
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Study, studyOrthancId));
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));
  }
  {
    accesses.clear();
    const char* getKeys[] = {"00100010"};
    const char* getValues[] = {"PATIENT.1"};
    AssociativeArray getArguments(1, getKeys, getValues, false);
    parser.Parse(accesses, "/dicom-web/studies", getArguments.GetMap());
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_Patient, patientOrthancId));
  }

  { // qido with no arguments = search all => system resource
    accesses.clear();
    parser.Parse(accesses, "/dicom-web/studies", noGetArguments.GetMap());
    ASSERT_TRUE(IsAccessing(accesses, AccessLevel_System, "/dicom-web/studies"));
  }

  accesses.clear();
  parser.Parse(accesses, "/dicom-web/servers", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_System, "/dicom-web/servers"));

  accesses.clear();
  parser.Parse(accesses, "/dicom-web/info", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_System, "/dicom-web/info"));

  accesses.clear();
  parser.Parse(accesses, "/dicom-web/servers/test/qido", noGetArguments.GetMap());
  ASSERT_TRUE(IsAccessing(accesses, AccessLevel_System, "/dicom-web/servers/test/qido"));

}
}

int main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
