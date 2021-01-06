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

#include "AssociativeArray.h"

#include <Toolbox.h>

namespace OrthancPlugins
{
  AssociativeArray::AssociativeArray(uint32_t headersCount,
                                     const char *const *headersKeys,
                                     const char *const *headersValues,
                                     bool caseSensitive) :
    caseSensitive_(caseSensitive)
  {
    for (uint32_t i = 0; i < headersCount; i++)
    {
      std::string value;

      if (caseSensitive)
      {
        Orthanc::Toolbox::ToLowerCase(value, headersValues[i]);
      }
      else
      {
        value = headersValues[i];
      }
        
      map_[headersKeys[i]] = value;
    }
  }

    
  bool AssociativeArray::GetValue(std::string& value,
                                  const std::string& key) const
  {
    if (key.empty())
    {
      return false;
    }

    Map::const_iterator found;

    if (caseSensitive_)
    {
      found = map_.find(key);
    }
    else
    {
      std::string lower;
      Orthanc::Toolbox::ToLowerCase(lower, key);
      found = map_.find(lower);
    }       

    if (found == map_.end())
    {
      return false;
    }
    else
    {
      value = found->second;
      return true;
    }
  }
}
