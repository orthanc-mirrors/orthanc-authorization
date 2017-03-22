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

#pragma once

#include <stdint.h>
#include <boost/noncopyable.hpp>
#include <map>
#include <string>

namespace OrthancPlugins
{
  class AssociativeArray : public boost::noncopyable
  {
  private:
    typedef std::map<std::string, std::string>  Map;

    Map  map_;
    bool caseSensitive_;

  public:
    AssociativeArray(uint32_t headersCount,
                     const char *const *headersKeys,
                     const char *const *headersValues,
                     bool caseSensitive);
    
    bool GetValue(std::string& value,
                  const std::string& key) const;
  };
}
