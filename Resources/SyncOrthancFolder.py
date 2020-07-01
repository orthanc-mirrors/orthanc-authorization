#!/usr/bin/python

#
# This maintenance script updates the content of the "Orthanc" folder
# to match the latest version of the Orthanc source code.
#

import multiprocessing
import os
import stat
import urllib2

TARGET = os.path.join(os.path.dirname(__file__), 'Orthanc')
PLUGIN_SDK_VERSION = '1.3.1'
REPOSITORY = 'https://hg.orthanc-server.com/orthanc/raw-file'

FILES = [
    ('OrthancFramework/Resources/CMake/DownloadOrthancFramework.cmake', '.'),
    ('OrthancFramework/Resources/Toolchains/LinuxStandardBaseToolchain.cmake', '.'),
    ('OrthancFramework/Resources/Toolchains/MinGW-W64-Toolchain32.cmake', '.'),
    ('OrthancFramework/Resources/Toolchains/MinGW-W64-Toolchain64.cmake', '.'),
    ('OrthancFramework/Resources/Toolchains/MinGWToolchain.cmake', '.'),
    ('OrthancServer/Plugins/Samples/Common/OrthancPluginCppWrapper.cpp', 'Plugins'),
    ('OrthancServer/Plugins/Samples/Common/OrthancPluginCppWrapper.h', 'Plugins'),
    ('OrthancServer/Plugins/Samples/Common/OrthancPluginException.h', 'Plugins'),
]

SDK = [
    'orthanc/OrthancCPlugin.h',
]


def Download(x):
    branch = x[0]
    source = x[1]
    target = os.path.join(TARGET, x[2])
    print target

    try:
        os.makedirs(os.path.dirname(target))
    except:
        pass

    url = '%s/%s/%s' % (REPOSITORY, branch, source)

    with open(target, 'w') as f:
        f.write(urllib2.urlopen(url).read())


commands = []

for f in FILES:
    commands.append([ 'default',
                      f[0],
                      os.path.join(f[1], os.path.basename(f[0])) ])

for f in SDK:
    commands.append([
        'Orthanc-%s' % PLUGIN_SDK_VERSION, 
        'Plugins/Include/%s' % f,
        'Sdk-%s/%s' % (PLUGIN_SDK_VERSION, f) 
    ])


pool = multiprocessing.Pool(10)  # simultaneous downloads
pool.map(Download, commands)
