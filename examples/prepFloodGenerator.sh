#!/bin/bash

# Prepare Flood Generator Framework:
# set path to libmoon build directory (libmoonBuild)
# include Flood Generator framework to lua path

# cd to directory of script
scriptDir=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")
pushd "$scriptDir" > /dev/null

############## Libmoon ##############

# set libmoon build directory
libmoonBuild=$(realpath ../../libmoon/build) # ADJUST IF NEEDED

# sometimes libmoon requires this library (https://github.com/emmericp/MoonGen/pull/265)
export LD_LIBRARY_PATH=LD_LIBRARY_PATH:$libmoonBuild/tbb_cmake_build/tbb_cmake_build_subdir_release


############## Flood Generator Framework ##############
# include Flood Generator framework to lua path
# path to Flood Generator framework
pathFloodGenerator=$(realpath ../lua) # ADJUST IF NEEDED
# extend LUA_PATH (https://www.lua.org/pil/8.1.html)
export LUA_PATH="$pathFloodGenerator/?.lua;;"

popd > /dev/null