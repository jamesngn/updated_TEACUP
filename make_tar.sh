#!/bin/sh
# Copyright (c) 2013-2015 Centre for Advanced Internet Architectures,
# Swinburne University of Technology. All rights reserved.
#
# Author: Sebastian Zander (sebastian.zander@gmx.de)
#
# Copyright (c) 2018 Internet For Things (I4T) Research Group,
# Swinburne University of Technology. All rights reserved.
#
# Author: Grenville Armitage (garmitage@swin.edu.au)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# Task: Generate a tar file from the local mercurial repository's working
# 	directory and currently selected branch.
# Usage: make_tar.sh
# Requires: Assumes mercurial is installed locally, and that the current working
#	directory's .hg/hgrc suitably enables the keywords= extension to
#	operate on .py, .R and .sh files.
#
# $Id: make_tar.sh,v e1d110a7fd4e 2018/02/10 00:43:13 garmitage $

if [ ! -e VERSION ] ; then
	echo "Error: this script needs to be executed in the source directory"
	exit 1
fi

VERSION=`cat VERSION | head -1`
NAME=teacup-${VERSION}.tar.gz
BRANCH=`hg branch`

echo "Generating ${NAME} from ${BRANCH} branch of local repository"
rm -rf teacup-${VERSION}/

# Create a staging area containing only change-tracked files and directories
# (avoiding any other crud potentially currently sitting in this working directory)

hg clone -b ${BRANCH} . teacup-${VERSION}

# substitute Id tags INSIDE the staging area
# (Copy the local hgrc to ensure kwexpand works in the staging area's cloned repo)
cp .hg/hgrc teacup-${VERSION}/.hg/
hg kwexpand --cwd teacup-${VERSION}/ || { echo "MUST commit changes first" ; rm -rf teacup-${VERSION}/ ; exit 1 ; }

# Construct a VERSION file in staging area with latest hg revision info
echo ${VERSION} > teacup-${VERSION}/VERSION
hg log -r tip --template "changeset: {node}\ndate:      {date|rfc822date}\n" >> teacup-${VERSION}/VERSION

# Eliminate any hg-related metadata from the staging area prior to tarball construction
rm -rf teacup-${VERSION}/.hg*

# tar everything remaining in the staging area
tar -cvzf $NAME teacup-${VERSION}/

# Clean up the staging area
rm -rf teacup-${VERSION}/
