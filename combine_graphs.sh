#!/bin/sh
# Copyright (c) 2013-2015 Centre for Advanced Internet Architectures,
# Swinburne University of Technology. All rights reserved.
#
# Author: Sebastian Zander (sebastian.zander@gmx.de)
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
# combine multiple pdf graphs on a single page
# requires the pdfjam package
#
# $Id: combine_graphs.sh,v e7ea179b29d8 2015/05/25 04:28:23 sebastian $

usage() {
	echo "Usage: $0 -c <combine> -o <out_file> <file1.pdf> ... <fileN.pdf>"
	echo "		-c <combine>		specify column x row layout in which to combine the graphs using pdfnup (default is 2x2)"
	echo "		-o <out_file>		output file name of the combined pdf file"
	echo "		<fileX>			the single images (pdf files>"
}

COMBINE="2x2"
OUT_FILE="combined.pdf"

while getopts "c:o:h" flag
do
#  echo $flag $OPTIND $OPTARG
   case $flag in
   c) COMBINE=$OPTARG
   ;;
   o) OUT_FILE=$OPTARG
   ;;
   h) usage ; exit 0
   ;;
   *) usage ; exit 1
   ;;
   esac
done

# strip of all arguments so we only have the file names left
I=1
while [ $I -lt $OPTIND ] ; do
	shift
	I=`expr $I + 1`
done

if [ $# -lt 1 ] ; then
	echo "Error: no file names specified"
	exit 1
fi

echo "pdfjoin -o __joined.pdf $@"
pdfjoin -o __joined.pdf $@
echo "pdfnup --nup ${COMBINE} --suffix combined __joined.pdf"
pdfnup --nup ${COMBINE} --suffix combined __joined.pdf 
mv -f __joined-combined.pdf ${OUT_FILE}
rm -f __joined.pdf 
