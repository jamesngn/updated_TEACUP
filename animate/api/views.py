# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 Centre for Advanced Internet Architectures,
# Swinburne University of Technology. All rights reserved.
#
# Author: Isaac True (itrue@swin.edu.au)
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

import collections
from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.http import JsonResponse
import teaplot
from os import getcwd
def get_experiments(request):
    return JsonResponse(
                        collections.OrderedDict(sorted(teaplot.get_experiments_from_teacup().items())))

def get_metric_list(request):
    return JsonResponse({
                        'metrics': sorted([f for f in teaplot.METRIC_LIST])
                        });

def get_metrics(request):
    if request.method == 'POST' and len(request.body) > 0:
        return JsonResponse(teaplot.get_metrics_from_request(request.body));
    else:
        return HttpResponseBadRequest()


def make_graph(request):
    if request.method == 'POST' and len(request.body) > 0:
        return JsonResponse(teaplot.make_graph(request.body));
    else:
        return HttpResponseBadRequest()

def get_default_view(request):
    return JsonResponse(teaplot.load_default());

def get_paths(request):
    return HttpResponse("""
TEACUP_DIR:     %s <br/>
EXP_COMPLETED:  %s <br/>
OUT_DIR:        %s <br/>
EXP_DIR:        %s <br/>
os.getcwd():       %s <br/>
    """ % (teaplot.TEACUP_DIR, teaplot.EXP_COMPLETED, teaplot.OUT_DIR, teaplot.EXP_DIR, getcwd()));