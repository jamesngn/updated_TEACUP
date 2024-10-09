/**
 * Copyright (c) 2015 Centre for Advanced Internet Architectures,
 * Swinburne University of Technology. All rights reserved.
 *
 * Author: Isaac True (itrue@swin.edu.au)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
*/

require.config({
    shim: {
        threejs: {
            exports: 'THREE'
        },
        bootstrap: {
            deps: [
                'jquery'
            ]
        },
        'threejs-trackballcontrols': {
            deps: [
                'threejs'
            ]
        },
        'threejs-orthotrackballcontrols': {
            deps: [
                'threejs'
            ]
        },
        graph: {
            deps: [
                'threejs',
                'threejs-orthotrackballcontrols',
                'threejs-trackballcontrols',
                'threejs-detector',
                'stats'
            ],
            urlArgs: "bust=" + (new Date()).getTime()
        },
        teaplot: {
            deps: [
                'graph',
                'jquery',
                'jquery-ui',
                'bootstrap',
                'beebole-pure',
            ],
            urlArgs: "bust=" + (new Date()).getTime()
        }
    },
    paths: {
        requirejs: 'require.min',
        jquery: 'jquery.min',
        'beebole-pure': 'pure.min',
        bootstrap: 'bootstrap.min',
        threejs: 'three.min',
        'threejs-trackballcontrols': 'TrackballControls.min',
        'threejs-orthotrackballcontrols': 'OrthographicTrackballControls.min',
        'threejs-detector': 'Detector.min',
        stats: 'stats.min',
        'jquery-ui': 'jquery-ui.min',
        'teaplot': 'teaplot',
        'graph': 'graph'
    },
    packages: [
    ]
});

requirejs(['jquery', 'jquery-ui', 'bootstrap', 'threejs', 'beebole-pure', 'threejs-trackballcontrols',
    'threejs-orthotrackballcontrols', 'threejs-detector', 'stats', 'graph', 'teaplot'], function () {

});
