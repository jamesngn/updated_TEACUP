/*jshint multistr: true */
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
 *
 * Example usage:
 *
 * <script type="text/javascript">
 *    var space = new THREE.GraphSpace('threejs');
 *    space.init();
 *    var mainGraph = new THREE.Graph(v(0,0,0), space);
 * </script>
 *
 */
/* Exported symbols */
var Plot;
var DataSeries;
var Graph;
var GraphSpace;
/**
 * Shorthand for creating a THREE.Vector3
 *
 * @param x
 * @param y
 * @param z
 * @returns {THREE.Vector3}
 */
function v(x, y, z) {
    "use strict";
    return new THREE.Vector3(x, y, z);
}

/* makeTextSprite and roundRect obtained from:
 * http://stemkoski.github.io/Three.js/Sprite-Text-Labels.html */

function makeTextSprite(message, parameters) {
    if (parameters === undefined)
        parameters = {};

    var fontface = parameters.hasOwnProperty("fontface") ?
            parameters.fontface : "Arial";

    var fontsize = parameters.hasOwnProperty("fontsize") ?
            parameters.fontsize : 18;

    var borderThickness = parameters.hasOwnProperty("borderThickness") ?
            parameters.borderThickness : 4;

    var borderColor = parameters.hasOwnProperty("borderColor") ?
            parameters.borderColor : {r: 0, g: 0, b: 0, a: 1.0};

    var backgroundColor = parameters.hasOwnProperty("backgroundColor") ?
            parameters.backgroundColor : {r: 255, g: 255, b: 255, a: 1.0};


    var canvas = document.createElement('canvas');
    var context = canvas.getContext('2d');
    context.font = "normal " + fontsize + "px " + fontface;

    // get size data (height depends only on font size)
    var metrics = context.measureText(message);
    var textWidth = metrics.width;
//    console.log("Message: " + message + " - " + " Width: " + textWidth); //TODO: Fix width - title/y-axis clipped off

    // background color
    context.fillStyle = "rgba(" + backgroundColor.r + "," + backgroundColor.g +
            "," + backgroundColor.b + "," + backgroundColor.a + ")";
    // border color
    context.strokeStyle = "rgba(" + borderColor.r + "," + borderColor.g + "," +
            borderColor.b + "," + borderColor.a + ")";

    context.lineWidth = borderThickness;
    roundRect(context, borderThickness / 2, borderThickness / 2, textWidth + borderThickness, fontsize * 1.4 + borderThickness, 6);
    // 1.4 is extra height factor for text below baseline: g,j,p,q.

    // text color
    context.fillStyle = "rgba(0, 0, 0, 1.0)";

    context.fillText(message, borderThickness, fontsize + borderThickness);

    // canvas contents will be used for a texture
    var texture = new THREE.Texture(canvas);
    texture.needsUpdate = true;
    texture.minFilter = THREE.LinearFilter;

    var spriteMaterial = new THREE.SpriteMaterial(
            {map: texture, useScreenCoordinates: false});
    var sprite = new THREE.Sprite(spriteMaterial);
    sprite.scale.set(100, 50, 1.0);
    return sprite;
}

// function for drawing rounded rectangles
function roundRect(ctx, x, y, w, h, r)
{
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
}

(function () {
    "use strict";
    /* Default shaders */
    var vertexShader = '\
uniform vec3 axes;\
uniform float upTo;\
uniform float xMax;\
uniform float xMin;\
uniform float yMax;\
uniform float yMin;\
uniform float zMax;\
uniform float zMin;\
\
attribute vec3 val;\
\
void main() { \
        vec3 min = vec3(xMin, yMin, zMin);\
        vec3 max = vec3(xMax, yMax, zMax);\
        vec3 realVal = vec3((val - min) * (axes) / (max - min));\
        if (realVal[0] <= upTo && \
                all(lessThanEqual(realVal, axes + 1.0)) &&\
                all(greaterThanEqual(realVal, vec3(0.,0.,0.)))) {\
                gl_Position = projectionMatrix * modelViewMatrix * vec4(realVal + position, 1.0 );\
        } else {\
                gl_Position = vec4(0.,0.,0.,0.);\
        }\
}\
';

    var fragShader = '\
uniform float upTo;\
\
uniform vec3 col;\
\
void main() {\
  	gl_FragColor = vec4(col, 1.);\
}\
';

    Plot = function (series, offset) {
        if (!(series instanceof DataSeries)) {
            throw 'Invalid data';
        }
        this.series = series;
        this.offset = offset;
        this.timeSeries = undefined;
        this.geometry = undefined;
        this.material = undefined;
        this.mesh = undefined;
        //this.baseGeometry = new THREE.SphereGeometry(2, 3, 3);
        this.baseGeometry = new THREE.TetrahedronGeometry(2);
    };

    Plot.prototype = {
        constructor: Plot,
        /**
         * drawPoint
         *
         * @param point
         * @param transparent
         */
        drawPoint: function (material, point, transparent) {
            var x = point[0] * this.series.xScale || 1.0;
            var y = point[1] * this.series.yScale || 1.0;
            var z = point.length === 3 ? point[2] * (this.series.zScale || 1.0) : 0.0;

            /*
             * Clone base geometry instead of re-creating it each time (high
             * performance boost)
             */
            var newGeo = this.baseGeometry.clone();
            /*
             * Store the coordinates as an attribute in each vertex of the geometry
             * for positioning in the shader program
             */
            for (var i = 0; i < newGeo.vertices.length; i++) {
                material.attributes.val.value.push(v(x, y, z));
            }
            this.geometry.merge(newGeo);
        },
        /**
         * drawPoints
         *
         * @param parent
         * @param transparent
         */
        drawPoints: function (origin, parent, transparent, axisRange) {
            this.parent = parent;
            this.points = [];
            this.timeSeries = new THREE.Object3D();
            this.geometry = new THREE.Geometry();
            this.geometry.dynamic = true;
            this.geometry.__dirtyVertices = true;
            this.material = new THREE.ShaderMaterial({
                uniforms: {
                    upTo: {
                        type: "f",
                        value: 1.0
                    },
                    col: {
                        type: "v3",
                        value: this.series.colour
                    },
                    xMax: {
                        type: "f",
                        value: 1000.0
                    },
                    xMin: {
                        type: "f",
                        value: 0.0
                    },
                    yMax: {
                        type: "f",
                        value: 1000.0
                    },
                    yMin: {
                        type: "f",
                        value: 0.0
                    },
                    zMax: {
                        type: "f",
                        value: 1000.0
                    },
                    zMin: {
                        type: "f",
                        value: 0.0
                    },
                    axes: {
                        type: "v3",
                        value: v(axisRange.x.max, axisRange.y.max, axisRange.z.max)
                    }
                },
                attributes: {
                    val: {
                        type: 'v3',
                        value: []
                    }
                },
                fragmentShader: fragShader,
                vertexShader: vertexShader
            });
            for (var i in this.series.data) {
                var point = this.series.data[i];
                this.drawPoint(this.material, point, transparent);
            }
            this.mesh = new THREE.Mesh(this.geometry, this.material);
            this.material.uniforms.upTo.value = axisRange.x.max;
            this.material.uniforms.upTo.needsUpdate = true;
            this.material.attributes.val.needsUpdate = true;
            this.timeSeries.parent = parent;
            this.timeSeries.add(this.mesh);
            this.timeSeries.frustumCulled = false;
            this.mesh.frustumCulled = false;
            this.timeSeries.position.copy(origin);
            this.parent.add(this.timeSeries);
            this.series.data = [];
        },
        setLimits: function (newLimits) {
            this.material.uniforms.xMax.value = newLimits.x.max;
            this.material.uniforms.xMin.value = newLimits.x.min;
            this.material.uniforms.yMax.value = newLimits.y.max;
            this.material.uniforms.yMin.value = newLimits.y.min;
            this.material.uniforms.zMax.value = newLimits.z.max;
            this.material.uniforms.zMin.value = newLimits.z.min;

            this.material.uniforms.xMax.needsUpdate = true;
            this.material.uniforms.xMin.needsUpdate = true;
            this.material.uniforms.yMax.needsUpdate = true;
            this.material.uniforms.yMin.needsUpdate = true;
            this.material.uniforms.zMax.needsUpdate = true;
            this.material.uniforms.zMin.needsUpdate = true;
        },
        /**
         * cleanUp
         */
        cleanUp: function () {
            if (this.timeSeries !== undefined) {
                this.parent.remove(this.timeSeries);
            }
        },
        /**
         * makePointsVisible
         *
         * @param upTo
         */
        makePointsVisible: function (upTo) {
            this.material.uniforms.upTo.value = upTo;
            this.material.uniforms.upTo.needsUpdate = true;
        }
    };

    /**
     * Dataseries object
     *
     *
     */
    DataSeries = function () {
        this.data = [];
        this.colour = new THREE.Vector3(0.0, 0.0, 0.0);
        this.yScale = 1.0;
        this.xScale = 1.0;
        this.zScale = 1.0;
        this.thickness = 1;
        this.lines = false;
        this.constrainAxis = true;
    };

    DataSeries.prototype = {
        constructor: DataSeries,
    };

    var CHART_MODE = {
        '2D': 0,
        'Density': 1
    };

    /**
     * Graph object.
     *
     * @param origin
     *            THREE.Vector3 representing graph origin in space
     * @param space
     *            GraphSpace container object
     */
    Graph = function (origin, space) {
        this.space = space;
        space.addGraph(this);
        this.origin = origin;
        this.plots = [];
        this.isAnimating = false;
        this.graphName = '';
        this.mode = CHART_MODE.TIME;
        this.axisLabels = {};
        this.limits = {
            x: {
                min: 0,
                max: 1000
            },
            y: {
                min: 0,
                max: 500
            },
            z: {
                min: 0,
                max: 500
            }
        };
        this.zoomLimits = {};
        $.extend(true, this.zoomLimits, this.limits);
        this.axisLabelRange = {
            x: {
                min: 0,
                max: 0
            },
            y: {
                min: 0,
                max: 0
            },
            z: {
                min: 0,
                max: 0
            }
        };
        this.axisSections = {
            x: 8,
            y: 8,
            z: 8
        };
        this.showGrid = true;
        this.gridOpacity = 0.10;
        this.gridThickness = 0.1;
        this.gridSections = {
            x: 4,
            y: 4,
            z: 4
        };
        this.axisColors = {
/*            x: 0xFF0000,
            y: 0x00FF00,
            z: 0x0000FF*/
            x: 0x000000,
            y: 0x000000,
            z: 0x000000
        };
        this.init();
    };

    Graph.prototype = {
        toString: function () {
            return this.graphName;
        },
        constructor: Graph,
        /**
         * init function to be called whenever axes are changed
         */
        init: function () {
            if (this.axes !== undefined) {
                this.space.scene.remove(this.axes);
            }
            // this.axes = this.createAxes();
            this.axes = this.buildAxes();
            this.space.scene.add(this.axes);
            this.updateAxisLabels();

            if (this.axisLabels.z !== undefined)
                this.axisLabels.z.visible = this.space.perspective;

            this.setName(this.graphName);
        },
        updateAxisLabels: function (labelRange) {
            if (this.axesLabels !== undefined) {
                this.space.spriteScene.remove(this.axesLabels);
            }
            this.axesLabels = this.createAxesLabels(labelRange || this.axisLabelRange);
            this.space.spriteScene.add(this.axesLabels);
        },
        /**
         * calculateRelativePosition
         *
         * @returns {___anonymous3810_4149}
         */
        calculateRelativePosition: function () {
            return {
                x: {
                    min: this.limits.x.min + this.origin.x,
                    max: this.limits.x.max + this.origin.x
                },
                y: {
                    min: this.limits.y.min + this.origin.y,
                    max: this.limits.y.max + this.origin.y
                },
                z: {
                    min: this.limits.z.min + this.origin.z,
                    max: this.limits.z.max + this.origin.z
                }
            };
        },
        /**
         * drawAxisMarkers
         *
         * @param axes
         * @param max
         * @param min
         * @param sections
         * @param origin
         * @param size
         * @param axis
         */
        drawAxisMarkers: function (axes, max, min, sections, origin, size, axis, limits) {
            var doDraw = function (graph, from, to, increment, min, max) {
                var range = max - min;
                for (var i = from; i <= to; i += increment) {
                    var label = graph.createText2D(Math.round(i / to * range + min), size);
                    switch (axis) {
                        case 'x':
                            label.position.x = origin.x + i + size;
//                            label.position.y = origin.y + size / 8;
                            label.position.y = origin.y - size;
                            label.position.z = origin.z;
                            break;
                        case 'y':
                            label.position.x = origin.x - size / 2;
//                            label.position.y = origin.y + i;
                            label.position.y = origin.y + i - size / 4;
                            label.position.z = origin.z + size / 2;
                            break;
                        case 'z':
                            label.position.x = origin.x;
                            label.position.y = origin.y + size / 8;
                            label.position.z = origin.z + i;
                            break;
                        default:
                            return;
                    }
                    axes.add(label);
                }
            };
            if (max > 0 && sections > 0) {
                doDraw(this, 0, limits.max, limits.max / sections, min, max);
            }

            /* negative axis */
            /*if (min < 0 && sections > 0) {
             doDraw(this, limits.min, 0, -limits.min / sections, min / limits.min);
             }*/
        },
        /**
         * setName
         *
         * @param name
         */
        setName: function (name) {
            this.graphName = name;
            if (this.graphNameSprite !== undefined) {
                this.axesLabels.remove(this.graphNameSprite);
            }
            if (name !== undefined && name.length > 0) {
                var size = 70;
                var title = this.createText2D(this.graphName, size);
                title.position.x = this.origin.x + (this.limits.x.max - this.limits.x.min) / 2;
                title.position.y = this.origin.y + this.limits.y.max + size / 4;
                title.position.z = this.origin.z;
                this.graphNameSprite = title;
                this.axesLabels.add(title);
            }
        },
        /**
         * createAxesLabels
         *
         * @returns {THREE.Object3D}
         */
        createAxesLabels: function (labelRange) {
            var labels = new THREE.Object3D();
            var c = this;

            var size = 45;

            var makeTitle = function (label, position) {
                var title = c.createText2D(label, size);
                title.position.x = position.x;
                title.position.y = position.y;
                title.position.z = position.z;
                labels.add(title);
            };

            if (this.limits.z.max > 0)
                makeTitle("Z", v(this.origin.x + size, this.origin.y - size / 4, this.origin.z + this.limits.z.max + size / 2));
            if (this.limits.y.max > 0)
                makeTitle("Y", v(this.origin.x + size, this.origin.y + this.limits.y.max, this.origin.z));
            if (this.limits.x.max > 0)
                makeTitle("X", v(this.origin.x + this.limits.x.max + size * 1.5, this.origin.y - size / 4, this.origin.z));

            this.drawAxisMarkers(labels, labelRange.x.max, labelRange.x.min, this.axisSections.x, this.origin, size, 'x',
                    this.limits.x);
            this.drawAxisMarkers(labels, labelRange.y.max, labelRange.y.min, this.axisSections.y, this.origin, size, 'y',
                    this.limits.y);
            if (this.space.perspective)
                this.drawAxisMarkers(labels, labelRange.z.max, labelRange.z.min, this.axisSections.z, this.origin, size,
                        'z', this.limits.z);

            return labels;
        },
        /**
         * buildAxes
         *
         * @returns {THREE.Object3D}
         */
        buildAxes: function () {
            var axes = new THREE.Object3D();
            var limits = this.calculateRelativePosition();
            var c = this;

            /* +X */
            axes.add(this.buildAxis(v(this.origin.x, this.origin.y, this.origin.z), v(limits.x.max, this.origin.y,
                    this.origin.z), this.axisColors.x, false, 3, 1.0, 'x'));

            /* -X */
            /*axes.add(this.buildAxis(v(this.origin.x, this.origin.y, this.origin.z), v(limits.x.min, this.origin.y,
             this.origin.z), this.axisColors.x, true, 3, 1.0, '-x'));*/
            /* +Y */
            axes.add(this.buildAxis(v(this.origin.x, this.origin.y, this.origin.z), v(this.origin.x, limits.y.max,
                    this.origin.z), this.axisColors.y, false, 3, 1.0, 'y'));

            /* -Y */
            /*axes.add(this.buildAxis(v(this.origin.x, this.origin.y, this.origin.z), v(this.origin.x, limits.y.min,
             this.origin.z), this.axisColors.y, true, 3, 1.0, '-y'));*/

            if (this.space.perspective) {
                /* +Z */
                axes.add(this.buildAxis(v(this.origin.x, this.origin.y, this.origin.z), v(this.origin.x, this.origin.y,
                        limits.z.max), this.axisColors.z, false, 3, 1.0, 'z'));

                /* -Z */
                /*axes.add(this.buildAxis(v(this.origin.x, this.origin.y, this.origin.z), v(this.origin.x, this.origin.y,
                 limits.z.min), this.axisColors.z, true, 3, 1.0));*/
            }

            if (this.showGrid) {
                this.addGridToAxes(limits, axes);
            }
            return axes;
        },
        /**
         * addGridToAxes
         *
         * TODO Fix math
         *
         * @param limits
         * @param axes
         */
        addGridToAxes: function (limits, axes) {
            var totalLength = {
                x: this.limits.x.max - this.limits.x.min,
                y: this.limits.y.max - this.limits.y.min,
                z: this.limits.z.max - this.limits.z.min,
            };

            var c = this;

            var buildGrid = function (start, end) {
                return c.buildAxis(start, end, 0x00000, false, c.gridThickness, c.gridOpacity);
            };
            var i, j;
            if (this.gridSections.z > 0) {
                for (i = 0; i <= totalLength.z; i += totalLength.z / this.gridSections.z) {
                    for (j = 0; j <= totalLength.y; j += totalLength.y / this.gridSections.y) {
                        axes.add(buildGrid(v(limits.x.min, limits.y.min + i, limits.z.min + j), v(limits.x.max,
                                limits.y.min + i, limits.z.min + j)));
                    }
                    for (j = 0; j <= totalLength.x; j += totalLength.x / this.gridSections.x) {
                        axes.add(buildGrid(v(limits.x.min + j, limits.y.min, limits.z.min + i), v(limits.x.min + j,
                                limits.y.max, limits.z.min + i)));
                    }
                }
            }

            if (this.gridSections.y > 0) {
                for (i = 0; i <= totalLength.y; i += totalLength.y / this.gridSections.y) {
                    for (j = 0; j <= totalLength.z; j += totalLength.z / this.gridSections.z) {
                        axes.add(buildGrid(v(limits.x.min, limits.y.min + j, limits.z.min + i), v(limits.x.max,
                                limits.y.min + j, limits.z.min + i)));
                    }
                    for (j = 0; j <= totalLength.x; j += totalLength.x / this.gridSections.x) {
                        axes.add(buildGrid(v(limits.x.min + j, limits.y.min + i, limits.z.min), v(limits.x.min + j,
                                limits.y.min + i, limits.z.max)));
                    }
                }
            }
            if (this.gridSections.x > 0) {
                for (i = 0; i <= totalLength.x; i += totalLength.x / this.gridSections.x) {
                    for (j = 0; j <= totalLength.y; j += totalLength.y / this.gridSections.y) {
                        axes.add(buildGrid(v(limits.x.min + i, limits.y.min, limits.z.min + j), v(limits.x.min + i,
                                limits.y.max, limits.z.min + j)));
                    }
                    for (j = 0; j <= totalLength.z; j += totalLength.z / this.gridSections.z) {
                        axes.add(buildGrid(v(limits.x.min + i, limits.y.min + j, limits.z.min), v(limits.x.min + i,
                                limits.y.min + j, limits.z.max)));
                    }
                }
            }
        },
        /**
         * buildAxis
         *
         * @param src
         * @param dst
         * @param colorHex
         * @param dashed
         * @param thickness
         * @param opacity
         * @returns {THREE.Line}
         */
        buildAxis: function (src, dst, colorHex, dashed, thickness, opacity, name) {
            var geometry = new THREE.Geometry(), material;

            if (dashed) {
                material = new THREE.LineDashedMaterial({
                    linewidth: thickness,
                    color: colorHex,
                    dashSize: 3,
                    gapSize: 3,
                    transparent: true,
                    opacity: opacity
                });
            } else {
                material = new THREE.LineBasicMaterial({
                    linewidth: thickness,
                    color: colorHex,
                    transparent: true,
                    opacity: opacity
                });
            }
            geometry.dynamic = true;
            geometry.vertices.push(src.clone());
            geometry.vertices.push(dst.clone());
            geometry.computeLineDistances(); // This one is SUPER important,
            // otherwise dashed lines will appear as
            // simple plain lines

            var axis = new THREE.Line(geometry, material, THREE.LinePieces);
            axis.axis = name;
            return axis;
        },
        setShowGrid: function (showGrid) {
            this.showGrid = showGrid;
            this.init();
        },
        /**
         * createText2D
         *
         * TODO fix rendering
         *
         * @param text
         * @param color
         * @param font
         * @param size
         * @returns {THREE.Sprite}
         */
        createText2D: function (text, size) {
            return makeTextSprite(text, {fontsize: size,
                borderColor: {r: 0, g: 0, b: 0, a: 0.0},
                backgroundColor: {r: 0, g: 0, b: 0, a: 0.0}});
        },
        /**
         * makeHeader
         *
         * @returns {THREE.Object3D}
         */
        makeHeader: function () {
            var header = new THREE.Object3D();
            header.position.set(this.origin.x, this.origin.y + (this.limits.y.max + this.limits.y.min) / 2, this.origin.z +
                    (this.limits.z.max + this.limits.z.min) / 2);

            var geometry = new THREE.BoxGeometry((this.limits.z.max - this.limits.z.min),
                    (this.limits.y.max - this.limits.y.min), 5);
            var material = new THREE.MeshBasicMaterial({
                color: 0xFF0000,
                transparent: true,
                side: THREE.DoubleSide,
                opacity: 0.3
            });
            var plane = new THREE.Mesh(geometry, material);
            header.add(plane);
            header.rotation.y = Math.PI / 2;

            return header;
        },
        /**
         * animate
         *
         * @param scaledPeriod
         * @param scaledDuration
         * @param period
         * @param cleanup
         * @param operation
         * @param position
         */
          animate: function (startPosition, endPosition, cleanup, operation, elapsedTime, lastTime, duration) {
            var currentTime = new Date().getTime();
            var deltaTime = currentTime - lastTime;
            var progress = elapsedTime / duration;
            var newPosition = (endPosition - startPosition) * progress + startPosition;
            operation(newPosition, elapsedTime);
            if (newPosition < endPosition) {
                var graph = this;
                if (graph.isAnimating) {
                    requestAnimationFrame(function () {
                        graph.animate(startPosition, endPosition, cleanup, operation, elapsedTime + deltaTime, currentTime, duration);
                    });
                }
            } else {
                cleanup();
            }
        },
        /**
         * animateGraph
         *
         * @param time
         * @param period
         */
        animateGraph: function (duration) {
            if (!this.isAnimating) {
                this.isAnimating = true;
                var axes = this.axes;
                if (this.header === undefined) {
                    this.header = this.makeHeader();
                    axes.add(this.header);
                    this.header.elapsedTime = 0.0;
                }
                var graph = this;
                var xStart = this.origin.x;
                var xEnd = this.limits.x.min + this.limits.x.max + this.origin.x;
                this.animate(xStart, xEnd, function () {
                    /*  cleanup */
                    graph.isAnimating = false;
                    if (graph.header !== undefined) {
                        axes.remove(graph.header);
                        graph.header = undefined;
                    }
                }, function (position, elapsedTime) {
                    /* animation operation */
                    graph.header.position.x = position;
                    graph.header.elapsedTime = elapsedTime;
                    for (var i in graph.plots) {
                        graph.plots[i].makePointsVisible(position - xStart);
                    }
                }, this.header.elapsedTime, new Date().getTime(), duration);
            } else {
                console.log('THREE.Graph: already animating');
            }
        },
        stopAnimating: function () {
            this.isAnimating = false;
        },
        /**
         * addPlot
         *
         * @param plot
         */
        addPlot: function (plot) {
            this.plots.push(plot);
            plot.drawPoints(this.origin, this.space.scene, true, this.limits);
            plot.setLimits(this.zoomLimits);
        },
        /**
         * deletePlots
         */
        deletePlots: function () {
            for (var i in this.plots) {
                this.plots[i].cleanUp();
            }
            this.plots = [];
            this.cleanUpAxisLabels();
        },
        /**
         * deletePlot
         *
         * @param plot
         */
        deletePlot: function (plot) {
            plot.cleanUp();
            var index = this.plots.indexOf(plot);
            if (index > -1) {
                this.plots.splice(index, 1);
            }
            this.cleanUpAxisLabels();
        },
        cleanUpAxisLabels: function () {

            if (this.plots.length === 0) {
                for (var i in this.axisLabels) {
                    this.space.spriteScene.remove(this.axisLabels[i]);
                }
            }
        },
        /**
         * destroy
         */
        destroy: function () {
            this.space.scene.remove(this.axes);
            this.space.spriteScene.remove(this.axesLabels);

            for (var i in this.plots) {
                this.plots[i].cleanUp();
            }
        },
        setLimits: function (newLimits) {
            this.limits = newLimits;
            for (var i in this.plots) {
                this.plots[i].setLimits(this.limits);
            }
        },
        zoom: function (zoom) {
            var newLimits = {};
            $.extend(true, newLimits, this.limits);
            var i;
            for (i in newLimits) {
                newLimits[i].max = zoom[i].max / 100.0 * (this.limits[i].max - this.limits[i].min);
                newLimits[i].min = -zoom[i].min / 100.0 * (this.limits[i].min - this.limits[i].max);
            }
            for (i in this.plots) {
                this.plots[i].setLimits(newLimits);
            }
            this.zoomLimits = newLimits;
        },
        zoomLabels: function (zoom) {
            var labelRange = {};
            $.extend(true, labelRange, this.axisLabelRange);
            for (var i in labelRange) {
                labelRange[i].max = zoom[i].max / 100.0 * (this.axisLabelRange[i].max - this.axisLabelRange[i].min);
                labelRange[i].min = -zoom[i].min / 100.0 * (this.axisLabelRange[i].min - this.axisLabelRange[i].max);
            }

            this.updateAxisLabels(labelRange);
        },
        setAxisLabel: function (axis, label) {
            if (axis !== 'x' && axis !== 'z' && axis !== 'y') {
                console.log('Invalid axis: ' + axis);
                return;
            } else {
                if (label === 'NOTHING') {
                    return;
                }
                if (label === 'TIME') {
                    label = 'Time';
                }
                if (this.axisLabels[axis] !== undefined) {
                    this.space.spriteScene.remove(this.axisLabels[axis]);
                }
                var size = 70;
                this.axisLabels[axis] = this.createText2D(label, size);
                var xPos = 0.0;
                var yPos = 0.0;
                var zPos = 0.0;
                switch (axis) {
                    case 'x':
                        xPos = this.origin.x + (this.limits.x.max - this.limits.x.min) / 2;
//                        yPos = this.origin.y - size / 2;
                        yPos = this.origin.y - size * 1.5;
                        zPos = this.origin.z;
                        break;
                    case 'y':
                        yPos = this.origin.y + (this.limits.y.max - this.limits.y.min) / 2 - size / 2;
//                        xPos = this.origin.x - size / 2;
                        xPos = this.origin.x - size * 1.5;
                        zPos = this.origin.z;
                        this.axisLabels[axis].material.rotation = Math.PI / 2;
                        break;
                    case 'z':
                        zPos = this.origin.z + (this.limits.z.max - this.limits.z.min) / 2;
                        xPos = this.origin.x;
                        yPos = this.origin.y - size / 2;
                        break;
                }
                /*this.axisLabels[axis].position.set(,
                 this.origin.y + (this.limits.y.min - this.limits.y.max) / 2,
                 this.origin.z + (this.limits.z.min - this.limits.z.max) / 2);*/
                this.axisLabels[axis].position.set(xPos, yPos, zPos);
                this.space.spriteScene.add(this.axisLabels[axis]);


                if (this.axisLabels.z !== undefined)
                    this.axisLabels.z.visible = this.space.perspective;
            }
        }
    };

    /**
     * GraphSpace
     *
     * Three.js rendering area for multiple graphs
     *
     * @param container
     *            DOM object which the scene will be rendered inside
     */
    GraphSpace = function (container) {
        this.container = document.getElementById(container);
        this.graphList = [];

        /*
         * Sprites must be rendered in a separate scene, otherwise they will be
         * obscure by transparent objects
         */
        this.spriteScene = new THREE.Scene();
        this.scene = new THREE.Scene();
        this.cameraStartPosition = v(0, 0, 1750);
        this.rotateSpeed = 1.0;
        this.perspectiveZoom = 1.0;
        this.zoomSpeed = 1.0;
        this.panSpeed = 1.0;
        this.perspective = false;
    };

    GraphSpace.prototype = {
        constructor: GraphSpace,
        /**
         * Must be called to initialise the renderer
         */
        init: function () {
            /* variable for anonymous wrapper functions */
            var cspace = this;

            if (!Detector.webgl) {
                Detector.addGetWebGLMessage();
            }

            // document.body.appendChild(this.container);
            // renderer
            this.renderer = new THREE.WebGLRenderer({
                antialias: true
            });
            this.container.appendChild(this.renderer.domElement);
            this.renderer.setSize(window.innerWidth, window.innerHeight);
            this.renderer.setClearColor(0xeeeeee, 1.0);
            this.renderer.autoClear = false; // Workaround for sprites over
            // transparency

            this.resetView();

            /* Add external event listeners with wrapper functions */
            window.addEventListener('resize', function () {
                graphSpaceOnWindowResize(cspace);
            }, false);

            $(document).keydown(function (e) {
                if (e.which === 82 || e.which === 114) {
                    cspace.controls.reset();
                }
            });

            /**
             * stats.js
             */

            var stats = new Stats();
            stats.setMode(0); // 0: fps, 1: ms, 2: mb

            // align top-left
            stats.domElement.style.position = 'absolute';
            stats.domElement.style.left = '0px';
            stats.domElement.style.bottom = '0px';

            document.body.appendChild(stats.domElement);

            var update = function () {

                stats.begin();

                space.controls.update();
                space.render();

                stats.end();

                requestAnimationFrame(update);

            };

            requestAnimationFrame(update);
        },
        /**
         * addGraph
         *
         * @param newGraph
         */
        addGraph: function (newGraph) {
            this.graphList.push(newGraph);
        },
        /**
         * removeGraph
         *
         * @param graph
         */
        removeGraph: function (graph) {
            var index = this.graphList.indexOf(graph);
            if (index > -1) {
                this.graphList.splice(index, 1);
            }
            graph.destroy();
        },
        /**
         * render
         */
        render: function () {
            this.renderer.clear();
            this.renderer.render(this.scene, this.camera);
            this.renderer.clearDepth();
            this.renderer.render(this.spriteScene, this.camera);
        },
        setPerspective: function (isPerspective) {
            if (isPerspective) {
                this.controls = this.perspectiveControls;
                this.camera = this.perspectiveCamera;
                this.perspectiveControls.noZoom = false;
                this.perspectiveControls.noRotate = false;
                this.perspectiveControls.noPan = false;

                /* Stop other controls from changing view */
                this.orthoControls.noZoom = true;
                this.orthoControls.noRotate = true;
                this.orthoControls.noPan = true;
            } else {
                this.controls = this.orthoControls;
                this.camera = this.orthoCamera;
                this.orthoControls.noZoom = false;
                this.orthoControls.noRotate = true;
                this.orthoControls.noPan = false;

                /* Stop other controls from changing view */
                this.perspectiveControls.noZoom = true;
                this.perspectiveControls.noRotate = true;
                this.perspectiveControls.noPan = true;
            }
            this.updateCameraParameters();
            this.camera.updateProjectionMatrix();
            this.perspective = isPerspective;

            for (var i in this.graphList) {
                this.graphList[i].init();
            }
        },
        /**
         * updateCameraParameters
         */
        updateCameraParameters: function () {
            this.controls.rotateSpeed = this.rotateSpeed;
            this.controls.zoomSpeed = this.zoomSpeed;
            this.controls.panSpeed = this.panSpeed;
            // this.camera.zoom = this.perspectiveZoom;
        },
        resetView: function () {
            /* Start ortho */

            this.orthoCamera = new THREE.OrthographicCamera(window.innerWidth / -2, window.innerWidth / 2,
                    window.innerHeight / 2, window.innerHeight / -2, 0.001, 10000);
            this.scene.add(this.orthoCamera);
            this.orthoCamera.position.set(0, 0, 500);
            this.orthoCamera.rotation.set(0, 0, 0);
            this.orthoCamera.zoom = 0.8;
            this.orthoCamera.lookAt(v(0, 0, 0));

            this.orthoControls = new THREE.OrthographicTrackballControls(this.orthoCamera, this.container);
            this.orthoControls.staticMoving = true;
            this.orthoControls.noZoom = false;
            this.orthoControls.noRotate = true;
            this.orthoControls.noPan = false;

            /* Start perspective */
            this.perspectiveCamera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 1, 10000);
            this.perspectiveCamera.position.set(this.cameraStartPosition.x, this.cameraStartPosition.y,
                    this.cameraStartPosition.z);
            this.scene.add(this.perspectiveCamera);

            this.perspectiveControls = new THREE.TrackballControls(this.perspectiveCamera, this.container);
            this.perspectiveControls.staticMoving = true;
            this.perspectiveControls.noZoom = false;
            this.perspectiveControls.noRotate = false;
            this.perspectiveControls.noPan = false;

            this.setPerspective(this.perspective);
        }
    };

    /**
     * graphSpaceOnWindowResize
     *
     * @param space
     */
    function graphSpaceOnWindowResize(space) {
        space.perspectiveCamera.aspect = window.innerWidth / window.innerHeight;
        space.perspectiveCamera.updateProjectionMatrix();
        space.orthoCamera.aspect = window.innerWidth / window.innerHeight;
        space.orthoCamera.updateProjectionMatrix();
        space.renderer.setSize(window.innerWidth, window.innerHeight);
    }
})();