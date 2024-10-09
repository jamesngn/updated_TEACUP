/*jshint multistr: true */
/**
 * Copyright (c) 2015 Centre for Advanced Internet Architectures, Swinburne University of Technology. All rights reserved.
 * 
 * Author: Isaac True (itrue@swin.edu.au)
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Exported symbols */
var space;

(function() {
    "use strict";

    // Djuro start here
    function arraysEqual(arr1, arr2) {
        if (arr1.length !== arr2.length)
            return false;
        for (var i = arr1.length; i--;) {
            if (arr1[i] !== arr2[i])
                return false;
        }

        return true;
    }

    function exp_identifier(splitArrayExps, indexToMatch, onlyUnique) {
        if (typeof (indexToMatch === 'undefined'))
            indexToMatch = 1;
        if (typeof (onlyUnique === 'undefined'))
            onlyUnique = 1;

        var temp = [];

        for (var i = 0; i < splitArrayExps.length; i++) {
            temp.push(splitArrayExps[i][indexToMatch]);
        }

        if (onlyUnique == 1) {
            // return Array.from(new Set(temp)); //ECMAScript 6 Solution
            return temp.filter(function(value, index, self) {
                return self.indexOf(value) === index;
            });
        } else {
            return temp;
        }
    }

    function exp_index_match(splitArrayExps) {
        // splitArrayExps is an array that contains multiple arrays which has
        // experiments split by an underscore (_)
        var uniqueElementsToMatchInArray = exp_identifier(splitArrayExps)
        var tempArrayIndex = [];

        for (var i = 0; i < uniqueElementsToMatchInArray.length; i++) {
            var tempDictIndex = {};
            tempArrayIndex[i] = tempDictIndex;
            tempDictIndex[uniqueElementsToMatchInArray[i]] = [];
        }

        for (var i = 0; i < splitArrayExps.length; i++) {
            for (var j = 0; j < uniqueElementsToMatchInArray.length; j++) {
                if (splitArrayExps[i].indexOf(uniqueElementsToMatchInArray[j]) > -1) {
                    // Add the index of splitArrayExps that matched the element
                    // in uniqueElementsToMatchInArray
                    tempArrayIndex[j][uniqueElementsToMatchInArray[j]].push(i);
                }
            }
        }

        return tempArrayIndex;
    }

    function exp_rejoin(splitArrayExps, getIndexArray, indexToMatch, joinSeparator) {
        // By default (indexToMatch = 1) it will group experiments by date
        if (typeof (indexToMatch === 'undefined'))
            indexToMatch = 1;
        // By default (joinSeparator = "_") it will group all split information
        // of a single exp using the default notation of underscore "_"
        if (typeof (joinSeparator === 'undefined'))
            joinSeparator = "_";

        var temp = [];

        for (var index = getIndexArray[0]; index <= getIndexArray[getIndexArray.length - 1]; index++) {
            temp.push(splitArrayExps[index].splice(indexToMatch + 1, splitArrayExps.length).join("_"));
        }

        return temp;
    }

    function metric_index_match(splitArrayMetrics, groupArray) {
        var tempArrayIndex = [];

        for (var i = 0; i < groupArray.length; i++) {
            var tempDictIndex = {};
            tempArrayIndex[i] = tempDictIndex;
            tempDictIndex[groupArray[i]] = [];
        }

        for (var metric = 0; metric < splitArrayMetrics.length; metric++) {
            for (var match = 0; match < groupArray.length - 1; match++) {
                if (splitArrayMetrics[metric][0].indexOf(groupArray[match]) > -1) {
                    tempArrayIndex[match][groupArray[match]].push(metric);
                }
            }

            if (splitArrayMetrics[metric].length == 1) {
                tempArrayIndex[groupArray.length - 1][Object.keys(tempArrayIndex[groupArray.length - 1])].push(metric);
            }
        }

        return tempArrayIndex;
    }

    function metric_rejoin(splitArrayExps, getIndexArray) {
        var temp = [];

        for (var index = getIndexArray[0]; index <= getIndexArray[getIndexArray.length - 1]; index++) {
            // temp.push(splitArrayExps[getIndexArray[index]].splice(indexToMatch
            // + 1, splitArrayExps.length).join(" "));
            temp.push(splitArrayExps[index][splitArrayExps[index].length - 1]);
        }

        return temp;
    }
    // Djuro end here

    var colourList;

    /**
     * pure.js template directives for mapping variables to HTML tags
     */
    var directives = {
        // Djuro start here
        expsTitle : {
            '.panel' : {
                'title<-' : {
                    '.panel-title span' : function() {
                        return "exp_" + this + "_*";
                    }
                }
            }
        },
        exps : {
            '#expData' : {
                'exp<-' : {
                    'span' : 'exp'
                }
            }
        },
        metricsTitle : {
            '.panel' : {
                'title<-' : {
                    '.panel-title span' : function() {
                        return this;
                    }
                }
            }
        },
        metricsInput : {
            '#metricData' : {
                'exp<-' : {
                    'span' : 'exp'
                }
            }
        },
        metricsFlowTitle : {
            '#metricFlowIdHeading' : {
                'title <-' : {
                    '#metricHeading span' : function() {
                        return this;
                    }
                }
            }
        },
        metricsFlowSubTitle : {
            '#metricFlowSubIdHeading' : {
                'title <-' : {
                    '#metricSubHeading span' : function() {
                        return this;
                    }
                }
            }
        },
        metricFlowData : {
            '#flowData' : {
                'data <-' : {
                    'span' : function(data) {
                        return data.item.flow.split("_").slice(-4).join("_") + "&nbsp;&nbsp;&nbsp;(" + data.item.start.toFixed(2) + "&nbsp;&nbsp;&nbsp;" + data.item.duration.toFixed(2) + "&nbsp;&nbsp;&nbsp;" + data.item.size + ")";
                    }
                }
            }
        },
        // Djuro end here
        graphs : {
            'tr' : {
                'graph<-' : {
                    '.graphName@value' : 'graph.graphName',
                    '.@graph' : 'graph.id',
                    '.graphID' : 'graph.id'
                }
            }
        },
        metrics : {
            'tr' : {
                'metric<-' : {
                    '.metricTableRowName' : 'metric',
                }
            }
        },
        expids : {
            'tr' : {
                'exp<-' : {
                    '.expIdTableName' : 'exp'
                }
            }
        },
        legends : {
            'li.legendRoot' : {
                'legend<-' : {
                    '.legendFlow' : function(data) {
                        return data.item.lname === undefined || data.item.lname === '' ? data.pos : data.item.lname;
                    },
                    '.legendFlow@flow' : function(data) {
                        return data.pos;
                    },
                    '.legendColour@style' : function(data) {
                        return 'background-color: rgb(' + (Math.floor(data.item.x * 255)) + ',' + (Math.floor(data.item.y * 255)) + ',' + (Math.floor(data.item.z * 255)) + ');';
                        // return 'background-color: ' + data.item + ';';
                    }
                },
            },
        },
        flows : {
            'tr.flowRow' : {
                'flow<-' : {
                    '.flowRowName' : function(data) {
                        return data.pos;
                    },
                    'tr.flowSubRow' : {
                        'flow<-flow' : {
                            '.flowSubRowTitle' : function(data) {
                                return data.item.flow;
                            },
                            '.flowSubRowLength' : function(data) {
                                return data.item.duration.toFixed(2);
                            },
                            '.flowSubRowDataPoints' : function(data) {
                                return data.item.size;
                            },
                            '.flowSubRowStart' : function(data) {
                                return data.item.start.toFixed(2);
                            },
                        }
                    }
                }
            }
        },
        flowMaps : {
            'tr.flowMapRow' : {
                'flow<-' : {
                    '.flowMapRowMetric' : 'flow.metric',
                    '.flowMapRowFlow' : 'flow.flow',
                }
            }
        }

    };

    /**
     * Configuration object.
     * 
     * 
     */
    var config = {
        exp_id : [],
        src_filter : '',
        metrics : [],
        yscale : {
            'spprtt' : 1000.0,
            'ackseq' : 0.001,
            'throughput' : 0.001,
            'goodput' : 0.001,
            'cwnd' : 0.001,
        },
        graphs : [],
        flows : {},
        mapping : [],
        graph : {
            x : {
                min : 0.0,
                max : 100.0
            },
            y : {
                min : 0.0,
                max : 100.0
            },
            z : {
                min : 0.0,
                max : 100.0
            }
        },
        animTime : 4000,
        lnames : [],
        stime : 0,
        etime : 0,
    };

    var flows = {};

    var flowMappingRowTemplate = '\
	<tr class="flowMapRow">\
		<td><span class="flowMapRowMetric"></span></td>\
		<td><span class="flowMapRowFlow"></span></td>\
		<td><div class="dropup flowMapRowGraph">\
			<button class="btn btn-default dropdown-toggle" type="button"\
				data-toggle="dropdown" aria-haspopup="true"\
				aria-expanded="true">\
				1 <span class="caret"></span>\
			</button>\
			<ul class="dropdown-menu">\
			</ul></div>\
		</td>\
		<td><div class="dropup flowMapRowXAxis">\
			<button class="btn btn-default dropdown-toggle pull-left" type="button"\
				data-toggle="dropdown" aria-haspopup="true"\
				aria-expanded="true"  metric="TIME" flow="" dataset="" >\
			Time <span class="caret"></span>\
			</button>\
			<ul class="dropdown-menu pull-right">\
			</ul></div>\
		</td>\
		<td><div class="dropup flowMapRowZAxis ">\
				<button class="btn btn-default dropdown-toggle" type="button"\
				data-toggle="dropdown" aria-haspopup="true"\
				aria-expanded="true" metric="NOTHING" flow="" dataset="" >\
				Nothing <span class="caret"></span>\
			</button>\
			<ul class="dropdown-menu pull-right">\
			</ul></div>\
		</td>\
	</tr>';

    // Djuro experimenting start here
    // Data Sources
    var expIdTemplate = '\
        <div class="panel-group" id="accordionExpId">\
        </div>\
    ';
    var expIdContent = '\
        <div class="panel panel-primary" id="expIdHeading">\
            <div class="panel-heading accordion-toggle collapsed" data-toggle="collapse">\
                <h4 class="panel-title" data-toggle="collapse"><span></span></h4>\
            </div>\
            <div class="panel-collapse collapse" id="expIdExperiments">\
                <div class="panel-body">\
                    <div class="row">\
                        <div class="col-lg-3 col-md-4 col-sm-6 col-xs-12" id="expData">\
                            <label class="btn btn-default btn-block btn-sm"> <input type="checkbox" autocomplete="off"> <span></span>\
                            </label>\
                        </div>\
                    </div>\
                </div>\
            </div>\
        </div>\
    ';
    // Metrics
    var metricIdTemplate = '\
        <div class="panel-group" id="accordionMetricId">\
        </div>\
    ';
    var metricIdContent = '\
        <div class="panel panel-primary" id="metricIdHeading">\
            <div class="panel-heading accordion-toggle collapsed" data-toggle="collapse">\
                <h4 class="panel-title" data-toggle="collapse"><span></span></h4>\
            </div>\
            <div class="panel-collapse collapse" id="metricIds">\
                <div class="panel-body">\
                    <div class="row">\
                        <div class="col-lg-3 col-md-4 col-sm-6 col-xs-12" id="metricData">\
                            <label class="btn btn-default btn-block btn-sm"> <input type="checkbox" autocomplete="off"> <span></span>\
                            </label>\
                        </div>\
                    </div>\
                </div>\
            </div>\
        </div>\
    ';
    // Flows
    var flowIdTemplate = '\
        <div class="panel-group" id="accordionFlowId">\
        </div>\
    ';
    var flowIdContent = '\
        <div class="panel panel-primary" id="metricFlowIdHeading">\
            <div id="metricNavTo" class="panel-heading accordion-toggle collapsed" data-toggle="collapse">\
                <h4 id="metricHeading" class="panel-title" data-toggle="collapse"><span></span></h4>\
            </div>\
            \
            <div class="panel-collapse collapse" id="metricNavFrom">\
                <div class="panel-body">\
                    \
                    <div class="panel-group" id="accordionSubFlowId">\
                        <div class="panel panel-primary" id="metricFlowSubIdHeading">\
                            <div id="metricFlowNavTo" class="panel-heading accordion-toggle collapsed" data-toggle="collapse">\
                                <h4 id="metricSubHeading" class="panel-title" data-toggle="collapse"><span></span></h4>\
                            </div>\
                            \
                            <div class="panel-collapse collapse" id="metricFlowNavFrom">\
                                <div class="panel-body">\
                                    <div class="row">\
                                        <div class="col-lg-4 col-md-4 col-sm-6 col-xs-12" id="flowData">\
                                            <label class="btn btn-default btn-block btn-sm"> <input type="checkbox" autocomplete="off"> <span></span>\
                                            </label>\
                                        </div>\
                                    </div>\
                                </div>\
                            </div>\
                        </div>\
                    </div>\
                    \
                </div>\
            </div>\
        </div>\
    ';
    // Djuro experimenting end here
    var expIdTableTemplate = '\
	<tr>							\
		<td class="expIdTableName"></td>			\
		<td class="checkBoxCell"><div class="checkbox teaplotCheckbox"><label><input type="checkbox"></label></div></td>		\
	</tr>';

    var metricTableRowTemplate = '\
<tr>							\
	<td style="vertical-align:middle;"><span class="metricTableRowName"></span></td>			\
	<td style="vertical-align:middle;"><input class="form-control yscale" type="number" pattern="\d*" min="0.0001" max="10" step="0.1" value="1.0"></td>		\
	<td class="checkBoxCell"><div class="checkbox teaplotCheckbox"><label><input type="checkbox"></label></div></td>		\
</tr>';

    var graphTemplate = '\
<tr>\
    <td><span class="graphID"></span></td>\
	<td><div class="input-group"  style="width:100%;">\
			<input type="text" class="form-control graphName"\
				placeholder="Name" aria-describedby="basic-addon1" />\
		</div></td>\
</tr>';

    var legendFlowTemplate = '\
<li class="legendRoot"> \
	<small><strong><span class="legendColour">&nbsp&nbsp&nbsp</span>&nbsp<a class="legendFlow" href="#"></a></strong></small> \
</li>';

    var flowRowTemplate = '\
<tr class="flowRow">							\
	<td><span class="flowRowName"></span></td>			\
	<td>\
		<table class="table wrappedTable">\
                        <colgroup>\
                          <col style="width:60%">\
                          <col style="width:10%">\
                          <col style="width:10%">\
                          <col style="width:10%">\
                          <col style="width:10%">\
                        </colgroup>  \
			<thead>\
				<tr>\
					<th>Name</th>\
					<th>Start time</th>\
					<th>Length (s)</th>\
					<th>Data points</th>\
					<th>Show</th>\
				</tr>\
			</thead>\
			<tbody>\
				<tr class="flowSubRow">\
			    	<td><span class="flowSubRowTitle"></span></td>\
					<td><span class="flowSubRowStart"></span></td>\
					<td><span class="flowSubRowLength"></span></td>\
					<td><span class="flowSubRowDataPoints"></span></td>\
					<td class="checkBoxCell><div class="checkbox teaplotCheckbox"><label><input type="checkbox"></label></div></td>		\
				</tr>\
			</tbody>\
		</table>\
	</td>\
</tr>';

    /**
     * centreViewOnGraph
     * 
     * @param graph
     */
    function centreViewOnGraph(graph) {
        space.perspectiveCamera.position.set((graph.limits.x.max) * 1.5, (graph.limits.y.max) * 1.5, (graph.limits.z.max) * 1.5);
    }

    /**
     * showAlert
     * 
     * @param id
     * @param text
     */
    function showAlert(id, text) {
        var alert = $(id);
        if (text !== undefined)
            alert.text(text);
        alert.show();
        setTimeout(function() {
            alert.hide();
        }, 5000);
    }

    /**
     * updateGraphList
     * 
     * @param space
     * @param graphCount
     */
    function updateGraphList(space, graphCount) {
        while (config.graphs.length > graphCount) {
            space.removeGraph(config.graphs[config.graphs.length - 1]);
            config.graphs.pop();
        }
        var newGraph;
        while (config.graphs.length < graphCount) {
            if (config.graphs.length > 0) {
                var lastGraph = config.graphs[config.graphs.length - 1];
                newGraph = new Graph(v(lastGraph.origin.x, (lastGraph.origin.y + lastGraph.limits.y.max - lastGraph.limits.y.min + 150), 0), space);

            } else {
                newGraph = new Graph(v(-window.innerWidth / 4.0, -window.innerHeight / 4.0, 0), space);
            }
            newGraph.axisSections = {
                x : 4,
                y : 4,
                z : 4
            };
            newGraph.id = config.graphs.length;
            newGraph.init();
            config.graphs.push(newGraph);
        }
    }

    /**
     * updateGraphConfigList
     */
    function updateGraphConfigList() {
        $('#graphConfigList').html(graphTemplate);
        $p('#graphConfigList').render(config.graphs, directives.graphs);

        $('#graphConfigList tr td div input').on('input', function(e) {
            var graph = parseInt($(this).parent().parent().parent().attr('graph'));
            config.graphs[graph].setName(this.value);
        });
    }
    
    // Russell adding starts here
    var animation = true;
    var StartTime = 0;
    var StopTime = 0;
    var ResumeTime = 0;
    var deltaTime = 0;
    var delayTimeCounter = 50;
    var Timer;
    var toggle_axis_color = "Black";
    $('#buttonStart').prop('disabled', false);
    $('#buttonStop').prop('disabled', false);
    $('.metricsUpdateButton').prop('disabled', true);
    $('.flowUpdateButton').prop('disabled', true);
    
    
    function finishedTimer(){
      for ( var i in config.graphs) {
           var graph = config.graphs[i];
           if (!graph.isAnimating) {
	      //jQuery("#buttonStart").button('toggle');
	      $('#buttonStart').prop('disabled', false);
	      animation = true;
	      deltaTime = 0;
	      delayTimeCounter = 50;
	   }  
      }  
    }
    
    function resetFinishedTimer(){
      clearTimeout(Timer);
    }

    function initButtons(space) {
	
	$('#button3DView').on('click', function(event) {
	      if (toggle_axis_color == "Black") {
		for ( var i in config.graphs) {
		    var graph = config.graphs[i];
		    graph.axisColors = {
		      x: 0xFF0000,
		      y: 0x00FF00,
		      z: 0x0000FF
		    };
		    space.setPerspective(!space.perspective);
		    toggle_axis_color = "RGB";
		}
	      } else if (toggle_axis_color == "RGB") {
		 for ( var i in config.graphs) {
		    var graph = config.graphs[i];
		    graph.axisColors = {
		      x: 0x000000,
		      y: 0x000000
		    };
		    space.setPerspective(!space.perspective);
		    toggle_axis_color = "Black";
		 }
	      } 
        });

        $('#buttonStart').on('click', function(event) {    
	  for ( var i in config.graphs) {
              var graph = config.graphs[i];
              if (animation == true & !graph.isAnimating) {
		 //jQuery("#buttonStart").button('toggle');
		 $('#buttonStart').prop('disabled', true);
		 graph.animateGraph(config.animTime);
		 Timer = setTimeout(finishedTimer, config.animTime+50);
		 StartTime = Date.now();
	      } else if (animation == false & !graph.isAnimating) {
		 //jQuery("#buttonStart").button('toggle');
		 $('#buttonStart').prop('disabled', true);
		 //jQuery("#buttonStop").button('toggle');
		 $('#buttonStop').prop('disabled', false);
		 graph.animateGraph(config.animTime);
		 animation = true;
		 Timer = setTimeout(finishedTimer, ResumeTime);
		 StartTime = Date.now();
	      } 
	  }
        });
	
	$('#buttonStop').on('click', function(event) { 
	    for ( var i in config.graphs) {
	        var graph = config.graphs[i];
		if (graph.isAnimating) {
		   graph.stopAnimating();
		   //jQuery("#buttonStart").button('toggle');
		   $('#buttonStart').prop('disabled', false);
		   //jQuery("#buttonStop").button('toggle');
		   $('#buttonStop').prop('disabled', true);
		   animation = false;
		   resetFinishedTimer();
		   StopTime = Date.now();
		   delayTimeCounter = delayTimeCounter + 15;
		   deltaTime = deltaTime + (StopTime - StartTime);
		   ResumeTime = config.animTime - deltaTime + delayTimeCounter;
		} 
	    }
        });
	
	$('#buttonReset').on('click', function(event) { 
	    for ( var i in config.graphs) {
                var graph = config.graphs[i];
		if (graph.isAnimating) {
		   graph.stopAnimating();
		   graph.animateGraph();
		   //jQuery("#buttonStart").button('toggle');
		   $('#buttonStart').prop('disabled', false);
		   resetFinishedTimer();
		   deltaTime = 0;
	           delayTimeCounter = 50;
                } else if (animation == false & !graph.isAnimating) {
		   graph.stopAnimating();
		   graph.animateGraph();
		   //jQuery("#buttonStop").button('toggle');
		   $('#buttonStop').prop('disabled', false);
		   animation = true;
		   resetFinishedTimer();
		   deltaTime = 0;
	           delayTimeCounter = 50;
                }
	    }
        });
	
        $('#buttonGrid').on('click', function(event) {
	     for ( var i in config.graphs) {
                 var graph = config.graphs[i];
	         graph.showGrid = !graph.showGrid;
                 graph.init();
	     }   
        });
    }
    // Russell adding ends here

    function initGraphConfig(space) {
        updateGraphList(space, 1);
        updateGraphConfigList();

        $('#gridDropdownList li a').on('click', function(e) {
            var result = updateDropdownText($(this));
            if (result) {
                updateGraphList(space, parseInt($(this).text()));
                updateGraphConfigList();
            }
            return result;
        });
    }

    function updateDropdownText(dropdown) {
        if (!dropdown.parent().hasClass('disabled') && !dropdown.parent().hasClass('dropdown-header')) {
            var btn = dropdown.parent().parent().parent().find('button');
            btn.html(dropdown.text() + ' <span class="caret"></span>');
            return true;
        } else {
            return false;
        }
    }

    function updateLegend(colours) {
        /* Pad lnames with empty names */
        while (config.lnames.length < Object.keys(colours).length) {
            config.lnames.push('');
        }
        for ( var i in config.lnames) {
            if (i < Object.keys(colours).length) {
                var index = Object.keys(colours)[i];
                colours[index].index = i;
                colours[index].lname = config.lnames[i];
            }
        }

        $('#legendList').html(legendFlowTemplate);
        $p('#legendList').render(colours, directives.legends);

        $('#legendList').find('a.legendFlow').off('click').on('click', function() {
            var flow = $(this).attr('flow');
            $('#flowNameHeading').text(flow);
            $('#flowNameText').val(colours[flow].lname);
            $('#flowNameText').attr('placeholder', flow);

            $('#flowNameUpdate').off('click').on('click', function() {
                config.lnames[colours[flow].index] = $('#flowNameText').val();
                updateLegend(colours);
            });

            $('#flowName').modal('show');
        });
    }

    function updateDataSourcesFailure(result) {
        $('#metricDataSourceError span.message').html(result);
        $('#metricDataSourceError').show();
        console.log(result);
        hideLoadingPanel();
    }

    /**
     * Separate raw data obtained from server into sets of 2D data for each data set of each flow of each metric
     * 
     * [3][2] 1 : 3/2 is one data pair [3] 2 [1]: 3/1 is second data pair
     * 
     * @param data
     */
    function parseProperties(data) {
        var i, j;
        /* Cleanup flows (remove anything that hasn't been selected) */
        for (i in flows) {
            if (!(i in data)) {
                delete flows[i];
            } else {
                for (j in flows[i]) {
                    if (!(j in data[i])) {
                        delete flows[i][j];
                    }
                }
            }
        }

        /* Metrics */
        for (i in data) {
            var metric = data[i];
            if (!(i in flows)) {
                flows[i] = {};
            }
            var metricProp = flows[i];
            /* Flows */
            for (j in metric) {
                var flow = metric[j];
                if (!(j in metricProp)) {
                    metricProp[j] = [];
                }
                metricProp[j] = flow;
            }
        }
    }

    function updateFlowMappingTable() {
        var tableData = [];

        for ( var i in config.flows) {
            for ( var j in config.flows[i]) {
                tableData.push({
                    'metric' : i,
                    'flow' : config.flows[i][j]
                });
            }
        }
        
//        console.log(tableData);
//        console.log(flows);

        $('#flowMappingTable').html(flowMappingRowTemplate);
        $p('#flowMappingTable').render(tableData, directives.flowMaps);

        var axisList = function() {
            var optionshtml = '<li><a href="#" metric="NOTHING" flow="" dataset=""><small>Nothing</small></a></li>\
			<li><a href="#" flow="" metric="TIME" dataset=""><small>Time</small></a></li>';

            for ( var i in flows) {
                var metric = flows[i];
                optionshtml += '<li class="disabled"><a href="#">' + i + '</a></li>';
                /*
                 * Sort the metrics so that they are in the same order as the flow list
                 */
                var metricFlowList = Object.keys(metric).sort()
                for ( var j in metricFlowList) {
                    var flowName = metricFlowList[j];
                    optionshtml += '<li><a href="#" metric="' + i + '" flow="' + flowName + '" ><small>' + flowName + '</small></a></li>';

                }
            }
            return optionshtml;
        }();

        /* Populate data set dropdown with data set indices for the flow/metric */

        $('#flowMappingTable').find('.flowMapRowDataSet').each(function() {
            var metric = $(this).closest('.flowMapRow').find('.flowMapRowMetric').text();
            var flow = $(this).closest('.flowMapRow').find('.flowMapRowFlow').text();
            var options = $(this).find('ul');
            var optionshtml = '';
            var count = flows[metric][flow].length;
            for (var i = 0; i < count; i++) {
                optionshtml += '<li><a href="#">' + i + '</a></li>';
            }
            options.html(optionshtml);

            $(this).find('a').off('click').on('click', function(e) {
                updateDropdownText($(this));
            });
        });

        /* Populate graph dropdown with graph indices */

        $('#flowMappingTable').find('.flowMapRowGraph').each(function() {
            var count = config.graphs.length;
            var options = $(this).find('ul');
            var optionshtml = '';
            for (var i = 0; i < count; i++) {
                optionshtml += '<li><a href="#">' + (i + 1) + '</a></li>';
            }
            options.html(optionshtml);

            $(this).find('a').off('click').on('click', function(e) {
                return updateDropdownText($(this));
            });
        });

        /* Populate x and z axis dropdowns with other metrics and flows */

        $('#flowMappingTable').find('.flowMapRowXAxis').each(function() {
            var options = $(this).find('ul');
            options.html(axisList);
            $(this).find('a').off('click').on('click', function(e) {
                var button = $(this).parent().parent().parent().find('button');
                button.attr('metric', $(this).attr('metric'));
                button.attr('flow', $(this).attr('flow'));
                button.attr('dataset', $(this).attr('dataset'));
                return updateDropdownText($(this));
            });
        });
        $('#flowMappingTable').find('.flowMapRowZAxis').each(function() {
            var options = $(this).find('ul');
            options.html(axisList);
            $(this).find('a').off('click').on('click', function(e) {
                var button = $(this).parent().parent().parent().find('button');
                button.attr('metric', $(this).attr('metric'));
                button.attr('flow', $(this).attr('flow'));
                button.attr('dataset', $(this).attr('dataset'));
                return updateDropdownText($(this));
            });
        });
    }

    var active_flowID = true; /* Changed */ 
    function updateFlowSelection() {
        var sorted = {};
        /* Push flows into an array in order to sort them */
        for ( var metric in flows) {
            var sortedFlows = [];
            for ( var i in flows[metric]) {
                var flow = flows[metric][i];
                flow.flow = i;
                sortedFlows.push(flow);
            }

            /* Lexically sort the flow names */
            sortedFlows.sort(function(a, b) {
                return a.flow.localeCompare(b.flow);
            });
            sorted[metric] = sortedFlows;
        }

        // Djuro start here
//        console.log(flows);
//        console.log(sorted);

        var flowData = {};
        var metricList = Object.keys(sorted);
        var groupList = [];
        var flowHeaderList;

//        console.log(metricList);

        for ( var metric in metricList) {
            for ( var flowIndex in sorted[metricList[metric]]) {
                var flow = sorted[metricList[metric]][flowIndex];
                if (groupList.indexOf(flow.group) == -1) {
                    groupList.push(flow.group);
                }
            }
        }

//        console.log(groupList);

        if (groupList.length == 1) {
            flowHeaderList = config.exp_id;
        } else {
            flowHeaderList = [];
            for ( var metric in metricList) {
                for ( var flowIndex in sorted[metricList[metric]]) {
                    var flow = sorted[metricList[metric]][flowIndex];
                    var flowName = flow.flow.split("_").slice(0, -4).join("_");
                    if (flowHeaderList.indexOf(flowName) == -1) {
                        flowHeaderList.push(flowName);
                    }
                }
            }
        }

//        console.log(flowHeaderList);

        for ( var metric in metricList) {
            flowData[metricList[metric]] = [];

            for ( var groupIndex in groupList) {
                var tempObject = {};
                tempObject[flowHeaderList[groupIndex]] = [];
                flowData[metricList[metric]].push(tempObject);
            }
            

            for ( var flowIndex in sorted[metricList[metric]]) {
                var flow = sorted[metricList[metric]][flowIndex];
                var groupIndex = groupList.indexOf(flow.group);

                flowData[metricList[metric]][groupIndex][flowHeaderList[groupIndex]].push(flow);
            }
        }

//        console.log(flowData);

        $('#flowIdData').html(flowIdTemplate);
        $('#accordionFlowId').html(flowIdContent);

        $p('#accordionFlowId').render(metricList, directives.metricsFlowTitle);
        $("#accordionFlowId #metricNavTo").attr("data-target", function(arr) {
            return "#collapseToMetricFlow" + arr;
        });

        $("#accordionFlowId #metricNavFrom").attr("id", function(arr) {
            return "collapseToMetricFlow" + arr;
        });

        for ( var keyIndex in metricList) {
            var keys = [];
            var key = metricList[keyIndex];
            var exp = flowData[key];
            for ( var expDataIndex in exp) {
                keys.push(Object.keys(exp[expDataIndex])[0]);
            }
//            console.log(keys);

            $p('#collapseToMetricFlow' + keyIndex + ' #accordionSubFlowId').render(keys, directives.metricsFlowSubTitle);
        }

        $("#accordionFlowId #metricFlowNavTo").attr("data-target", function(arr) {
            return "#collapseToMetricFlowSub" + arr;
        });

        $("#accordionFlowId #metricFlowNavFrom").attr("id", function(arr) {
            return "collapseToMetricFlowSub" + arr;
        });

        var count = 0;
        for ( var keyIndex in metricList) {
            var key = metricList[keyIndex];
            var exp = flowData[key];
            for ( var expDataIndex in exp) {
                var expKey = Object.keys(exp[expDataIndex])[0];
                var expDataList = exp[expDataIndex][expKey];
                $p('#accordionFlowId #collapseToMetricFlowSub' + count).render(expDataList, directives.metricFlowData);

                count = count + 1;
            }
        }

        $('.toggle-accordion-flow').on('click', function() {
            if (active_flowID == true) { /* Changed */
                $('#accordionFlowId .panel-collapse').collapse('show');
                $('#accordionFlowId .panel-title').attr('data-toggle', '');
                $(this).text('Collapse all');
		setTimeout(function() { /* Changed */
                   active_flowID = false; /* Changed */
                }, 500); /* Changed */
            } else {
                $('#accordionFlowId .panel-collapse').collapse('hide');
                $('#accordionFlowId panel-title').attr('data-toggle', 'collapse');
                $(this).text('Expand all');
		setTimeout(function() { /* Changed */
                   active_flowID = true; /* Changed */
                }, 500); /* Changed */
            }
        });

        var numberOfPanels = metricList.length + count;
        $('#accordionFlowId .panel').on('shown.bs.collapse', function() {
            var result = $('#accordionFlowId .panel-heading[aria-expanded=true]');
//            console.log("SHOWN" + result);
            if (result.length == numberOfPanels) {
                $('#accordionFlowId .panel-collapse').collapse('show');
                $('#accordionFlowId .panel-title').attr('data-toggle', '');
                $('.toggle-accordion-flow').text('Collapse all');
		setTimeout(function() { /* Changed */
                   active_flowID = false; /* Changed */
                }, 500); /* Changed */
            }
        });
        $('#accordionFlowId .panel').on('hidden.bs.collapse', function() {
            var result = $('#accordionFlowId .panel-heading[aria-expanded=true]');
//            console.log("HIDDEN" + result)
            if (result.length == 0) {
                $('#accordionFlowId .panel-collapse').collapse('hide');
                $('#accordionFlowId panel-title').attr('data-toggle', 'collapse');
                $('.toggle-accordion-flow').text('Expand all');
		setTimeout(function() { /* Changed */
                   active_flowID = true; /* Changed */
                }, 500); /* Changed */
            }
        });
        // Djuro end here

//        $('#flowSelectionTable').html(flowRowTemplate); $p('#flowSelectionTable').render(sorted, directives.flows);

        config.flows = {};
	
	// Russell Changes start here
	var flowID_change = 0;
	$('#accordionFlowId').find('input').off('change').on('change', function() {
           var metric = $(this).closest('#metricFlowIdHeading').find('#metricHeading span').text();
           var flowName = $(this).closest('#metricFlowSubIdHeading').find('#metricSubHeading span').text();
           var flowDetails = $(this).parent().find('span').text().split("(")[0].trim();
           var flow;
           if(groupList.length == 1) {
               flow = flowDetails;
           } else {
               flow = flowName + "_" + flowDetails; 
           }
           
//           console.log("metric: " + metric);
//           console.log("flowName: " + flowName);
//           console.log("flowDetails: " + flowDetails);
//           console.log("flow: " + flow);
           if ($(this).is(':checked')) {
	       if (!(metric in config.flows)) {
                   config.flows[metric] = [];
               }
               if (config.flows[metric].indexOf(flow) === -1) {
                   config.flows[metric].push(flow);
		   $('.flowUpdateButton').prop('disabled', false);
		   flowID_change += 1;
               } 
           } else if (metric in config.flows && config.flows[metric].indexOf(flow) > -1) {
	           config.flows[metric].splice(config.flows[metric].indexOf(flow), 1);
		   flowID_change -= 1;
                   if (flowID_change == 0) {
		      $('.flowUpdateButton').prop('disabled', true);
		   }   
           }

           updateFlowMappingTable();
        });
	// Russell Changes end here

// //        $('#flowSelectionTable').find('input').off('change').on('change', function() {
// //            var metric = $(this).closest('.flowRow').find('.flowRowName').text();
// //            console.log(metric);
// //            var flow = $(this).closest('.flowSubRow').find('.flowSubRowTitle').text();
// //            console.log(flow);
// //            if ($(this).is(':checked')) {
// //                console.log("CHECKED TRUE");
// //                if (!(metric in config.flows)) {
// //                    config.flows[metric] = [];
// //                }
// //                if (config.flows[metric].indexOf(flow) === -1) {
// //                    config.flows[metric].push(flow);
// //                }
// //            } else {
// //                if (metric in config.flows && config.flows[metric].indexOf(flow) > -1) {
// //                    config.flows[metric].splice(config.flows[metric].indexOf(flow), 1);
// //                }
// //            }
// //
// //            updateFlowMappingTable();
// //        });
    }

    function updateDataSourcesSuccess(result) {
        var resultCode = result.result;
        if (resultCode === 'Success') {
            $('#metricSelection').modal('hide');
            parseProperties(result.data);
            updateFlowSelection();
	    $('#metricDataSourceError').hide();
        } else {
            $('#metricDataSourceError span.message').html(resultCode);
            $('#metricDataSourceError').show();
        }
        hideLoadingPanel();
    }

    function updateDataSources() {
        //showLoadingPanel();
        config.src_filter = $('#metricsTabDataSourcesFilter').val();
        $.ajax({
            type : "POST",
            url : "/api/metrics/get/",
            data : JSON.stringify({
                'exp_id' : config.exp_id,
                'src_filter' : config.src_filter,
                'metrics' : config.metrics,
                'yscale' : config.yscale
            }),
            contentType : "application/json; charset=utf-8",
            dataType : "json",
            success : updateDataSourcesSuccess,
            failure : updateDataSourcesFailure,
        });
    }

    function highest(data) {
        var y = 0, x = 0, z = 0;
        for ( var k in data) {
            if (data[k][1] > y)
                y = data[k][1];
            if (data[k][0] > x)
                x = data[k][0];
            if (data[k].length === 3 && data[k][2] > z)
                z = data[k][2];
        }
        return v(x, y, z);
    }

    function getGraphSuccess(data) {

        hideLoadingPanel(); 
        $('#flowSelection').modal('hide');
        $('.flowUpdateButton').prop('disabled', false); /* Changed */

        if (data.result === 'Success') {  
            var highestValues = {};
            var highestX = 0;
            var colours = {};
            var i;
            /*
             * Iterate through and ascertain highest values prior to plotting
             */
            for (i in data.data) {
                var mapData = data.data[i];
                var map = config.mapping[mapData.map];
                var graphIndex = map.graph;
                var high = highest(mapData.plot[0]);
                var graph = space.graphList[map.graph];
                if (highestValues[graphIndex] === undefined) {
                    highestValues[graphIndex] = v(0.0, 0.0, 0.0);
                }
                if (highestX < high.x) {
                    highestX = high.x;
                }
                if (highestValues[graphIndex].y < high.y) {
                    highestValues[graphIndex].y = high.y;
                }
                if (highestValues[graphIndex].z < high.z) {
                    highestValues[graphIndex].z = high.z;
                }
            }

            for ( var i in space.graphList) {
                if (highestValues[i] !== undefined) {
                    var graph = space.graphList[i];
                    graph.axisLabelRange.z.max = highestValues[i].z;
                    graph.axisLabelRange.y.max = highestValues[i].y;
                    graph.axisLabelRange.x.max = highestX;
                }
            }

            for (i in data.data) {
                var mapData = data.data[i];
                var map = config.mapping[mapData.map];
                var graphIndex = map.graph;
                var graph = space.graphList[map.graph];
                graph.init();
                var dataSeries = new DataSeries();
                dataSeries.data = mapData.plot[0];
                dataSeries.yScale = graph.limits.y.max / graph.axisLabelRange.y.max;
                if (colours[map.flow] === undefined) {
                    var colourIndex = Object.keys(colours).length % colourList.length;
                    var colour = colourList[colourIndex];
                    colours[map.flow] = v(colour.r, colour.b, colour.g);
                }
                dataSeries.colour = colours[map.flow];
                dataSeries.xScale = graph.limits.x.max / graph.axisLabelRange.x.max;
                dataSeries.zScale = highestValues[graphIndex].z === 0.0 ? 1.0 : (graph.limits.z.max / graph.axisLabelRange.z.max);
                var plot = new Plot(dataSeries, 0);
                graph.addPlot(plot);

                graph.setAxisLabel('x', map.xaxis.metric);
                graph.setAxisLabel('y', map.metric);
                graph.setAxisLabel('z', map.zaxis.metric);

                if (graph.graphName === '')
                    graph.setName(map.metric);

            }
            updateStartAndEndTime(highestX);

            updateLegend(colours);
        } else {
            console.log('API Error: ' + data.result);
        }
    }

    function updateStartAndEndTime(highestTime) {
        var xMinPercent = 0.0, xMaxPercent = 100.0;
        if (((config.stime < config.etime) || (config.stime > 0 && config.etime === 0.0)) && config.etime < highestTime) {
            if (config.stime > 0.0) {
                xMinPercent = parseFloat((config.stime / highestTime * 100.0).toFixed(1));
            }

            if (config.etime > 0.0) {
                xMaxPercent = parseFloat((config.etime / highestTime * 100.0).toFixed(1));
            }
        }

        updateControlXMinSlider(xMinPercent);
        updateControlXMaxSlider(xMaxPercent);
        updateLabels();
    }

    function getGraphFailure(result) {
        console.log('Failure: ' + result);
        hideLoadingPanel();
	$('#flowSelection').modal('hide');
        $('.flowUpdateButton').prop('disabled', false); /* Changed */
	//$('.flowUpdateButton').removeAttr('disabled');
    }

    function getFilename(metric, flow) {
        console.log(flows);
        console.log("Metric: " + metric);
        console.log("Flow: " + flow);
        if (metric === 'TIME' || metric === 'NOTHING') {
            console.log("RETURN metric");
            return metric;
        } else {
            console.log("Filename: " + flows[metric][flow].filename);
            return flows[metric][flow].filename;
        }

    }

    function updateView() {
        var i;
        for (i in space.graphList) {
            space.graphList[i].deletePlots();
        }
        var data = [];

        for (i in config.mapping) {
            var map = config.mapping[i];
            var xmetric = map.xaxis.metric;
            var ymetric = map.metric;
            var zmetric = map.zaxis.metric;
            var mapData = {
                'map' : i,
                'x' : {
                    'metric' : xmetric,
                    'dataset' : map.xaxis.dataset,
                    'file' : getFilename(xmetric, map.xaxis.flow),
                    'scale' : (xmetric !== 'TIME' && xmetric !== 'NOTHING' ? config.yscale[xmetric] : 1.0)
                },
                'y' : {
                    'metric' : ymetric,
                    'dataset' : map.dataset,
                    'file' : getFilename(ymetric, map.flow),
                    'scale' : config.yscale[ymetric],
                    'group' : flows[ymetric][map.flow].group
                },
                'z' : {
                    'metric' : zmetric,
                    'dataset' : map.zaxis.dataset,
                    'file' : getFilename(zmetric, map.zaxis.flow),
                    'scale' : (zmetric !== 'TIME' && zmetric !== 'NOTHING' ? config.yscale[zmetric] : 1.0)
                }
            };

            data.push(mapData);
        }

        $.ajax({
            type : "POST",
            url : "/api/graph/",
            data : JSON.stringify(data),
            contentType : "application/json; charset=utf-8",
            dataType : "json",
            success : getGraphSuccess,
            failure : getGraphFailure,
        });

    }

    function updateFlows() {

        /* Save list of flow maps */
        config.mapping = [];
        $('.flowMapRow').each(function(index) {
            var xaxisButton = $(this).find('.flowMapRowXAxis').find('button');
            var zaxisButton = $(this).find('.flowMapRowZAxis').find('button');
            var mapping = {
                metric : $(this).find('.flowMapRowMetric').text(),
                flow : $(this).find('.flowMapRowFlow').text(),
                graph : (parseInt($(this).find('.flowMapRowGraph').find('button').text()) - 1) || 0,
                dataset : parseInt($(this).find('.flowMapRowDataSet').find('button').text()) || 0,
                xaxis : {
                    flow : xaxisButton.attr('flow'),
                    dataset : parseInt(xaxisButton.attr('dataset')) || 0,
                    metric : xaxisButton.attr('metric')
                },
                zaxis : {
                    flow : zaxisButton.attr('flow'),
                    dataset : parseInt(zaxisButton.attr('dataset')) || 0,
                    metric : zaxisButton.attr('metric')
                }
            };
            config.mapping.push(mapping); 
        });
        if (config.mapping.length > 0) {
            showLoadingPanel();
            $('.flowUpdateButton').prop('disabled', true); /* Changed */
            updateView();
        } 
    }

    function updateYScales() {
        $('#metricsTabDataSourcesTable tr td input.yscale').each(function(index) {
            /* TODO: Replace parent()s with closest() */
            var metric = $(this).parent().parent().find('.metricTableRowName').html();
            var yscale = parseFloat($(this).val()) || 1.0;
            config.yscale[metric] = yscale;
        });
    }

    var metricID_change = 0; /* Changed */
    var active_metricID = true; /* Changed */
    function initMetricSelection() {
        $('#metricDataSourceError').hide();
        $('#metricDataSourceError button').on('click', function() {
            $(this).parent().hide();
        });

        $.getJSON('/api/metrics', function(data) {
            var metricList = data.metrics;
            // console.log(metricList);
            // $('#metricsTabDataSourcesTable').html(metricTableRowTemplate);
            // $p('#metricsTabDataSourcesTable').render(metricList,
            // directives.metrics);

            // Djuro start here
            // Generate HTML abstract accordion template
            $('#metricIdData').html(metricIdTemplate);
            // $('#accordionExpId').html(expIdHeading +
            // expIdExperiments);
            $('#accordionMetricId').html(metricIdContent);

            // Split all experiment data using space ( )
            var splitExp = [];
            for (var eachExp = 0; eachExp < metricList.length; eachExp++) {
                var tempSplit = metricList[eachExp].split(' ');
                var actualSplit = [];
                if (tempSplit.length > 2) {
                    actualSplit.push(tempSplit[0]);
                    actualSplit.push(tempSplit.slice(1, tempSplit.length).join(" "));
                    splitExp.push(actualSplit);
                } else {
                    splitExp.push(tempSplit);
                }
            }
            // console.log(splitExp);

            // Match the experiment metric by certain features
            // (eg. "SIFTR", "Web10G", "Common"). Note "Common"
            // has no spaces so it doesn't need to be identified
            var metricGroupKeys = [ "SIFTR", "Web10G", "Common" ];
            var indexMetricMatch = metric_index_match(splitExp, metricGroupKeys);

            $p('#accordionMetricId').render(metricGroupKeys, directives.metricsTitle);
            $("#accordionMetricId .panel-heading").attr("data-target", function(arr) {
                return "#collapseToMetric" + arr;
            });

            $("#accordionMetricId .panel-collapse").attr("id", function(arr) {
                return "collapseToMetric" + arr;
            });

            for (var eachMajorMetric = 0; eachMajorMetric < metricGroupKeys.length; eachMajorMetric++) {
                var key = metricGroupKeys[eachMajorMetric];
                var indexGroupMetric = indexMetricMatch[eachMajorMetric][key];

                // Create data for each sub metric in major
                // metric
                var multipleSingleJoinedMetric = metric_rejoin(splitExp, indexGroupMetric);

                $p('#accordionMetricId #collapseToMetric' + eachMajorMetric).render(multipleSingleJoinedMetric, directives.metricsInput);
            }
            
            // Russell changes start here
            $('#accordionMetricId #metricData').on('change', function() {
                /*
                 * TODO: Replace parent()s with closest()
                 */
                var titleId = $(this).parent().parent().parent().parent().find('.panel-title span').text();
                if (titleId == metricGroupKeys[metricGroupKeys.length - 1]) {
                    titleId = "";
                } else {
                    titleId = titleId + " ";
                }
                var metricId = $(this).find('span').text();
                var metricWhole = titleId.concat(metricId);
                var index = config.metrics.indexOf(metricWhole);
                if (index === -1) {
                    config.metrics.push(metricWhole);
		    $('.metricsUpdateButton').prop('disabled', false);
		    metricID_change += 1;
                } else {
                    config.metrics.splice(index, 1);
		    metricID_change -= 1;
		    if (metricID_change == 0) {
		       $('.metricsUpdateButton').prop('disabled', true);
		    }   
                }
            });
	    // Russell changes end here

            $('#accordionMetricId #metricData').each(function() {
                /*
                 * TODO: Replace parent()s with closest()
                 */
                var titleId = $(this).parent().parent().parent().parent().find('.panel-title span').text();
                if (titleId == metricGroupKeys[metricGroupKeys.length - 1]) {
                    titleId = "";
                } else {
                    titleId = titleId + " ";
                }
                var metricId = $(this).find('span').text();
                var metricWhole = titleId.concat(metricId);
                var index = config.metrics.indexOf(metricWhole);
                if (index > -1) {
                    $(this).find('input').attr('checked', true);
                }
            });

            $('.toggle-accordion-metric').on('click', function() {
                if (active_metricID == true) { /* Changed */
                    $('#accordionMetricId .panel-collapse').collapse('show');
                    $('#accordionMetricId .panel-title').attr('data-toggle', '');
                    $(this).text('Collapse all');
		    setTimeout(function() { /* Changed */
                       active_metricID = false; /* Changed */
                    }, 500); /* Changed */
                } else {
                    $('#accordionMetricId .panel-collapse').collapse('hide');
                    $('#accordionMetricId panel-title').attr('data-toggle', 'collapse');
                    $(this).text('Expand all');
		    setTimeout(function() { /* Changed */
                       active_metricID = true; /* Changed */
                    }, 500); /* Changed */
                }
            });

            var numberOfPanels = metricGroupKeys.length;
            $('#accordionMetricId .panel').on('shown.bs.collapse', function() {
                var result = $('#accordionMetricId .panel-heading[aria-expanded=true]');
                if (result.length == numberOfPanels) {
                    $('#accordionMetricId .panel-collapse').collapse('show');
                    $('#accordionMetricId .panel-title').attr('data-toggle', '');
                    $('.toggle-accordion-metric').text('Collapse all');
		    setTimeout(function() { /* Changed */
                       active_metricID = false; /* Changed */
                    }, 500); /* Changed */
                }
            });
            $('#accordionMetricId .panel').on('hidden.bs.collapse', function() {
                var result = $('#accordionMetricId .panel-heading[aria-expanded=true]');
                if (result.length == 0) {
                    $('#accordionMetricId .panel-collapse').collapse('hide');
                    $('#accordionMetricId panel-title').attr('data-toggle', 'collapse');
                    $('.toggle-accordion-metric').text('Expand all');
		    setTimeout(function() { /* Changed */
                       active_metricID = true; /* Changed */
                    }, 500); /* Changed */
                }
            });
            // Djuro end here

            /*
             * $('#metricsTabDataSourcesTable tr').each(function (index) { var metric = $(this).find('.metricTableRowName').html(); if (config.metrics.indexOf(metric) > -1) { $(this).find('td div input').attr('checked', true); } if (metric in config.yscale) { $(this).find('td input.yscale').val(config.yscale[metric]); } });
             * 
             * $('#metricsTabDataSourcesTable tr td div input').on('change', function () { TODO: Replace parent()s with closest() var metric = $(this).parent().parent().parent().parent().find('.metricTableRowName').text(); var index = config.metrics.indexOf(metric); if (index === -1) { config.metrics.push(metric); } else { config.metrics.splice(index, 1); } });
             */

            hideLoadingPanel();
        });

        showLoadingPanel();
    }
    
    var expID_change = 0; /* Changed */
    var active_expID = true; /* Changed */
    function initExpIDList() {
        $.getJSON('/api/experiments', function(data) {
            if (data.result === 'Success') {
                /*
                 * $('#metricsTabDataSourcesExp').html(expIdTableTemplate); $p('#metricsTabDataSourcesExp').render(data.experiments, directives.expids);
                 */
                // console.log(data);
                // Generate HTML abstract accordion template
                $('#expIdData').html(expIdTemplate);
                // $('#accordionExpId').html(expIdHeading + expIdExperiments);
                $('#accordionExpId').html(expIdContent);

                // Split all experiment data using underscore
                // (_)
                var splitExp = [];
                for (var eachExp = 0; eachExp < data.experiments.length; eachExp++) {
                    splitExp.push(data.experiments[eachExp].split('_'));
                }
                // console.log(splitExp);

                // Match the experiment data by certain features
                // (eg. group all data by date)
                var indexExpMatch = exp_index_match(splitExp);
                // console.log(indexExpMatch);

                var keys = [];
                for (var eachMajorExp = 0; eachMajorExp < indexExpMatch.length; eachMajorExp++) {
                    var key = Object.keys(indexExpMatch[eachMajorExp])[0];
                    keys.push(key);
                }
                // console.log(keys);

                $p('#accordionExpId').render(keys, directives.expsTitle);
                $("#accordionExpId .panel-heading").attr("data-target", function(arr) {
                    return "#collapseToExp" + arr;
                });

                $("#accordionExpId .panel-collapse").attr("id", function(arr) {
                    return "collapseToExp" + arr;
                });

                for (var eachMajorExp = 0; eachMajorExp < indexExpMatch.length; eachMajorExp++) {
                    var key = keys[eachMajorExp];
                    var indexGroupExp = indexExpMatch[eachMajorExp][key];

                    var multipleSingleJoinedExp = exp_rejoin(splitExp, indexGroupExp);

                    $p('#accordionExpId #collapseToExp' + eachMajorExp).render(multipleSingleJoinedExp, directives.exps);
                }
                
                // Russell changes start here
                $('#accordionExpId #expData').on('change', function() {
                    /*
                     * TODO: Replace parent()s with closest()
                     */
                    var titleId = $(this).parent().parent().parent().parent().find('.panel-title span').text().slice(0, -1);
                    var expId = $(this).find('span').text();
                    var expWhole = titleId.concat(expId);
                    var index = config.exp_id.indexOf(expWhole);
                    if (index === -1) {
                        config.exp_id.push(expWhole);
			$('.metricsUpdateButton').prop('disabled', false);
			expID_change += 1;
                    } else {
                        config.exp_id.splice(index, 1);
			expID_change -= 1;
			if (expID_change == 0) {
			   $('.metricsUpdateButton').prop('disabled', true);
			}   
                    }
                });
		// Russell changes end here

                $('#accordionExpId #expData').each(function() {
                    /*
                     * TODO: Replace parent()s with closest()
                     */
                    var titleId = $(this).parent().parent().parent().parent().find('.panel-title span').text().slice(0, -1);
                    var expId = $(this).find('span').text();
                    var expWhole = titleId.concat(expId);
                    var index = config.exp_id.indexOf(expWhole);
                    if (index > -1) {
                        $(this).find('input').attr('checked', true);
                    }
                });

		$('.toggle-accordion-exp').on('click', function() {
		    if (active_expID == true) { /* Changed */
                        $('#accordionExpId .panel-collapse').collapse('show');
                        $('#accordionExpId .panel-title').attr('data-toggle', '');
                        $(this).text('Collapse all');
			setTimeout(function() { /* Changed */
                           active_expID = false; /* Changed */
                        }, 500); /* Changed */
                    } else {
                        $('#accordionExpId .panel-collapse').collapse('hide');
                        $('#accordionExpId panel-title').attr('data-toggle', 'collapse');
                        $(this).text('Expand all');
			setTimeout(function() { /* Changed */
                           active_expID = true; /* Changed */
                        }, 500); /* Changed */
                    }
                });

                var numberOfPanels = keys.length;
                $('#accordionExpId .panel').on('shown.bs.collapse', function() {
                    var result = $('#accordionExpId .panel-heading[aria-expanded=true]');
                    if (result.length == numberOfPanels) {
                        $('#accordionExpId .panel-collapse').collapse('show');
                        $('#accordionExpId .panel-title').attr('data-toggle', '');
                        $('.toggle-accordion-exp').text('Collapse all');
			setTimeout(function() { /* Changed */
                           active_expID = false; /* Changed */
                        }, 500); /* Changed */
                    }
                });
                $('#accordionExpId .panel').on('hidden.bs.collapse', function() {
                    var result = $('#accordionExpId .panel-heading[aria-expanded=true]');
                    if (result.length == 0) {
                        $('#accordionExpId .panel-collapse').collapse('hide');
                        $('#accordionExpId panel-title').attr('data-toggle', 'collapse');
                        $('.toggle-accordion-exp').text('Expand all');
			setTimeout(function() { /* Changed */
                           active_expID = true; /* Changed */
                        }, 500); /* Changed */
                    }
                });
                // Djuro end here

                /*
                 * $('#metricsTabDataSourcesExp tr td div input').on('change', function () { TODO: Replace parent()s with closest() console.log("CHANGE"); var expId = $(this).parent().parent().parent().parent().find('.expIdTableName').text(); console.log("expId: " + expId); var index = config.exp_id.indexOf(expId); console.log("index: " + index); if (index === -1) { config.exp_id.push(expId); } else { config.exp_id.splice(index, 1); } });
                 * 
                 * $('#metricsTabDataSourcesExp tr td div input').each(function () { TODO: Replace parent()s with closest() console.log("EXECUTED"); var expId = $(this).parent().parent().parent().parent().find('.expIdTableName').text(); console.log("expId: " + expId); var index = config.exp_id.indexOf(expId); console.log("index: " + index); if (index > -1) { $(this).attr('checked', true); } });
                 */
            } else {
                console.log(data.result);
            }
        });
    }

    function updateLimits(axis, parameter, value) {
        config.graph[axis][parameter] = value;
        for ( var i in space.graphList) {
            space.graphList[i].zoom(config.graph);
        }
    }

    function updateLabels() {
        for ( var i in space.graphList) {
            space.graphList[i].zoomLabels(config.graph);
        }
    }

    function updateControlXMaxSlider(value) {
        $('#controlXMin').slider('option', 'max', value);
        updateLimits('x', 'max', value);
        $('#controlXMax').closest('div.control-container').find('.control-display').text(value + '%');
        $('#controlXMax').slider('option', 'value', value);
    }
    function updateControlXMinSlider(value) {
        $('#controlXMax').slider('option', 'min', value);
        updateLimits('x', 'min', value);
        $('#controlXMin').closest('div.control-container').find('.control-display').text(value + '%');
        $('#controlXMin').slider('option', 'value', value);
    }

    function updateControlRanges(space) {
        var controlXMin = $('#controlXMin');
        var controlXMax = $('#controlXMax');
        var controlYMin = $('#controlYMin');
        var controlYMax = $('#controlYMax');
        var controlZMin = $('#controlZMin');
        var controlZMax = $('#controlZMax');

        controlXMin.slider({
            max : 100.0,
            min : 0.0,
            step : 0.1,
            value : config.graph.x.min
        });
        controlXMax.slider({
            max : 100.0,
            min : 0.0,
            step : 0.1,
            value : config.graph.x.max
        });
        controlYMin.slider({
            max : 100.0,
            min : 0.0,
            step : 0.1,
            value : config.graph.y.min
        });
        controlYMax.slider({
            max : 100.0,
            min : 0.0,
            step : 0.1,
            value : config.graph.y.max
        });
        controlZMin.slider({
            max : 100.0,
            min : 0.0,
            step : 0.1,
            value : config.graph.z.min
        });
        controlZMax.slider({
            max : 100.0,
            min : 0.0,
            step : 0.1,
            value : config.graph.z.max
        });

        $('.control-display').each(function() {
            $(this).text($(this).closest('div').find('.control-slider').slider("option", "value") + '%');
        });

        controlXMax.on('slide', function(event, ui) {
            updateControlXMaxSlider(ui.value);
        });

        controlXMin.on('slide', function(event, ui) {
            updateControlXMinSlider(ui.value);
        });

        controlYMax.on('slide', function(event, ui) {
            controlYMin.slider('option', 'max', ui.value);
            updateLimits('y', 'max', ui.value);
            $(this).closest('div.control-container').find('.control-display').text(ui.value + '%');
        });
        controlYMin.on('slide', function(event, ui) {
            controlYMax.slider('option', 'min', ui.value);
            updateLimits('y', 'min', ui.value);
            $(this).closest('div.control-container').find('.control-display').text(ui.value + '%');
        });

        controlZMax.on('slide', function(event, ui) {
            controlZMin.slider('option', 'max', ui.value);
            updateLimits('z', 'max', ui.value);
            $(this).closest('div.control-container').find('.control-display').text(ui.value + '%');
        });
        controlZMin.on('slide', function(event, ui) {
            controlZMax.slider('option', 'min', ui.value);
            updateLimits('z', 'min', ui.value);
            $(this).closest('div.control-container').find('.control-display').text(ui.value + '%');
        });

        $('.control-slider').on('slidestop', function(event, ui) {
            updateLabels();
        });
    }

    /* Russell Changes starts here */
    function hideLoadingPanel() {
        $('.loadPanel').removeClass('loadPanel-show');
    }
    
    function showLoadingPanel() {
        $('.loadPanel').addClass('loadPanel-show');
    }
    /* Russell Changes ends here */

    function initAnimationSlider() {
        var animSlider = $('#controlAnimationTime');
        var animDisplay = $('#animationTimeDisplay');
        animDisplay.text(config.animTime + ' ms');
        animSlider.slider({
            max : 30000,
            min : 50,
            step : 50,
            value : config.animTime
        });

        animSlider.on('slide', function(event, ui) {
            config.animTime = ui.value;
            animDisplay.text(config.animTime + ' ms');
        });
    }
    function arrayToTeacupArg(array) {
        var arg = ''
        for ( var i in array) {
            arg += array[i];
            if (i < (array.length - 1)) {
                arg += ';';
            }
        }
        return arg;
    }

    function exportView() {
        var metrics = arrayToTeacupArg(config.metrics);
        var test_ids = arrayToTeacupArg(config.exp_id);
        var lnames = arrayToTeacupArg(config.lnames);
        var graph_names = '';

        for ( var i in config.graphs) {
            graph_names += config.graphs[i].graphName;
            if (i < (config.graphs.length - 1)) {
                graph_names += ';';
            }
        }

        $('#exportViewText').val('fab animate:metric="' + metrics + '",test_id="' + test_ids + '",source_filter="' + config.src_filter + '",lnames="' + lnames + '",graph_count="' + config.graphs.length + '",graph_names="' + graph_names + '",etime="' + config.etime + '",stime="' + config.stime + '"');
        $('#exportView').modal('show');

    }

    function loadDefaultView(space) {
        $.getJSON('/api/default', function(data) {
            config.exp_id = data.test_id;
            config.src_filter = data.source_filter;
            config.metrics = data.metric;

            config.lnames = data.lnames;

            updateGraphList(space, data.graph_count);

            for (var i = 0; i < data.graph_names.length; i++) {
                if (i < data.graph_count) {
                    config.graphs[i].setName(data.graph_names[i]);
                }
            }

            updateDataSources();

            config.stime = data.stime;
            config.etime = data.etime;
        });
    }
    
    $(document).ready(function() {
        space = new GraphSpace('threejs');
        space.init();
	
        initButtons(space);
        initGraphConfig(space);
        updateControlRanges(space);

        initAnimationSlider();
	
	showLoadingPanel();
	initMetricSelection();
        initExpIDList();

        $('#metricSelection').on('shown.bs.modal', function() {
	     $('#metricDataSourceError').hide();
//             showLoadingPanel();
//             initMetricSelection();
//             initExpIDList();

//             $(".toggle-accordion").each(function() {
//                if ($(this).text() == "Collapse all") {
//                    $(this).text("Expand all");
//                }
//             });
        });

        colourList = [ new THREE.Color('#f44336'), new THREE.Color('#3f51b5'), new THREE.Color('#4caf50'), new THREE.Color('#ff9800'), new THREE.Color('#2196f3'), new THREE.Color('#009688'), new THREE.Color('#ffeb3b'), new THREE.Color('#00bcd4'), new THREE.Color('#cddc39'), new THREE.Color('#607d8b') ];
        $('.metricsUpdateButton').off('click').on('click', function() {
            showLoadingPanel();
            updateYScales();
            updateDataSources();
        });

        $('.flowUpdateButton').off('click').on('click', function() { /* Changed */;
	    updateFlows();
        });

        $('#graphConfig').on('shown.bs.modal', function() {
            updateGraphConfigList();
        });

        $('#buttonExport').off('click').on('click', function() {
            exportView();
        });

        $('#buttonResetView').off('click').on('click', function() {
            space.resetView();	    
        });

        $('#buttonControls').off('click').on('click', function() {
            $(".controls").toggleClass('hidden');
        });
	
        loadDefaultView(space);
    });
})();

function init() {
    "use strict";
    /**
     * Initialisation function
     */

}