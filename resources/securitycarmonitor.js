'use strict';
/**
 *
 */

(function() {


var appCommand = angular.module('securitycarmonitor', ['googlechart', 'ui.bootstrap', 'ngSanitize']);






// --------------------------------------------------------------------------
//
// Controler Ping
//
// --------------------------------------------------------------------------

// Ping the server
appCommand.controller('SecurityCarControler',
	function ( $http, $scope,$sce ) {

	
	this.showgithublogin=false;
	
	// --------------------------------------------------------------------------
	//
	//  General
	//
	// --------------------------------------------------------------------------

	this.isshowhistory = false;
	this.showhistory = function( showhistory ) {
		this.isshowhistory = showhistory;
	};
	
	this.getListEvents = function ( listevents ) {
		return $sce.trustAsHtml(  listevents);
	}
	
	
	                       
	
	// --------------------------------------------------------------------------
	//
	//  Custom page
	//
	// --------------------------------------------------------------------------
	this.theft={};
	this.users= {};
	
	this.users.theft =[];
	/*
		{'username': 'jan.fisher', 'status': 'BLOCKED', 'nbtentative':6},
		{'username': 'helen.kelly', 'status': 'WARNING', 'nbtentative':3}
		];
		*/
	this.users.connected=[];
	/*
		{'username': 'walter.bates', },
		{'username': 'william.jobs'},
		{'username': 'Daniella.angello'}
		];
		*/
	this.users.operations=[];

	this.params ={ 	'connectedStartIndex': 0, 'connectedMaxResults':100,
					'useroperationFilteruser':'', 'useroperationStartIndex':0, 'useroperationMaxResults':100,
					'theftStartIndex': 0, 'theftMaxResults':100
				};

	
	this.loading= false;

	
	this.init = function() {
		var self=this;
		if (1==1)
			return;
		self.loading=true;
		var json = encodeURI(angular.toJson(this.params, true));
		$http.get( '?page=custompage_securitycar&action=init&paramjson='+json)
				.then( function ( jsonResult ) {
					// the custom page upgrated is in the list, first position
					
					self.listevents 			= jsonResult.data.listevents;
					self.users.theft			= jsonResult.data.theft;
					self.users.connected		= jsonResult.data.connected;
					self.parameter				= jsonResult.data.parameter;
					self.theft.theftLog 		= jsonResult.data.theftLog;
					self.theft.theftTimeLine 	= jsonResult.data.theftTimeLine;

					self.loading=false;
					
				},
				function(jsonResult) {
					self.status			= "Can't connect the server ("+jsonResult.status+")";
					self.loading=false;
					});

	}
	this.init();

	this.refresh= function() {
		var self=this;
		self.loading=true;

		var json = encodeURI(angular.toJson(this.params, true));
		$http.get( '?page=custompage_securitycar&action=refresh&paramjson='+json)
				.then( function ( jsonResult ) {
					self.loading=false;
					// the custom page upgrated is in the list, first position					
					self.listevents 	= jsonResult.data.listevents;
					self.users.theft			= jsonResult.data.theft;
					self.users.connected		= jsonResult.data.connected;
					self.theft.theftLog 		= jsonResult.data.theftLog;
					self.theft.theftTimeLine 	= jsonResult.data.theftTimeLine;
					$scope.theftTimeLine		 = JSON.parse(jsonResult.data.theftGraph);
					
					

					
				},
				function(jsonResult) {
					self.status			= "Can't connect the server ("+jsonResult.status+")";
					self.loading=false;
					});
	}
	
	// --------------------------------------------------------------------------
	//
	//  User operation
	//
	// --------------------------------------------------------------------------
	this.searchUser= function() {
		var self=this;
		self.loading=true;
		var json = encodeURI(angular.toJson(this.params, true));

		$http.get( '?page=custompage_securitycar&action=usersoperation&paramjson='+json)
				.then( function ( jsonResult ) {
					// the custom page upgrated is in the list, first position
					
					self.listevents 			= jsonResult.data.listevents;
					self.users.operations		= jsonResult.data.operations;
					self.loading=false;
				},
				function(jsonResult) {
					self.status			= "Can't connect the server ("+jsonResult.status+")";
					self.loading=false;
					});
	}

	
	
	
	/** add the custom page in a profile
	 * 
	 */
	
	this.activatedeactivate = function( userinfo, activate ) {
		var self=this;
		var action="";
		if ( activate)
			action="activate";
		else
			action="deactivate";
		if (confirm('Do you want to '+action+' '+userinfo.username+" ? "))
		{
			self.loading=true;
			var param = {'userid':userinfo.userid, 'username':userinfo.username,
						'connectedStartIndex': this.params.connectedStartIndex, 'connectedMaxResults':this.params.connectedMaxResults,
					'useroperationFilteruser':this.params.useroperationFilteruser, 'useroperationStartIndex':this.params.useroperationFilteruser, 'useroperationMaxResults':this.params.useroperationFilteruser};
			var json = encodeURI(angular.toJson(param, true));
			$http.get( '?page=custompage_securitycar&action='+action+'&paramjson='+json)
					.then( function ( jsonResult ) {
						userinfo.listevents 		= jsonResult.data.listevents;
						userinfo.isenabled 			= jsonResult.data.userIsEnabled;
						
						self.loading=false;
					},
					function(jsonResult) {
						self.loading=false;
						});		
		}
	}

	
	this.disconnect = function( userinfo ) {
		var self=this;
		if (confirm('Do you want to disconnect '+userinfo.username+" ? "))
		{
			self.loading=true;
			var param = {'userid':userinfo.userid, 'username':userinfo.username,
						'connectedStartIndex': this.params.connectedStartIndex, 'connectedMaxResults':this.params.connectedMaxResults,
					'useroperationFilteruser':this.params.useroperationFilteruser, 'useroperationStartIndex':this.params.useroperationFilteruser, 'useroperationMaxResults':this.params.useroperationFilteruser};
			var json = encodeURI(angular.toJson(param, true));
			$http.get( '?page=custompage_securitycar&action=disconnect&paramjson='+json)
					.then( function ( jsonResult ) {
						userinfo.listevents 		= jsonResult.data.listevents;
						userinfo.isenabled 			= jsonResult.data.userIsEnabled;
						
						self.loading=false;
					},
					function(jsonResult) {
						self.loading=false;
						});		
		}
	}
	
	this.resetTentative = function( userinfo ) {
		var self=this;
		self.loading=true;
		var param = {'userid':userinfo.userid, 'username':userinfo.username,
					'connectedStartIndex': this.params.connectedStartIndex, 'connectedMaxResults':this.params.connectedMaxResults,
					'useroperationFilteruser':this.params.useroperationFilteruser, 'useroperationStartIndex':this.params.useroperationFilteruser, 'useroperationMaxResults':this.params.useroperationFilteruser};
		var json = encodeURI(angular.toJson(param, true));
		$http.get( '?page=custompage_securitycar&action=resettentative&paramjson='+json)
			.then( function ( jsonResult ) {
				userinfo.listeventsreset 		= jsonResult.data.listevents;
				if (jsonResult.data.listeventssuccess)
					userinfo.nbtentative=0;
				self.loading=false;
			},
			function(jsonResult) {
				self.loading=false;
				});				
	}
	this.resetPassword = function( userinfo ) {
		var self=this;
		self.loading=true;
		var param = {'userid':userinfo.userid, 'username':userinfo.username,
					'connectedStartIndex': this.params.connectedStartIndex, 'connectedMaxResults':this.params.connectedMaxResults,
					'useroperationFilteruser':this.params.useroperationFilteruser, 'useroperationStartIndex':this.params.useroperationFilteruser, 'useroperationMaxResults':this.params.useroperationFilteruser};
		var json = encodeURI(angular.toJson(param, true));
		$http.get( '?page=custompage_securitycar&action=resetpassword&paramjson='+json)
			.then( function ( jsonResult ) {
				userinfo.listevents 		= jsonResult.data.listevents;
				userinfo.passwordGenerated 		= jsonResult.data.passwordGenerated;
				self.loading=false;
			},
			function(jsonResult) {
				self.loading=false;
				});				
	}
	// --------------------------------------------------------------------------
	//
	//  properties
	//
	// --------------------------------------------------------------------------

	this.loadParameters = function() 
	{
		var self = this;
		self.saveinprogress=true;
		$http.get( '?page=custompage_securitycar&action=loadparameters' )
		.then( function ( jsonResult ) {
				console.log("loadparameters",jsonResult.data);
				self.saveinprogress=false;
				// $.extend( self.param, jsonResult.data); 
				// angular.copy(jsonResult.data.param, self.param); 
				self.parameter		= jsonResult.data.parameter;
				self.listevents		= jsonResult.data.listevents;
				self.listcustompage();
			},
		function(jsonResult ) {
			self.saveinprogress=false;

			// alert("loadparameters Error : "+ angular.toJson( jsonResult.data ) );
			this.listcustompage();
			}
		);
		
	};


	this.saveParameters = function () 
	{
		var self = this;
		self.saveinprogress=true;
		
		var json = encodeURI(angular.toJson(self.parameter, false));
		
		$http.get( '?page=custompage_securitycar&action=saveParameters&paramjson='+json )
		.then( function ( jsonResult ) {	
				self.parameter.listevents= jsonResult.data.listevents;
				self.saveinprogress=false;
		},
		function(jsonResult ) {
			alert("Error when save parameters ("+jsonResult.status+")");
			self.saveinprogress=false;
		})	
	}
	// --------------------------------------------------------------------------
	//
	//  Initialisation
	//
	// --------------------------------------------------------------------------
	
	
	
});



})();