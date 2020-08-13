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
	
	
	this.navbaractiv='AntiTheft';
	
	this.getNavClass = function( tabtodisplay )
	{
		if (this.navbaractiv === tabtodisplay)
			return 'ng-isolate-scope active';
		return 'ng-isolate-scope';
	}

	this.getNavStyle = function( tabtodisplay )
	{
		if (this.navbaractiv === tabtodisplay)
			return 'border: 1px solid #c2c2c2;border-bottom-color: transparent;';
		return 'background-color:#cbcbcb';
	}
	
            
	
	// --------------------------------------------------------------------------
	//
	//  Custom page
	//
	// --------------------------------------------------------------------------
	this.theft={};
	this.serveractivity = {};
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

	
	this.inprogress= false;

	


	this.refresh= function( action ) {
		var self=this;
		self.inprogress=true;

		var json = encodeURI(angular.toJson(this.params, true));
		$http.get( '?page=custompage_securitycar&action='+action+'&paramjson='+json)
			.success(function(jsonResult, statusHttp, headers, config) {
				
				// connection is lost ?
				if (statusHttp==401 || typeof jsonResult === 'string') {
					console.log("Redirected to the login page !");
					window.location.reload();
				}
				self.inprogress=false;
				// the custom page upgrated is in the list, first position					
				self.listevents 			= jsonResult.listevents;
				self.users.theft			= jsonResult.theft;
				self.users.usersconnected	= jsonResult.usersconnected;
				
				self.theft.theftTentatives	= jsonResult.theftTentatives;
				self.theft.theftSlots 		= jsonResult.theftSlots;
				self.theft.theftTimeLine 	= jsonResult.theftTimeLine;
				self.serveractivity.httpcall = jsonResult.httpcall;
				
				$scope.theftTimeLine		 = JSON.parse(jsonResult.theftGraph);
				
				
			}).error(function(jsonResult, statusHttp, headers, config) {
				self.status			= "Can't connect the server ("+jsonResult.status+")";
				self.inprogress=false;
			});
	}
	this.refresh( 'init');

	// --------------------------------------------------------------------------
	//
	//  User operation
	//
	// --------------------------------------------------------------------------
	this.searchUser= function() {
		var self=this;
		self.inprogress=true;
		var json = encodeURI(angular.toJson(this.params, true));

		$http.get( '?page=custompage_securitycar&action=usersoperation&paramjson='+json)
			.success(function(jsonResult, statusHttp, headers, config) {
				
				// connection is lost ?
				if (statusHttp==401 || typeof jsonResult === 'string') {
					console.log("Redirected to the login page !");
					window.location.reload();
				}
				// the custom page upgrated is in the list, first position
				
				self.listevents 			= jsonResult.data.listevents;
				self.users.operations		= jsonResult.data.operations;
				self.inprogress=false;
			}).error(function(jsonResult, statusHttp, headers, config) {
				self.status			= "Can't connect the server ("+jsonResult.status+")";
				self.inprogress=false;
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
			self.inprogress=true;
			var param = {'userid':userinfo.userid, 'username':userinfo.username,
						'connectedStartIndex': this.params.connectedStartIndex, 'connectedMaxResults':this.params.connectedMaxResults,
					'useroperationFilteruser':this.params.useroperationFilteruser, 'useroperationStartIndex':this.params.useroperationFilteruser, 'useroperationMaxResults':this.params.useroperationFilteruser};
			var json = encodeURI(angular.toJson(param, true));
			$http.get( '?page=custompage_securitycar&action='+action+'&paramjson='+json)
				.success(function(jsonResult, statusHttp, headers, config) {
					
					// connection is lost ?
					if (statusHttp==401 || typeof jsonResult === 'string') {
						console.log("Redirected to the login page !");
						window.location.reload();
					}
						userinfo.listevents 		= jsonResult.data.listevents;
						userinfo.isenabled 			= jsonResult.data.userIsEnabled;
						
						self.inprogress=false;
				}).error(function(jsonResult, statusHttp, headers, config) {
					self.inprogress=false;
				});		
		}
	}

	
	this.disconnect = function( userinfo ) {
		var self=this;
		if (confirm('Do you want to disconnect '+userinfo.username+" ? "))
		{
			self.inprogress=true;
			var param = {'userid':userinfo.userid, 'username':userinfo.username,
						'connectedStartIndex': this.params.connectedStartIndex, 'connectedMaxResults':this.params.connectedMaxResults,
					'useroperationFilteruser':this.params.useroperationFilteruser, 'useroperationStartIndex':this.params.useroperationFilteruser, 'useroperationMaxResults':this.params.useroperationFilteruser};
			var json = encodeURI(angular.toJson(param, true));
			$http.get( '?page=custompage_securitycar&action=disconnect&paramjson='+json)
				.success(function(jsonResult, statusHttp, headers, config) {
					
					// connection is lost ?
					if (statusHttp==401 || typeof jsonResult === 'string') {
						console.log("Redirected to the login page !");
						window.location.reload();
					}
						userinfo.listevents 		= jsonResult.data.listevents;
						userinfo.isenabled 			= jsonResult.data.userIsEnabled;
						
						self.inprogress=false;
				}).error(function(jsonResult, statusHttp, headers, config) {
					self.inprogress=false;
				});		
		}
	}
	
	this.resetTentative = function( userinfo ) {
		var self=this;
		self.inprogress=true;
		var param = {'userid':userinfo.userid, 'username':userinfo.username,
					'connectedStartIndex': this.params.connectedStartIndex, 'connectedMaxResults':this.params.connectedMaxResults,
					'useroperationFilteruser':this.params.useroperationFilteruser, 'useroperationStartIndex':this.params.useroperationFilteruser, 'useroperationMaxResults':this.params.useroperationFilteruser};
		var json = encodeURI(angular.toJson(param, true));
		$http.get( '?page=custompage_securitycar&action=resettentative&paramjson='+json)
			.success(function(jsonResult, statusHttp, headers, config) {
				
				// connection is lost ?
				if (statusHttp==401 || typeof jsonResult === 'string') {
					console.log("Redirected to the login page !");
					window.location.reload();
				}
				userinfo.listeventsreset 		= jsonResult.data.listevents;
				if (jsonResult.data.listeventssuccess)
					userinfo.nbtentative=0;
				self.inprogress=false;
			}).error(function(jsonResult, statusHttp, headers, config) {
				self.inprogress=false;
				});				
	}
	this.resetPassword = function( userinfo ) {
		var self=this;
		self.inprogress=true;
		var param = {'userid':userinfo.userid, 'username':userinfo.username,
					'connectedStartIndex': this.params.connectedStartIndex, 'connectedMaxResults':this.params.connectedMaxResults,
					'useroperationFilteruser':this.params.useroperationFilteruser, 'useroperationStartIndex':this.params.useroperationFilteruser, 'useroperationMaxResults':this.params.useroperationFilteruser};
		var json = encodeURI(angular.toJson(param, true));
		$http.get( '?page=custompage_securitycar&action=resetpassword&paramjson='+json)
			.success(function(jsonResult, statusHttp, headers, config) {
				
				// connection is lost ?
				if (statusHttp==401 || typeof jsonResult === 'string') {
					console.log("Redirected to the login page !");
					window.location.reload();
				}
				userinfo.listevents 		= jsonResult.data.listevents;
				userinfo.passwordGenerated 		= jsonResult.data.passwordGenerated;
				self.inprogress=false;
			}).error(function(jsonResult, statusHttp, headers, config) {
				self.inprogress=false;
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
			.success(function(jsonResult, statusHttp, headers, config) {
				
				// connection is lost ?
				if (statusHttp==401 || typeof jsonResult === 'string') {
					console.log("Redirected to the login page !");
					window.location.reload();
				}

				console.log("loadparameters",jsonResult.data);
				self.saveinprogress=false;
				// $.extend( self.param, jsonResult.data); 
				// angular.copy(jsonResult.data.param, self.param); 
				self.parameter		= jsonResult.data.parameter;
				self.listevents		= jsonResult.data.listevents;
				self.listcustompage();
			}).error(function(jsonResult, statusHttp, headers, config) {
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
			.success(function(jsonResult, statusHttp, headers, config) {
				
				// connection is lost ?
				if (statusHttp==401 || typeof jsonResult === 'string') {
					console.log("Redirected to the login page !");
					window.location.reload();
				}
				self.parameter.listevents= jsonResult.data.listevents;
				self.saveinprogress=false;
			}).error(function(jsonResult, statusHttp, headers, config) {
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