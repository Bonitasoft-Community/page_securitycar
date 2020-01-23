package org.bonitasoft.googlegraph;

import java.util.List;

public class GraphGenerator {
	

	
	public static class GraphRange {
		public String title;
		public long count;

		public GraphRange(String title, long count) {
			this.title = title;
			this.count = count;
		}
	}
		
	public List<GraphRange>addGraphRange(List<GraphRange> listRange, String title, long count)
	{
		listRange.add( new GraphRange(title, count));
		return listRange;
	}
			
	/**
	 * ----------------------------------------------------------------
	 * getGraphRange
	 * ADD in Java
	 * 	map.put("myGraph", GraphGenerator.getGraphRange(..)
	 * ADD in AngularJS
	 * 		$scope.myTimeLine		 = JSON.parse(jsonResult.data.myGraph);
	 * ADD in HTML
	 * 	<div google-chart chart="myTimeLine" style="height: 200px; width: 100%; position: relative; "></div>
					
		
	 * 
	 * @return
	 */
	public static String getGraphRange(final String title, final List<GraphRange> listRange) {

		/**
		 * structure "rows": [ { c: [ { "v": "January" }," { "v": 19,"f": "42
		 * items" }, { "v": 12,"f": "Ony 12 items" }, ] }, { c: [ { "v":
		 * "January" }," { "v": 19,"f": "42 items" }, { "v": 12,"f": "Ony 12
		 * items" }, ] },
		 */
		String resultValue = "";

		for (int i = 0; i < listRange.size(); i++) {
			resultValue += "{\"c\":[{\"v\":\"" + listRange.get(i).title + "\"},{\"v\": " + listRange.get(i).count + "} ]},";

		}
		if (resultValue.length() > 0) {
			resultValue = resultValue.substring(0, resultValue.length() - 1);
		}

		final String resultLabel = "{ \"type\": \"string\", \"id\": \"whattime\", \"label\":\"whattime\" }," + "{ \"type\": \"number\", \"id\": \"value\", \"label\":\"Occurence\" }";

		final String valueChart = "	{" + "\"type\": \"ColumnChart\", " + "\"displayed\": true, " + "\"data\": {" + "\"cols\": [" + resultLabel + "], " + "\"rows\": [" + resultValue + "] "
		/*
		 * + "\"options\": { " + "\"bars\": \"horizontal\"," + "\"title\": \""
		 * +title+"\", \"fill\": 20, \"displayExactValues\": true," +
		 * "\"vAxis\": { \"title\": \"ms\", \"gridlines\": { \"count\": 100 } }"
		 */
				+ "}" + "}";
		// +"\"isStacked\": \"true\","

		// +"\"displayExactValues\": true,"
		//
		// +"\"hAxis\": { \"title\": \"Date\" }"
		// +"},"
		// logger.info("TrackRangeChart >>"+ valueChart+"<<");
		// String valueChartBar="{\"type\": \"BarChart\", \"displayed\": true,
		// \"data\": {\"cols\": [{ \"id\": \"perf\", \"label\": \"Perf\",
		// \"type\": \"string\" }, { \"id\": \"perfbase\", \"label\":
		// \"ValueBase\", \"type\": \"number\" },{ \"id\": \"perfvalue\",
		// \"label\": \"Value\", \"type\": \"number\" }], \"rows\": [{ \"c\": [
		// { \"v\": \"Write BonitaHome\" }, { \"v\": 550 }, { \"v\": 615 } ] },{
		// \"c\": [ { \"v\": \"Read BonitaHome\" }, { \"v\": 200 }, { \"v\": 246
		// } ] },{ \"c\": [ { \"v\": \"Read Medata\" }, { \"v\": 370 }, { \"v\":
		// 436 } ] },{ \"c\": [ { \"v\": \"Sql Request\" }, { \"v\": 190 }, {
		// \"v\": 213 } ] },{ \"c\": [ { \"v\": \"Deploy process\" }, { \"v\":
		// 40 }, { \"v\": 107 } ] },{ \"c\": [ { \"v\": \"Create 100 cases\" },
		// { \"v\": 3600 }, { \"v\": 16382 } ] },{ \"c\": [ { \"v\": \"Process
		// 100 cases\" }, { \"v\": 3700 }, { \"v\": 16469 } ] }]}, \"options\":
		// { \"bars\": \"horizontal\",\"title\": \"Performance Measure\",
		// \"fill\": 20, \"displayExactValues\": true,\"vAxis\": { \"title\":
		// \"ms\", \"gridlines\": { \"count\": 100 } }}}";

		return valueChart;
	}
	
	

}
