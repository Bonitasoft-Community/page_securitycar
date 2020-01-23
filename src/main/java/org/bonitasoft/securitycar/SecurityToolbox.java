package org.bonitasoft.securitycar;

import java.util.Map;

public class SecurityToolbox {

	/**
	 * @param mapRequestMultipart
	 * @param paramName
	 * @param defaultValue
	 * @return
	 */
	public static Integer getInteger(final Map<String, Object> mapRequestMultipart, final String paramName, final Integer defaultValue) {
		final Object value = mapRequestMultipart.get(paramName);
		if (value == null) {
			return defaultValue;
		}
		if (value instanceof Integer) {
			return (Integer) value;
		}
		try {
			return Integer.valueOf(value.toString());
		} catch (final Exception e) {
			return defaultValue;
		}
	}

	public static Integer getInteger(Object value, final Integer defaultValue) {
		if (value == null) {
			return defaultValue;
		}
		if (value instanceof Integer) {
			return (Integer) value;
		}
		try {
			return Integer.valueOf(value.toString());
		} catch (final Exception e) {
			return defaultValue;
		}
	}

	/**
	 * @param mapRequestMultipart
	 * @param paramName
	 * @param defaultValue
	 * @return
	 */
	public static String getString(final Map<String, Object> mapRequestMultipart, final String paramName, final String defaultValue) {
		final Object value = mapRequestMultipart.get(paramName);
		if (value == null) {
			return defaultValue;
		}
		return value.toString();
	}

	/**
	 * getLong
	 * 
	 * @param value
	 * @param defaultValue
	 * @return
	 */
	public static Long getLong(Object value, final Long defaultValue) {
		if (value == null) {
			return defaultValue;
		}
		if (value instanceof Long) {
			return (Long) value;
		}
		try {
			return Long.valueOf(value.toString());
		} catch (final Exception e) {
			return defaultValue;
		}
	}
}
