/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.adaptive.guard.config;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.adaptive.guard.GuardMode;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.Locale;

/**
 * Helper that reads the adaptive guard configuration from deployment descriptors.
 */
public class AdaptiveGuardConfigLoader {

    private static final Log LOG = LogFactory.getLog(AdaptiveGuardConfigLoader.class);

    private static final String CONFIG_PREFIX = "authentication.adaptive.guard.";
    private static final String ENABLED = CONFIG_PREFIX + "enabled";
    private static final String MODE = CONFIG_PREFIX + "mode";
    private static final String WINDOW_SECONDS = CONFIG_PREFIX + "window_seconds";
    private static final String BYTES_BUDGET = CONFIG_PREFIX + "bytes_budget_60s";
    private static final String BREACH_BUDGET = CONFIG_PREFIX + "breach_budget_60s";
    private static final String COOL_OFF_SECONDS = CONFIG_PREFIX + "cool_off_seconds";
    private static final String SCRIPT_TIMEOUT_MS = CONFIG_PREFIX + "script_timeout_ms";
    private static final String MAX_HTTP_BODY_KB = CONFIG_PREFIX + "max_http_body_kb";
    private static final String MAX_SCRIPT_INPUT_KB = CONFIG_PREFIX + "max_script_input_kb";
    private static final String MAX_SCRIPT_OUTPUT_KB = CONFIG_PREFIX + "max_script_output_kb";
    private static final String HTTP_CONNECT_TIMEOUT_MS = CONFIG_PREFIX + "http_connect_timeout_ms";
    private static final String HTTP_READ_TIMEOUT_MS = CONFIG_PREFIX + "http_read_timeout_ms";

    private static final boolean DEFAULT_ENABLED = false;
    private static final long DEFAULT_WINDOW_MILLIS = 60_000L;
    private static final long DEFAULT_BYTES_BUDGET = 134_217_728L; // 128 MiB
    private static final int DEFAULT_BREACH_BUDGET = 5;
    private static final long DEFAULT_COOL_OFF_MILLIS = 180_000L;
    private static final long DEFAULT_SCRIPT_TIMEOUT_MILLIS = 750L;
    private static final long DEFAULT_HTTP_BODY_BYTES = 131_072L; // 128 KiB
    private static final long DEFAULT_SCRIPT_INPUT_BYTES = 32_768L;
    private static final long DEFAULT_SCRIPT_OUTPUT_BYTES = 32_768L;
    private static final long DEFAULT_HTTP_CONNECT_TIMEOUT_MILLIS = 400L;
    private static final long DEFAULT_HTTP_READ_TIMEOUT_MILLIS = 400L;

    private AdaptiveGuardConfigLoader() {

    }

    public static AdaptiveGuardConfig load() {

        boolean enabled = Boolean.parseBoolean(readProperty(ENABLED, String.valueOf(DEFAULT_ENABLED)));
        GuardMode mode = parseMode(readProperty(MODE, GuardMode.SKIP_SCRIPT.name()));
        long windowMillis = parseDurationMillis(readProperty(WINDOW_SECONDS, null), DEFAULT_WINDOW_MILLIS);
        long bytesBudget = parseSizeBytes(readProperty(BYTES_BUDGET, null), DEFAULT_BYTES_BUDGET);
        int breachBudget = parseInteger(readProperty(BREACH_BUDGET, null), DEFAULT_BREACH_BUDGET);
        long coolOffMillis = parseDurationMillis(readProperty(COOL_OFF_SECONDS, null), DEFAULT_COOL_OFF_MILLIS);
        long scriptTimeout = parseDurationMillis(readProperty(SCRIPT_TIMEOUT_MS, null), DEFAULT_SCRIPT_TIMEOUT_MILLIS);
        long maxHttpBody = parseSizeBytes(readProperty(MAX_HTTP_BODY_KB, null), DEFAULT_HTTP_BODY_BYTES);
        long maxScriptInput = parseSizeBytes(readProperty(MAX_SCRIPT_INPUT_KB, null), DEFAULT_SCRIPT_INPUT_BYTES);
        long maxScriptOutput = parseSizeBytes(readProperty(MAX_SCRIPT_OUTPUT_KB, null), DEFAULT_SCRIPT_OUTPUT_BYTES);
        long httpConnectTimeout = parseDurationMillis(readProperty(HTTP_CONNECT_TIMEOUT_MS, null),
                DEFAULT_HTTP_CONNECT_TIMEOUT_MILLIS);
        long httpReadTimeout = parseDurationMillis(readProperty(HTTP_READ_TIMEOUT_MS, null),
                DEFAULT_HTTP_READ_TIMEOUT_MILLIS);

        return new AdaptiveGuardConfig(enabled, mode, windowMillis, bytesBudget, breachBudget, coolOffMillis,
                scriptTimeout, maxHttpBody, maxScriptInput, maxScriptOutput, httpConnectTimeout, httpReadTimeout);
    }

    private static String readProperty(String key, String defaultValue) {

        String value = IdentityUtil.getProperty(key);
        if (StringUtils.isBlank(value)) {
            return defaultValue;
        }
        return value.trim();
    }

    private static GuardMode parseMode(String value) {

        if (StringUtils.isBlank(value)) {
            return GuardMode.SKIP_SCRIPT;
        }
        try {
            return GuardMode.valueOf(value.trim().toUpperCase(Locale.ENGLISH));
        } catch (IllegalArgumentException e) {
            LOG.warn("Unsupported adaptive guard mode '" + value + "'. Falling back to SKIP_SCRIPT.");
            return GuardMode.SKIP_SCRIPT;
        }
    }

    private static int parseInteger(String raw, int defaultValue) {

        if (StringUtils.isBlank(raw)) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            LOG.warn("Invalid integer value '" + raw + "' for adaptive guard configuration. Using default "
                    + defaultValue + '.', e);
            return defaultValue;
        }
    }

    private static long parseDurationMillis(String raw, long defaultValue) {

        if (StringUtils.isBlank(raw)) {
            return defaultValue;
        }
        String value = raw.trim().toLowerCase(Locale.ENGLISH);
        try {
            if (value.endsWith("ms")) {
                return Long.parseLong(value.substring(0, value.length() - 2));
            } else if (value.endsWith("s")) {
                long seconds = Long.parseLong(value.substring(0, value.length() - 1));
                return seconds * 1000L;
            } else {
                return Long.parseLong(value);
            }
        } catch (NumberFormatException e) {
            LOG.warn("Invalid duration value '" + raw + "' for adaptive guard configuration. Using default "
                    + defaultValue + '.', e);
            return defaultValue;
        }
    }

    private static long parseSizeBytes(String raw, long defaultValue) {

        if (StringUtils.isBlank(raw)) {
            return defaultValue;
        }
        String value = raw.trim().toLowerCase(Locale.ENGLISH);
        try {
            if (value.endsWith("kb")) {
                long number = Long.parseLong(value.substring(0, value.length() - 2));
                return number * 1024L;
            } else if (value.endsWith("mb")) {
                long number = Long.parseLong(value.substring(0, value.length() - 2));
                return number * 1024L * 1024L;
            } else if (value.endsWith("gb")) {
                long number = Long.parseLong(value.substring(0, value.length() - 2));
                return number * 1024L * 1024L * 1024L;
            } else if (value.endsWith("b")) {
                long number = Long.parseLong(value.substring(0, value.length() - 1));
                return number;
            } else {
                return Long.parseLong(value);
            }
        } catch (NumberFormatException e) {
            LOG.warn("Invalid byte-size value '" + raw + "' for adaptive guard configuration. Using default "
                    + defaultValue + '.', e);
            return defaultValue;
        }
    }
}
