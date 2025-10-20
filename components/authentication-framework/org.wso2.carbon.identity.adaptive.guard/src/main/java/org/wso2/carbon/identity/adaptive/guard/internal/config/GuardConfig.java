/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.adaptive.guard.internal.config;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;

/**
 * Loads guard configuration from deployment.toml and provides defaults.
 */
public class GuardConfig {

    public enum QuarantineMode {
        SKIP_SCRIPT,
        BLOCK_LOGIN
    }

    private static final Log LOG = LogFactory.getLog(GuardConfig.class);
    private static final String CONFIG_ROOT = "authentication.adaptive.guard";
    private static final String CONFIG_ENABLED = CONFIG_ROOT + ".enabled";
    private static final String CONFIG_MODE = CONFIG_ROOT + ".mode";
    private static final String CONFIG_BYTES_BUDGET = CONFIG_ROOT + ".bytes_budget_60s";
    private static final String CONFIG_BREACH_BUDGET = CONFIG_ROOT + ".breach_budget_60s";
    private static final String CONFIG_COOL_OFF = CONFIG_ROOT + ".cool_off_seconds";
    private static final String CONFIG_TIMEOUT = CONFIG_ROOT + ".script_timeout_ms";
    private static final String CONFIG_HTTP_BODY = CONFIG_ROOT + ".max_http_body_kb";
    private static final String CONFIG_INPUT = CONFIG_ROOT + ".max_script_input_kb";
    private static final String CONFIG_OUTPUT = CONFIG_ROOT + ".max_script_output_kb";

    private final boolean enabled;
    private final QuarantineMode mode;
    private final long bytesBudget;
    private final int breachBudget;
    private final long coolOffMillis;
    private final long scriptTimeoutMillis;
    private final int maxHttpBodyKb;
    private final int maxScriptInputKb;
    private final int maxScriptOutputKb;

    public GuardConfig() {

        enabled = Boolean.parseBoolean(read(CONFIG_ENABLED, "true"));
        mode = parseMode(read(CONFIG_MODE, "skip_script"));
        bytesBudget = parseSize(read(CONFIG_BYTES_BUDGET, "134217728"));
        breachBudget = (int) parseLong(read(CONFIG_BREACH_BUDGET, "5"));
        coolOffMillis = parseLong(read(CONFIG_COOL_OFF, "180")) * 1000L;
        scriptTimeoutMillis = parseLong(read(CONFIG_TIMEOUT, "750"));
        maxHttpBodyKb = (int) parseLong(read(CONFIG_HTTP_BODY, "128"));
        maxScriptInputKb = (int) parseLong(read(CONFIG_INPUT, "32"));
        maxScriptOutputKb = (int) parseLong(read(CONFIG_OUTPUT, "32"));
    }

    private String read(String key, String defaultValue) {

        String value = IdentityUtil.getProperty(key);
        if (StringUtils.isBlank(value)) {
            return defaultValue;
        }
        return value;
    }

    private QuarantineMode parseMode(String value) {

        if (StringUtils.isBlank(value)) {
            return QuarantineMode.SKIP_SCRIPT;
        }
        switch (value.toLowerCase()) {
            case "block_login":
                return QuarantineMode.BLOCK_LOGIN;
            case "skip_script":
            default:
                if (!"skip_script".equalsIgnoreCase(value)) {
                    LOG.warn("Unknown adaptive guard mode '" + value + "'. Falling back to skip_script.");
                }
                return QuarantineMode.SKIP_SCRIPT;
        }
    }

    private long parseSize(String value) {

        if (StringUtils.isBlank(value)) {
            return 0L;
        }
        String trimmed = value.trim().toUpperCase();
        try {
            if (trimmed.endsWith("KB")) {
                return Long.parseLong(trimmed.substring(0, trimmed.length() - 2).trim()) * 1024L;
            } else if (trimmed.endsWith("MB")) {
                return Long.parseLong(trimmed.substring(0, trimmed.length() - 2).trim()) * 1024L * 1024L;
            }
            return Long.parseLong(trimmed);
        } catch (NumberFormatException e) {
            LOG.warn("Unable to parse size value '" + value + "'. Using zero.", e);
            return 0L;
        }
    }

    private long parseLong(String value) {

        if (StringUtils.isBlank(value)) {
            return 0L;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            LOG.warn("Unable to parse numeric value '" + value + "'. Using zero.", e);
            return 0L;
        }
    }

    public boolean isEnabled() {

        return enabled;
    }

    public QuarantineMode getMode() {

        return mode;
    }

    public long getBytesBudget() {

        return bytesBudget;
    }

    public int getBreachBudget() {

        return breachBudget;
    }

    public long getCoolOffMillis() {

        return coolOffMillis;
    }

    public long getScriptTimeoutMillis() {

        return scriptTimeoutMillis;
    }

    public int getMaxHttpBodyKb() {

        return maxHttpBodyKb;
    }

    public int getMaxScriptInputKb() {

        return maxScriptInputKb;
    }

    public int getMaxScriptOutputKb() {

        return maxScriptOutputKb;
    }
}
