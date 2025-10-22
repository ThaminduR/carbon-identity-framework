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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;

/**
 * Loads guard configuration from deployment.toml and provides defaults.
 */
public class GuardConfig {

    private static final Log LOG = LogFactory.getLog(GuardConfig.class);
    private static final String CONFIG_ROOT = "authentication.adaptive.guard";
    private static final String CONFIG_ENABLED = CONFIG_ROOT + ".enabled";
    private static final String CONFIG_BYTES_BUDGET = CONFIG_ROOT + ".bytes_budget_60s";
    private static final String CONFIG_BREACH_BUDGET = CONFIG_ROOT + ".breach_budget_60s";
    private static final String CONFIG_TIMEOUT = CONFIG_ROOT + ".script_timeout_ms";
    private static final String CONFIG_INPUT = CONFIG_ROOT + ".max_script_input_kb";
    private static final String CONFIG_OUTPUT = CONFIG_ROOT + ".max_script_output_kb";

    private final boolean enabled;
    private final long bytesBudget;
    private final int breachBudget;
    private final long scriptTimeoutMillis;
    private final int maxScriptInputKb;
    private final int maxScriptOutputKb;

    public GuardConfig() {

        enabled = Boolean.parseBoolean(read(CONFIG_ENABLED, "true"));
        bytesBudget = parseSize(read(CONFIG_BYTES_BUDGET, "134217728"));
        breachBudget = (int) parseLong(read(CONFIG_BREACH_BUDGET, "5"));
        scriptTimeoutMillis = parseLong(read(CONFIG_TIMEOUT, "750"));
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

    public long getBytesBudget() {

        return bytesBudget;
    }

    public int getBreachBudget() {

        return breachBudget;
    }

    public long getScriptTimeoutMillis() {

        return scriptTimeoutMillis;
    }

    public int getMaxScriptInputKb() {

        return maxScriptInputKb;
    }

    public int getMaxScriptOutputKb() {

        return maxScriptOutputKb;
    }
}
