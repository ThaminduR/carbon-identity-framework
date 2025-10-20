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

import org.wso2.carbon.identity.adaptive.guard.GuardMode;

/**
 * Immutable configuration model for the adaptive guard service.
 */
public class AdaptiveGuardConfig {

    private final boolean enabled;
    private final GuardMode mode;
    private final long windowMillis;
    private final long bytesBudget;
    private final int breachBudget;
    private final long coolOffMillis;
    private final long scriptTimeoutMillis;
    private final long maxHttpBodyBytes;
    private final long maxScriptInputBytes;
    private final long maxScriptOutputBytes;
    private final long httpConnectTimeoutMillis;
    private final long httpReadTimeoutMillis;

    public AdaptiveGuardConfig(boolean enabled, GuardMode mode, long windowMillis, long bytesBudget,
                               int breachBudget, long coolOffMillis, long scriptTimeoutMillis,
                               long maxHttpBodyBytes, long maxScriptInputBytes, long maxScriptOutputBytes,
                               long httpConnectTimeoutMillis, long httpReadTimeoutMillis) {

        this.enabled = enabled;
        this.mode = mode;
        this.windowMillis = windowMillis;
        this.bytesBudget = bytesBudget;
        this.breachBudget = breachBudget;
        this.coolOffMillis = coolOffMillis;
        this.scriptTimeoutMillis = scriptTimeoutMillis;
        this.maxHttpBodyBytes = maxHttpBodyBytes;
        this.maxScriptInputBytes = maxScriptInputBytes;
        this.maxScriptOutputBytes = maxScriptOutputBytes;
        this.httpConnectTimeoutMillis = httpConnectTimeoutMillis;
        this.httpReadTimeoutMillis = httpReadTimeoutMillis;
    }

    public boolean isEnabled() {

        return enabled;
    }

    public GuardMode getMode() {

        return mode;
    }

    public long getWindowMillis() {

        return windowMillis;
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

    public long getMaxHttpBodyBytes() {

        return maxHttpBodyBytes;
    }

    public long getMaxScriptInputBytes() {

        return maxScriptInputBytes;
    }

    public long getMaxScriptOutputBytes() {

        return maxScriptOutputBytes;
    }

    public long getHttpConnectTimeoutMillis() {

        return httpConnectTimeoutMillis;
    }

    public long getHttpReadTimeoutMillis() {

        return httpReadTimeoutMillis;
    }
}
