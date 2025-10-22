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

package org.wso2.carbon.identity.adaptive.guard.internal;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.adaptive.guard.AdaptiveGuardService;
import org.wso2.carbon.identity.adaptive.guard.internal.config.GuardConfig;

/**
 * Default implementation of {@link AdaptiveGuardService}.
 */
public class AdaptiveGuardServiceImpl implements AdaptiveGuardService {

    private static final Log LOG = LogFactory.getLog(AdaptiveGuardServiceImpl.class);
    private static final long WINDOW_MILLIS = 60_000L;

    private final GuardConfig config;
    private final ScriptMonitor monitor;

    public AdaptiveGuardServiceImpl() {

        this(new GuardConfig());
    }

    public AdaptiveGuardServiceImpl(GuardConfig config) {

        this.config = config;
        this.monitor = new ScriptMonitor(WINDOW_MILLIS, config.getBytesBudget(), config.getBreachBudget());
    }

    @Override
    public boolean isEnabled() {

        return config.isEnabled();
    }

    @Override
    public long getScriptTimeoutMillis() {

        return config.getScriptTimeoutMillis();
    }

    @Override
    public int getMaxScriptInputKb() {

        return config.getMaxScriptInputKb();
    }

    @Override
    public int getMaxScriptOutputKb() {

        return config.getMaxScriptOutputKb();
    }

    @Override
    public boolean onFinish(String orgId, long inputBytes, long outputBytes, long memoryBytes, boolean limitBreached) {

        if (!config.isEnabled()) {
            return limitBreached;
        }
        if (StringUtils.isBlank(orgId)) {
            return limitBreached;
        }
        long totalBytes = safeAdd(inputBytes, outputBytes, memoryBytes);
        boolean tripped = monitor.register(orgId, totalBytes, limitBreached ? 1 : 0);
        boolean shouldBlock = limitBreached || tripped;
        if (shouldBlock && LOG.isWarnEnabled()) {
            LOG.warn(String.format("Adaptive guard blocked org: %s (bytes=%d, breach=%s)", orgId,
                    totalBytes, limitBreached));
        }
        return shouldBlock;
    }

    private long safeAdd(long... values) {

        long total = 0L;
        for (long value : values) {
            if (value <= 0) {
                continue;
            }
            if (Long.MAX_VALUE - total < value) {
                total = Long.MAX_VALUE;
            } else {
                total += value;
            }
        }
        return total;
    }

    public GuardConfig getConfig() {

        return config;
    }
}
