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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.adaptive.guard.AdaptiveGuardService;
import org.wso2.carbon.identity.adaptive.guard.AdaptiveGuardService.QuarantineMode;
import org.wso2.carbon.identity.adaptive.guard.http.BoundedHttpClient;
import org.wso2.carbon.identity.adaptive.guard.http.BoundedHttpClientFactory;
import org.wso2.carbon.identity.adaptive.guard.internal.config.GuardConfig;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Default implementation of {@link AdaptiveGuardService}.
 */
public class AdaptiveGuardServiceImpl implements AdaptiveGuardService {

    private static final Log LOG = LogFactory.getLog(AdaptiveGuardServiceImpl.class);
    private static final long WINDOW_MILLIS = 60_000L;

    private final GuardConfig config;
    private final ScriptMonitor monitor;
    private final QuarantineService quarantineService;
    private final BoundedHttpClientFactory httpClientFactory;
    private final ConcurrentMap<String, BoundedHttpClient> httpClients = new ConcurrentHashMap<>();

    public AdaptiveGuardServiceImpl() {

        this(new GuardConfig());
    }

    public AdaptiveGuardServiceImpl(GuardConfig config) {

        this.config = config;
        this.monitor = new ScriptMonitor(WINDOW_MILLIS, config.getBytesBudget(), config.getBreachBudget());
        this.quarantineService = new QuarantineService();
        this.httpClientFactory = new BoundedHttpClientFactory(config.getMaxHttpBodyKb());
    }

    @Override
    public boolean isEnabled() {

        return config.isEnabled();
    }

    @Override
    public boolean isQuarantined(String orgId) {

        if (!config.isEnabled()) {
            return false;
        }
        return quarantineService.isQuarantined(orgId);
    }

    @Override
    public BoundedHttpClient getBoundedHttpClient(String orgId) {

        if (!config.isEnabled()) {
            return new BoundedHttpClientFactory(0).create(orgId);
        }
        return httpClients.compute(orgId, (key, existing) -> existing != null ? existing : httpClientFactory.create(key));
    }

    @Override
    public QuarantineMode getQuarantineMode() {

        return config.getMode() == GuardConfig.QuarantineMode.BLOCK_LOGIN ? QuarantineMode.BLOCK_LOGIN :
                QuarantineMode.SKIP_SCRIPT;
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
    public void onFinish(String orgId, long inputBytes, long httpBytesIn, long outputBytes, long allocatedBytes,
                         int limitBreaches) {

        if (!config.isEnabled()) {
            return;
        }
        long totalBytes = safeAdd(inputBytes, httpBytesIn, outputBytes, allocatedBytes);
        boolean tripped = monitor.register(orgId, totalBytes, limitBreaches);
        if (tripped) {
            quarantineService.quarantine(orgId, config.getCoolOffMillis());
            monitor.clear(orgId);
            httpClients.remove(orgId);
            if (LOG.isWarnEnabled()) {
                LOG.warn(String.format("Adaptive guard quarantined org: %s (bytes=%d, breaches=%d)", orgId,
                        totalBytes, limitBreaches));
            }
        }
        if (httpBytesIn <= 0) {
            return;
        }
        BoundedHttpClient client = httpClients.get(orgId);
        if (client != null) {
            try {
                client.registerBytes(httpBytesIn);
            } catch (IOException e) {
                LOG.debug("HTTP budget already recorded for organisation " + orgId, e);
            }
        }
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

    public QuarantineService getQuarantineService() {

        return quarantineService;
    }
}
