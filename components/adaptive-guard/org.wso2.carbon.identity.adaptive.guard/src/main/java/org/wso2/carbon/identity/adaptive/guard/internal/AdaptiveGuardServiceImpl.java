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

package org.wso2.carbon.identity.adaptive.guard.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.adaptive.guard.AdaptiveGuardService;
import org.wso2.carbon.identity.adaptive.guard.GuardMode;
import org.wso2.carbon.identity.adaptive.guard.config.AdaptiveGuardConfig;
import org.wso2.carbon.identity.adaptive.guard.config.AdaptiveGuardConfigLoader;
import org.wso2.carbon.identity.adaptive.guard.http.BoundedHttpClient;
import org.wso2.carbon.identity.adaptive.guard.monitor.ExecutionSample;
import org.wso2.carbon.identity.adaptive.guard.monitor.ScriptMonitor;
import org.wso2.carbon.identity.adaptive.guard.quarantine.QuarantineService;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Default implementation of {@link AdaptiveGuardService}.
 */
public class AdaptiveGuardServiceImpl implements AdaptiveGuardService {

    private static final Log LOG = LogFactory.getLog(AdaptiveGuardServiceImpl.class);

    private final AdaptiveGuardConfig config;
    private final ScriptMonitor monitor;
    private final QuarantineService quarantineService;

    public AdaptiveGuardServiceImpl() {

        this(AdaptiveGuardConfigLoader.load());
    }

    public AdaptiveGuardServiceImpl(AdaptiveGuardConfig config) {

        this.config = config;
        this.monitor = new ScriptMonitor(config.getWindowMillis(), config.getBytesBudget(),
                config.getBreachBudget());
        this.quarantineService = new QuarantineService();
        if (config.isEnabled()) {
            LOG.info("Adaptive guard service initialized with mode " + config.getMode());
        } else {
            LOG.info("Adaptive guard service initialized in disabled state.");
        }
    }

    @Override
    public boolean isEnabled() {

        return config.isEnabled();
    }

    @Override
    public boolean isQuarantined(String organizationId) {

        if (!config.isEnabled()) {
            return false;
        }
        return quarantineService.isQuarantined(organizationId);
    }

    @Override
    public GuardMode getQuarantineMode() {

        return config.getMode();
    }

    @Override
    public BoundedHttpClient getBoundedHttpClient(String organizationId) {

        if (!config.isEnabled()) {
            return BoundedHttpClient.noop();
        }
        return new SimpleBoundedHttpClient();
    }

    @Override
    public void onFinish(String organizationId, long inputBytes, long httpBytesIn, long outputBytes,
                         long allocatedBytes, int limitBreaches) {

        if (!config.isEnabled()) {
            return;
        }
        long totalBytes = safeSum(inputBytes, httpBytesIn, outputBytes, allocatedBytes);
        ExecutionSample sample = new ExecutionSample(System.currentTimeMillis(), totalBytes, limitBreaches);
        boolean tripped = monitor.record(organizationId, sample);
        if (tripped) {
            quarantineService.quarantine(organizationId, config.getCoolOffMillis());
            LOG.warn(String.format("Adaptive guard quarantined organization '%s' after breaching limits: "
                            + "totalBytes=%d, breaches=%d", organizationId, totalBytes, limitBreaches));
        }
    }

    private long safeSum(long... values) {

        long total = 0;
        for (long value : values) {
            if (value <= 0) {
                continue;
            }
            long tentative = total + value;
            if (tentative < total) {
                return Long.MAX_VALUE;
            }
            total = tentative;
        }
        return total;
    }

    private static final class SimpleBoundedHttpClient implements BoundedHttpClient {

        private final AtomicLong bytesIn = new AtomicLong();

        @Override
        public void recordBytesIn(long bytes) {

            if (bytes <= 0) {
                return;
            }
            bytesIn.addAndGet(bytes);
        }

        @Override
        public long getBytesIn() {

            return bytesIn.get();
        }

        @Override
        public void close() {

            // Nothing additional to do for the in-memory implementation.
        }
    }
}
