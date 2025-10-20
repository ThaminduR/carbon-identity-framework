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

package org.wso2.carbon.identity.adaptive.guard.monitor;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Maintains a rolling window of adaptive script executions and detects budget breaches.
 */
public class ScriptMonitor {

    private final Map<String, RollingWindow> state = new ConcurrentHashMap<>();
    private final long windowMillis;
    private final long bytesBudget;
    private final int breachBudget;

    public ScriptMonitor(long windowMillis, long bytesBudget, int breachBudget) {

        this.windowMillis = Math.max(windowMillis, 1L);
        this.bytesBudget = Math.max(bytesBudget, 0L);
        this.breachBudget = Math.max(breachBudget, 0);
    }

    /**
     * Record a new sample for the provided organization and determine whether the guard should trip.
     *
     * @param organizationId Organization identifier.
     * @param sample         Execution sample.
     * @return {@code true} if the rolling totals exceeded configured budgets.
     */
    public boolean record(String organizationId, ExecutionSample sample) {

        if (organizationId == null || sample == null) {
            return false;
        }
        RollingWindow window = state.computeIfAbsent(organizationId, key -> new RollingWindow());
        return window.add(sample, windowMillis, bytesBudget, breachBudget);
    }

    private static final class RollingWindow {

        private final Deque<ExecutionSample> samples = new ArrayDeque<>();
        private long totalBytes;
        private int totalBreaches;

        synchronized boolean add(ExecutionSample sample, long windowMillis, long bytesBudget, int breachBudget) {

            prune(windowMillis, sample.getTimestamp());
            samples.addLast(sample);
            totalBytes += sample.getTotalBytes();
            totalBreaches += sample.getLimitBreaches();
            boolean tripped = totalBytes > bytesBudget || totalBreaches >= breachBudget;
            if (tripped) {
                samples.clear();
                totalBytes = 0;
                totalBreaches = 0;
            }
            return tripped;
        }

        private void prune(long windowMillis, long now) {

            while (!samples.isEmpty()) {
                ExecutionSample oldest = samples.peekFirst();
                if (oldest == null) {
                    break;
                }
                if (now - oldest.getTimestamp() <= windowMillis) {
                    break;
                }
                samples.removeFirst();
                totalBytes -= oldest.getTotalBytes();
                totalBreaches -= oldest.getLimitBreaches();
            }
        }
    }
}
