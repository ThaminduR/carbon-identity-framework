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

import org.wso2.carbon.identity.adaptive.guard.model.ExecutionSample;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Maintains per-organisation execution windows and determines when the guard should trip.
 */
public class ScriptMonitor {

    private final long windowMillis;
    private final long bytesBudget;
    private final int breachBudget;
    private final ConcurrentMap<String, Deque<ExecutionSample>> samples = new ConcurrentHashMap<>();

    public ScriptMonitor(long windowMillis, long bytesBudget, int breachBudget) {

        this.windowMillis = windowMillis;
        this.bytesBudget = bytesBudget;
        this.breachBudget = breachBudget;
    }

    /**
     * Register a new execution sample and determine whether the organisation should be quarantined.
     *
     * @param orgId Organisation identifier.
     * @param bytes Total bytes consumed by the execution.
     * @param breaches Limit breach count reported by the execution.
     * @return {@code true} if the window budgets have been exceeded.
     */
    public boolean register(String orgId, long bytes, int breaches) {

        long now = System.currentTimeMillis();
        Deque<ExecutionSample> deque = samples.computeIfAbsent(orgId, ignored -> new ArrayDeque<>());
        synchronized (deque) {
            deque.addLast(new ExecutionSample(now, bytes, breaches));
            trim(deque, now);
            long totalBytes = 0L;
            int totalBreaches = 0;
            for (ExecutionSample sample : deque) {
                totalBytes += sample.getBytes();
                totalBreaches += sample.getBreaches();
                if (bytesBudget > 0 && totalBytes > bytesBudget) {
                    return true;
                }
                if (breachBudget > 0 && totalBreaches >= breachBudget) {
                    return true;
                }
            }
            return false;
        }
    }

    private void trim(Deque<ExecutionSample> deque, long now) {

        while (!deque.isEmpty()) {
            ExecutionSample head = deque.peekFirst();
            if (head == null) {
                break;
            }
            if (now - head.getTimestamp() > windowMillis) {
                deque.removeFirst();
            } else {
                break;
            }
        }
    }

    /**
     * Clears the recorded samples for the provided organisation.
     *
     * @param orgId Organisation identifier.
     */
    public void clear(String orgId) {

        Deque<ExecutionSample> deque = samples.remove(orgId);
        if (deque != null) {
            synchronized (deque) {
                deque.clear();
            }
        }
    }
}
