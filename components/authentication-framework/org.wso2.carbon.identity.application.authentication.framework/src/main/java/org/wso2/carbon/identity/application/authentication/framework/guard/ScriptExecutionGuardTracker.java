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

package org.wso2.carbon.identity.application.authentication.framework.guard;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.adaptive.guard.AdaptiveGuardService;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JSExecutionMonitorData;
import org.wso2.carbon.identity.application.authentication.framework.exception.AdaptiveScriptGuardException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Collects basic metrics for adaptive script executions and notifies the adaptive guard service.
 */
public class ScriptExecutionGuardTracker {

    private final AdaptiveGuardService guardService;
    private final String organisationId;
    private final long maxInputBytes;
    private final long maxOutputBytes;
    private final boolean enabled;

    private long inputBytes;
    private long outputBytes;
    private boolean limitTriggered;
    private boolean outputLimitBreached;
    private GuardResult lastResult;
    private boolean finished;
    private boolean guardExceptionRaised;

    private ScriptExecutionGuardTracker(AdaptiveGuardService guardService, String organisationId,
                                        int maxInputKb, int maxOutputKb) {

        this.guardService = guardService;
        this.organisationId = organisationId;
        this.enabled = guardService != null && guardService.isEnabled() && StringUtils.isNotBlank(organisationId);
        this.maxInputBytes = toBytes(maxInputKb);
        this.maxOutputBytes = toBytes(maxOutputKb);
    }

    public static ScriptExecutionGuardTracker create(AdaptiveGuardService guardService, String organisationId) {

        int maxInput = guardService != null ? guardService.getMaxScriptInputKb() : 0;
        int maxOutput = guardService != null ? guardService.getMaxScriptOutputKb() : 0;
        return new ScriptExecutionGuardTracker(guardService, organisationId, maxInput, maxOutput);
    }

    private long toBytes(int kilobytes) {

        return kilobytes <= 0 ? 0L : kilobytes * 1024L;
    }

    /**
     * Records the input payload that will be supplied to the script execution.
     *
     * @param params     Parameters passed to the script invocation.
     * @param serializer Serializer used to convert values into serializable representations.
     */
    public void recordInput(Object[] params, Function<Object, Object> serializer) {

        if (!enabled || finished) {
            return;
        }
        IdentityHashMap<Object, Boolean> visited = new IdentityHashMap<>();
        inputBytes = estimateAggregate(params, serializer, visited);
        if (maxInputBytes > 0 && inputBytes > maxInputBytes) {
            limitTriggered = true;
            guardExceptionRaised = true;
            throw new AdaptiveScriptGuardException(
                    "Adaptive authentication script input exceeded the configured limit");
        }
    }

    /**
     * Records the script output prior to notifying the guard.
     *
     * @param result     The result returned from the script.
     * @param serializer Serializer used to convert values into serializable representations.
     */
    public void recordOutputCandidate(Object result, Function<Object, Object> serializer) {

        if (!enabled || finished) {
            return;
        }
        IdentityHashMap<Object, Boolean> visited = new IdentityHashMap<>();
        outputBytes = estimateValue(result, serializer, visited);
        if (maxOutputBytes > 0 && outputBytes > maxOutputBytes) {
            outputLimitBreached = true;
            limitTriggered = true;
        }
    }

    /**
     * Completes the execution and notifies the guard service.
     *
     * @param scriptSucceeded {@code true} if the script completed successfully.
     * @param guardBreach     {@code true} if the execution was terminated due to a guard violation.
     * @param monitorData     Data returned from the legacy execution supervisor; used for memory metrics.
     * @return Result describing whether the login should be blocked and if the output limit was breached.
     */
    public GuardResult finish(boolean scriptSucceeded, boolean guardBreach, JSExecutionMonitorData monitorData) {

        if (finished) {
            return lastResult != null ? lastResult : new GuardResult(false, false, guardExceptionRaised);
        }
        boolean outputBreach = scriptSucceeded && outputLimitBreached;
        boolean shouldBlock = limitTriggered || guardBreach;
        boolean guardException = guardBreach || guardExceptionRaised;
        if (enabled) {
            long memoryBytes = monitorData != null ? monitorData.getConsumedMemory() : 0L;
            boolean blocked = guardService.onFinish(organisationId, inputBytes, outputBytes, memoryBytes, shouldBlock);
            shouldBlock = shouldBlock || blocked;
        }
        GuardResult result = new GuardResult(shouldBlock, outputBreach, guardException);
        lastResult = result;
        finished = true;
        return result;
    }

    private long estimateAggregate(Object[] values, Function<Object, Object> serializer,
                                   IdentityHashMap<Object, Boolean> visited) {

        if (values == null || values.length == 0) {
            return 0L;
        }
        long total = 0L;
        for (Object value : values) {
            total = safeAdd(total, estimateValue(value, serializer, visited));
            if (maxInputBytes > 0 && total > maxInputBytes) {
                return total;
            }
        }
        return total;
    }

    private long estimateValue(Object value, Function<Object, Object> serializer,
                               IdentityHashMap<Object, Boolean> visited) {

        Object serialized = serializer != null ? serializer.apply(value) : value;
        return estimateSerialized(serialized, visited);
    }

    private long estimateSerialized(Object value, IdentityHashMap<Object, Boolean> visited) {

        if (value == null) {
            return 0L;
        }
        if (visited.containsKey(value)) {
            return 0L;
        }
        visited.put(value, Boolean.TRUE);
        try {
            if (value instanceof byte[]) {
                return ((byte[]) value).length;
            }
            if (value instanceof CharSequence) {
                return ((CharSequence) value).toString().getBytes(StandardCharsets.UTF_8).length;
            }
            if (value instanceof Number || value instanceof Boolean) {
                return value.toString().getBytes(StandardCharsets.UTF_8).length;
            }
            if (value instanceof Map<?, ?>) {
                long total = 0L;
                for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                    total = safeAdd(total, estimateSerialized(entry.getKey(), visited));
                    total = safeAdd(total, estimateSerialized(entry.getValue(), visited));
                }
                return total;
            }
            if (value instanceof Iterable<?>) {
                long total = 0L;
                for (Object element : (Iterable<?>) value) {
                    total = safeAdd(total, estimateSerialized(element, visited));
                }
                return total;
            }
            Class<?> type = value.getClass();
            if (type.isArray()) {
                long total = 0L;
                int length = Array.getLength(value);
                for (int i = 0; i < length; i++) {
                    total = safeAdd(total, estimateSerialized(Array.get(value, i), visited));
                }
                return total;
            }
            if (value instanceof Serializable) {
                return serializedSize((Serializable) value);
            }
            return value.toString().getBytes(StandardCharsets.UTF_8).length;
        } finally {
            visited.remove(value);
        }
    }

    private long serializedSize(Serializable value) {

        try (ByteArrayOutputStream out = new ByteArrayOutputStream();
             ObjectOutputStream objectOutputStream = new ObjectOutputStream(out)) {
            objectOutputStream.writeObject(value);
            return out.size();
        } catch (IOException e) {
            return value.toString().getBytes(StandardCharsets.UTF_8).length;
        }
    }

    private long safeAdd(long current, long increment) {

        long result = current + increment;
        if (result < 0 || result < current) {
            return Long.MAX_VALUE;
        }
        return result;
    }

    /**
     * Outcome returned after finishing a guard tracked execution.
     */
    public static final class GuardResult {

        private final boolean blockLogin;
        private final boolean outputLimitBreached;
        private final boolean guardExceptionRaised;

        private GuardResult(boolean blockLogin, boolean outputLimitBreached, boolean guardExceptionRaised) {

            this.blockLogin = blockLogin;
            this.outputLimitBreached = outputLimitBreached;
            this.guardExceptionRaised = guardExceptionRaised;
        }

        public boolean shouldBlockLogin() {

            return blockLogin;
        }

        public boolean isOutputLimitBreached() {

            return outputLimitBreached;
        }

        public boolean wasGuardExceptionRaised() {

            return guardExceptionRaised;
        }
    }
}
