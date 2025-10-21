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

import com.sun.management.ThreadMXBean;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.adaptive.guard.AdaptiveGuardService;
import org.wso2.carbon.identity.application.authentication.framework.exception.AdaptiveScriptGuardException;

import java.lang.management.ManagementFactory;
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
    private GuardResult lastResult;
    private boolean started;
    private boolean finished;
    private boolean guardExceptionRaised;
    private ThreadMemoryMonitor memoryMonitor;
    private boolean memoryCaptured;
    private long memoryBytes;

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

    /**
     * Starts monitoring for the current execution.
     */
    public void start() {

        if (started) {
            return;
        }
        started = true;
        if (!enabled) {
            return;
        }
        memoryMonitor = ThreadMemoryMonitor.start();
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
        ensureStarted();
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
        ensureStarted();
        IdentityHashMap<Object, Boolean> visited = new IdentityHashMap<>();
        outputBytes = estimateValue(result, serializer, visited);
        if (maxOutputBytes > 0 && outputBytes > maxOutputBytes) {
            limitTriggered = true;
            guardExceptionRaised = true;
            throw new AdaptiveScriptGuardException(
                    "Adaptive authentication script output exceeded the configured limit");
        }
    }

    /**
     * Completes the execution and notifies the guard service.
     *
     * @param guardBreach {@code true} if the execution was terminated due to a guard violation.
     * @return Result describing whether the login should be blocked and if the output limit was breached.
     */
    public GuardResult finish(boolean guardBreach) {

        if (finished) {
            return lastResult != null ? lastResult : new GuardResult(false, guardExceptionRaised);
        }
        boolean shouldBlock = limitTriggered || guardBreach;
        boolean guardException = guardBreach || guardExceptionRaised;
        if (enabled) {
            long consumedMemory = captureMemory();
            boolean blocked = guardService.onFinish(organisationId, inputBytes, outputBytes, consumedMemory, shouldBlock);
            shouldBlock = shouldBlock || blocked;
        }
        GuardResult result = new GuardResult(shouldBlock, guardException);
        lastResult = result;
        finished = true;
        return result;
    }

    private void ensureStarted() {

        if (!started) {
            start();
        }
    }

    private long captureMemory() {

        if (memoryCaptured) {
            return memoryBytes;
        }
        memoryCaptured = true;
        if (memoryMonitor == null) {
            memoryBytes = 0L;
            return 0L;
        }
        long consumed = memoryMonitor.finish();
        memoryBytes = consumed;
        return consumed;
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
            return value.toString().getBytes(StandardCharsets.UTF_8).length;
        } finally {
            visited.remove(value);
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
        private final boolean guardExceptionRaised;

        private GuardResult(boolean blockLogin, boolean guardExceptionRaised) {

            this.blockLogin = blockLogin;
            this.guardExceptionRaised = guardExceptionRaised;
        }

        public boolean shouldBlockLogin() {

            return blockLogin;
        }

        public boolean wasGuardExceptionRaised() {

            return guardExceptionRaised;
        }
    }

    /**
     * Captures thread allocated memory for the duration of the script execution.
     */
    private static final class ThreadMemoryMonitor {

        private final ThreadMXBean threadMXBean;
        private final long threadId;
        private final long startBytes;
        private final boolean supported;

        private ThreadMemoryMonitor(ThreadMXBean threadMXBean, long threadId, long startBytes, boolean supported) {

            this.threadMXBean = threadMXBean;
            this.threadId = threadId;
            this.startBytes = startBytes;
            this.supported = supported;
        }

        static ThreadMemoryMonitor start() {

            java.lang.management.ThreadMXBean baseMxBean = ManagementFactory.getThreadMXBean();
            if (!(baseMxBean instanceof ThreadMXBean)) {
                return new ThreadMemoryMonitor(null, -1L, 0L, false);
            }
            ThreadMXBean threadMXBean = (ThreadMXBean) baseMxBean;
            if (!threadMXBean.isThreadAllocatedMemorySupported()) {
                return new ThreadMemoryMonitor(null, -1L, 0L, false);
            }
            try {
                if (!threadMXBean.isThreadAllocatedMemoryEnabled()) {
                    threadMXBean.setThreadAllocatedMemoryEnabled(true);
                }
            } catch (UnsupportedOperationException | SecurityException e) {
                return new ThreadMemoryMonitor(null, -1L, 0L, false);
            }
            long threadId = Thread.currentThread().getId();
            long start = threadMXBean.getThreadAllocatedBytes(threadId);
            if (start < 0) {
                start = 0L;
            }
            return new ThreadMemoryMonitor(threadMXBean, threadId, start, true);
        }

        long finish() {

            if (!supported || threadMXBean == null) {
                return 0L;
            }
            long current = threadMXBean.getThreadAllocatedBytes(threadId);
            if (current < 0) {
                return 0L;
            }
            long delta = current - startBytes;
            return delta > 0 ? delta : 0L;
        }
    }
}
