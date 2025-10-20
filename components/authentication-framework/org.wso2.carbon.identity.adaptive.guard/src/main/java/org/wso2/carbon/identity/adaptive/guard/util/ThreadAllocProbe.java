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

package org.wso2.carbon.identity.adaptive.guard.util;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;

/**
 * Utility to measure thread allocated bytes when supported by the runtime.
 */
public class ThreadAllocProbe {

    private static final ThreadMXBean THREAD_MX_BEAN = ManagementFactory.getThreadMXBean();
    private static final boolean SUPPORTED = THREAD_MX_BEAN.isThreadAllocatedMemorySupported();

    private ThreadAllocProbe() {

    }

    public static long snapshot() {

        if (!SUPPORTED) {
            return 0L;
        }
        if (!THREAD_MX_BEAN.isThreadAllocatedMemoryEnabled()) {
            THREAD_MX_BEAN.setThreadAllocatedMemoryEnabled(true);
        }
        return THREAD_MX_BEAN.getThreadAllocatedBytes(Thread.currentThread().getId());
    }

    public static long delta(long start) {

        if (!SUPPORTED || start <= 0) {
            return 0L;
        }
        long now = THREAD_MX_BEAN.getThreadAllocatedBytes(Thread.currentThread().getId());
        if (now < 0) {
            return 0L;
        }
        return Math.max(now - start, 0L);
    }
}
