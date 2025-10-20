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

/**
 * Immutable record that captures a single adaptive execution sample.
 */
public class ExecutionSample {

    private final long timestamp;
    private final long totalBytes;
    private final int limitBreaches;

    public ExecutionSample(long timestamp, long totalBytes, int limitBreaches) {

        this.timestamp = timestamp;
        this.totalBytes = Math.max(totalBytes, 0L);
        this.limitBreaches = Math.max(limitBreaches, 0);
    }

    public long getTimestamp() {

        return timestamp;
    }

    public long getTotalBytes() {

        return totalBytes;
    }

    public int getLimitBreaches() {

        return limitBreaches;
    }
}
