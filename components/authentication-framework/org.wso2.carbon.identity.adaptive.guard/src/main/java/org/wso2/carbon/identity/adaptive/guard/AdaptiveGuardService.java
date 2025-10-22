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

package org.wso2.carbon.identity.adaptive.guard;

/**
 * Adaptive guard service contract. Provides guard rails for adaptive authentication scripts.
 */
public interface AdaptiveGuardService {

    /**
     * Indicates whether the adaptive guard is enabled in the deployment configuration.
     *
     * @return {@code true} if guard functionality is enabled.
     */
    boolean isEnabled();

    /**
     * Returns the script timeout configured for the guard.
     *
     * @return Timeout in milliseconds.
     */
    long getScriptTimeoutMillis();

    int getMaxScriptInputKb();

    int getMaxScriptOutputKb();

    /**
     * Notify the guard about an execution completion.
     *
     * @param orgId           Organisation identifier.
     * @param inputBytes      Number of input bytes processed by the script execution.
     * @param outputBytes     Number of output bytes produced by the script execution.
     * @param memoryBytes     Approximate memory allocated/consumed during execution.
     * @param limitBreached   {@code true} if the execution breached a limit.
     * @return {@code true} if the tenant should have the login flow blocked.
     */
    boolean onFinish(String orgId, long inputBytes, long outputBytes, long memoryBytes, boolean limitBreached);
}
