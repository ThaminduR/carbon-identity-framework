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

package org.wso2.carbon.identity.adaptive.guard;

import org.wso2.carbon.identity.adaptive.guard.http.BoundedHttpClient;

/**
 * Public contract exposed by the adaptive guard bundle.
 */
public interface AdaptiveGuardService {

    /**
     * Check whether the guard is globally enabled.
     *
     * @return {@code true} when enforcement is active.
     */
    boolean isEnabled();

    /**
     * Reports whether the provided organization is currently quarantined.
     *
     * @param organizationId Organization/tenant identifier.
     * @return {@code true} if logins for the organization must bypass or block adaptive scripts.
     */
    boolean isQuarantined(String organizationId);

    /**
     * Retrieve the configured quarantine handling mode.
     *
     * @return Guard mode to apply for quarantined organizations.
     */
    GuardMode getQuarantineMode();

    /**
     * Create a bounded HTTP client instance for the provided organization.
     *
     * @param organizationId Organization identifier.
     * @return Guard-aware HTTP client wrapper.
     */
    BoundedHttpClient getBoundedHttpClient(String organizationId);

    /**
     * Report end-of-execution statistics to the guard.
     *
     * @param organizationId Organization identifier.
     * @param inputBytes     Bytes consumed as script input payloads.
     * @param httpBytesIn    Bytes consumed through HTTP calls executed by the script.
     * @param outputBytes    Bytes produced by the script output.
     * @param allocatedBytes Estimated allocated bytes (0 if unsupported).
     * @param limitBreaches  Number of limit breaches encountered during execution.
     */
    void onFinish(String organizationId, long inputBytes, long httpBytesIn, long outputBytes,
                  long allocatedBytes, int limitBreaches);
}
