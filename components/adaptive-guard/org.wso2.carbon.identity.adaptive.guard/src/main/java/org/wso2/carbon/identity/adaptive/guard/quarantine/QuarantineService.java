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

package org.wso2.carbon.identity.adaptive.guard.quarantine;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory quarantine registry. This implementation intentionally keeps the logic simple so it can be
 * replaced by a cluster-aware implementation in the future without touching the public contract.
 */
public class QuarantineService {

    private final Map<String, Long> quarantined = new ConcurrentHashMap<>();

    public boolean isQuarantined(String organizationId) {

        if (organizationId == null) {
            return false;
        }
        Long until = quarantined.get(organizationId);
        if (until == null) {
            return false;
        }
        long now = System.currentTimeMillis();
        if (until > now) {
            return true;
        }
        quarantined.remove(organizationId, until);
        return false;
    }

    public void quarantine(String organizationId, long durationMillis) {

        if (organizationId == null || durationMillis <= 0) {
            return;
        }
        long until = System.currentTimeMillis() + durationMillis;
        quarantined.put(organizationId, until);
    }
}
