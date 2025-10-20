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

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory quarantine service that keeps track of organisations that have tripped the guard.
 */
public class QuarantineService {

    private final ConcurrentMap<String, Long> quarantined = new ConcurrentHashMap<>();

    public boolean isQuarantined(String orgId) {

        Long until = quarantined.get(orgId);
        if (until == null) {
            return false;
        }
        if (System.currentTimeMillis() > until) {
            quarantined.remove(orgId, until);
            return false;
        }
        return true;
    }

    public void quarantine(String orgId, long durationMillis) {

        quarantined.put(orgId, System.currentTimeMillis() + durationMillis);
    }

    public long getRemaining(String orgId) {

        Long until = quarantined.get(orgId);
        if (until == null) {
            return 0L;
        }
        long remaining = until - System.currentTimeMillis();
        return Math.max(remaining, 0L);
    }
}
