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

import org.testng.annotations.Test;
import org.wso2.carbon.identity.adaptive.guard.internal.ScriptMonitor;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for {@link ScriptMonitor}.
 */
public class ScriptMonitorTest {

    @Test
    public void testRegisterWithinBudget() {

        ScriptMonitor monitor = new ScriptMonitor(60_000L, 1000L, 5);
        assertFalse(monitor.register("org", 100L, 0));
        assertFalse(monitor.register("org", 200L, 0));
    }

    @Test
    public void testRegisterBytesBudgetExceeded() {

        ScriptMonitor monitor = new ScriptMonitor(60_000L, 100L, 5);
        assertTrue(monitor.register("org", 50L, 0));
    }

    @Test
    public void testRegisterBreachBudgetExceeded() {

        ScriptMonitor monitor = new ScriptMonitor(60_000L, 10_000L, 2);
        assertFalse(monitor.register("org", 10L, 1));
        assertTrue(monitor.register("org", 10L, 1));
    }
}
