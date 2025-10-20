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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.adaptive.guard.AdaptiveGuardService;
import org.wso2.carbon.identity.adaptive.guard.http.BoundedHttpClient;

/**
 * Declarative service component that exposes the adaptive guard.
 */
@Component(name = "org.wso2.carbon.identity.adaptive.guard", immediate = true, service = AdaptiveGuardService.class)
public class AdaptiveGuardComponent implements AdaptiveGuardService {

    private static final Log LOG = LogFactory.getLog(AdaptiveGuardComponent.class);
    private AdaptiveGuardServiceImpl adaptiveGuardService;

    @Activate
    protected void activate(ComponentContext ctx) {

        adaptiveGuardService = new AdaptiveGuardServiceImpl();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Adaptive guard component activated.");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctx) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Adaptive guard component deactivated.");
        }
    }

    @Override
    public boolean isEnabled() {

        return adaptiveGuardService.isEnabled();
    }

    @Override
    public boolean isQuarantined(String orgId) {

        return adaptiveGuardService.isQuarantined(orgId);
    }

    @Override
    public BoundedHttpClient getBoundedHttpClient(String orgId) {

        return adaptiveGuardService.getBoundedHttpClient(orgId);
    }

    @Override
    public QuarantineMode getQuarantineMode() {

        return adaptiveGuardService.getQuarantineMode();
    }

    @Override
    public long getScriptTimeoutMillis() {

        return adaptiveGuardService.getScriptTimeoutMillis();
    }

    @Override
    public int getMaxScriptInputKb() {

        return adaptiveGuardService.getMaxScriptInputKb();
    }

    @Override
    public int getMaxScriptOutputKb() {

        return adaptiveGuardService.getMaxScriptOutputKb();
    }

    @Override
    public void onFinish(String orgId, long inputBytes, long httpBytesIn, long outputBytes, long allocatedBytes,
                         int limitBreaches) {

        adaptiveGuardService.onFinish(orgId, inputBytes, httpBytesIn, outputBytes, allocatedBytes, limitBreaches);
    }
}
