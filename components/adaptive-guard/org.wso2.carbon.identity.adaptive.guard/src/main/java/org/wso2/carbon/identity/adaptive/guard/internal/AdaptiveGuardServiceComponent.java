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

package org.wso2.carbon.identity.adaptive.guard.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.adaptive.guard.AdaptiveGuardService;

/**
 * Declarative services component responsible for registering the adaptive guard service.
 */
@Component(name = "org.wso2.carbon.identity.adaptive.guard", immediate = true)
public class AdaptiveGuardServiceComponent {

    private static final Log LOG = LogFactory.getLog(AdaptiveGuardServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        BundleContext bundleContext = context.getBundleContext();
        AdaptiveGuardService service = new AdaptiveGuardServiceImpl();
        bundleContext.registerService(AdaptiveGuardService.class, service, null);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Adaptive guard service registered");
        }
    }
}
