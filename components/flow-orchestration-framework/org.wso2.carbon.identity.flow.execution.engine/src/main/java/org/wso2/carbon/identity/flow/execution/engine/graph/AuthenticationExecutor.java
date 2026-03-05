/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.flow.execution.engine.graph;

import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.mgt.model.ExecutorDTO;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.ErrorMessages.ERROR_CODE_GET_IDP_CONFIG_FAILURE;
import static org.wso2.carbon.identity.flow.execution.engine.util.FlowExecutionEngineUtils.handleServerException;
import static org.wso2.carbon.identity.flow.mgt.Constants.IDP_NAME;

/**
 * Abstract class representing an authentication executor in the flow execution engine.
 */
public abstract class AuthenticationExecutor implements Executor {

    /**
     * Get the AMR value of the authentication executor.
     *
     * @return AMR value of the authentication executor.
     */
    public abstract String getAMRValue();

    /**
     * Resolves Identity Provider configurations and populates authenticator properties in the context.
     * Executors that do not require an IDP (i.e. no {@code idpName} in metadata) are unaffected.
     *
     * @param context     Flow execution context.
     * @param executorDTO Executor configuration and metadata.
     * @throws FlowEngineException If an error occurs while retrieving the Identity Provider configuration.
     */
    @Override
    public void prepareContext(FlowExecutionContext context, ExecutorDTO executorDTO) throws FlowEngineException {

        Map<String, String> metadata = executorDTO.getMetadata();
        if (metadata == null || !metadata.containsKey(IDP_NAME)) {
            return;
        }
        String tenantDomain = context.getTenantDomain();
        String idpName = metadata.get(IDP_NAME);
        try {
            IdentityProvider idp =
                    IdentityProviderManager.getInstance().getIdPByName(idpName, tenantDomain);
            if (idp == null || idp.getId() == null || idp.getDefaultAuthenticatorConfig() == null) {
                throw handleServerException(context.getFlowType(), ERROR_CODE_GET_IDP_CONFIG_FAILURE, idpName,
                        tenantDomain);
            }
            FederatedAuthenticatorConfig authenticatorConfig = idp.getDefaultAuthenticatorConfig();
            Map<String, String> propertyMap = new HashMap<>();
            for (Property property : authenticatorConfig.getProperties()) {
                propertyMap.put(property.getName(), property.getValue());
            }
            context.setAuthenticatorProperties(propertyMap);
        } catch (IdentityProviderManagementException e) {
            throw handleServerException(context.getFlowType(), ERROR_CODE_GET_IDP_CONFIG_FAILURE, e, idpName,
                    tenantDomain);
        }
    }
}
