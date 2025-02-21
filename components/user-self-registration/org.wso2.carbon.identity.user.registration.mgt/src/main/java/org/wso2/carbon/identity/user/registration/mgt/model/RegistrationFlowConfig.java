/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
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
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.user.registration.mgt.model;

import java.util.HashMap;
import java.util.Map;

public class RegistrationFlowConfig {

    private String id;
    private String name;
    private String firstNodeId;
    private final Map<String, NodeConfig> nodeConfigs = new HashMap<>();
    private final Map<String, StepDTO> nodePageMappings = new HashMap<>();

    public String getId() {

        return id;
    }

    public void setId(String id) {

        this.id = id;
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

    public String getFirstNodeId() {

        return firstNodeId;
    }

    public void setFirstNodeId(String firstNodeId) {

        this.firstNodeId = firstNodeId;
    }

    public Map<String, NodeConfig> getNodeConfigs() {

        return nodeConfigs;
    }

    public void addNodeConfig(NodeConfig node) {

        this.nodeConfigs.put(node.getUuid(), node);
    }

    public Map<String, StepDTO> getNodePageMappings() {

        return nodePageMappings;
    }

    public void addNodePageMapping(String nodeId, StepDTO stepDTO) {

        this.nodePageMappings.put(nodeId, stepDTO);
    }
}
