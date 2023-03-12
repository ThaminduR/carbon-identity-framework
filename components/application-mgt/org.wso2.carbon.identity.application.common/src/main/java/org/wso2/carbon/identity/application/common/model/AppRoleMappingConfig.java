/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.common.model;

import org.apache.axiom.om.OMElement;

import java.io.Serializable;
import java.util.Iterator;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Application role mapping type of application for an IdP.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "ApplicationRoleMappingConfig")
public class AppRoleMappingConfig implements Serializable {

    private static final long serialVersionUID = 497647508006862448L;

    @XmlElement(name = "IdPName")
    private String idPName;

    @XmlElement(name = "UseAppRoleMappings")
    private boolean useAppRoleMappings;

    public static AppRoleMappingConfig build(OMElement applicationRoleMappingConfigOM) {

        AppRoleMappingConfig applicationRoleMappingType = new AppRoleMappingConfig();
        Iterator<?> iterator = applicationRoleMappingConfigOM.getChildElements();

        while (iterator.hasNext()) {
            OMElement omElement = (OMElement) iterator.next();
            if ("IdPName".equals(omElement.getLocalName())) {
                applicationRoleMappingType.setIdPName(omElement.getText());
            } else if ("UseAppRoleMappings".equals(omElement.getLocalName())) {
                applicationRoleMappingType.setUseAppRoleMappings(Boolean.parseBoolean(omElement.getText()));
            }
        }
        return applicationRoleMappingType;
    }

    /**
     * @return IdPName
     */
    public String getIdPName() {

        return idPName;
    }

    /**
     * @param idPName IdPName
     */
    public void setIdPName(String idPName) {

        this.idPName = idPName;
    }

    /**
     * @return useAppRoleMappings
     */
    public boolean isUseAppRoleMappings() {

        return useAppRoleMappings;
    }

    /**
     * @param useAppRoleMappings useAppRoleMappings
     */
    public void setUseAppRoleMappings(boolean useAppRoleMappings) {

        this.useAppRoleMappings = useAppRoleMappings;
    }
}
