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

import java.util.ArrayList;
import java.util.List;

public class StepDTO {

    private String id;
    private String type;
    private double coordinateX;
    private double coordinateY;
    private double width;
    private double height;
    private List<BlockDTO> blocks = new ArrayList<>();
    private ActionDTO actionDTO;

    private StepDTO(Builder builder) {

        this.id = builder.id;
        this.type = builder.type;
        this.coordinateX = builder.coordinateX;
        this.coordinateY = builder.coordinateY;
        this.width = builder.width;
        this.height = builder.height;
        this.blocks = builder.blocks;
        this.actionDTO = builder.actionDTO;
    }

    public String getId() {

        return id;
    }

    public void setId(String id) {

        this.id = id;
    }

    public String getType() {

        return type;
    }

    public void setType(String type) {

        this.type = type;
    }

    public double getCoordinateX() {

        return coordinateX;
    }

    public void setCoordinateX(double coordinateX) {

        this.coordinateX = coordinateX;
    }

    public double getCoordinateY() {

        return coordinateY;
    }

    public void setCoordinateY(double coordinateY) {

        this.coordinateY = coordinateY;
    }

    public double getWidth() {

        return width;
    }

    public void setWidth(double width) {

        this.width = width;
    }

    public double getHeight() {

        return height;
    }

    public void setHeight(double height) {

        this.height = height;
    }

    public List<BlockDTO> getBlocks() {

        return blocks;
    }

    public void setBlocks(List<BlockDTO> blocks) {

        this.blocks = blocks;
    }

    public ActionDTO getActionDTO() {

        return actionDTO;
    }

    public void setActionDTO(ActionDTO actionDTO) {

        this.actionDTO = actionDTO;
    }

    public static class Builder {

        private String id;
        private String type;
        private double coordinateX;
        private double coordinateY;
        private double width;
        private double height;
        private List<BlockDTO> blocks = new ArrayList<>();
        private ActionDTO actionDTO;

        public Builder setId(String id) {

            this.id = id;
            return this;
        }

        public Builder setType(String type) {

            this.type = type;
            return this;
        }

        public Builder setCoordinateX(double coordinateX) {

            this.coordinateX = coordinateX;
            return this;
        }

        public Builder setCoordinateY(double coordinateY) {

            this.coordinateY = coordinateY;
            return this;
        }

        public Builder setWidth(double width) {

            this.width = width;
            return this;
        }

        public Builder setHeight(double height) {

            this.height = height;
            return this;
        }

        public Builder setBlocks(List<BlockDTO> blocks) {

            this.blocks = blocks;
            return this;
        }

        public Builder addBlock(BlockDTO block) {

            this.blocks.add(block);
            return this;
        }

        public Builder setActionDTO(ActionDTO actionDTO) {

            this.actionDTO = actionDTO;
            return this;
        }

        public StepDTO build() {

            return new StepDTO(this);
        }
    }
}
