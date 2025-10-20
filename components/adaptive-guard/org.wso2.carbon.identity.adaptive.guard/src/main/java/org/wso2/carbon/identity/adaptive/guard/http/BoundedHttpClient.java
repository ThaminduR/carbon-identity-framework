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

package org.wso2.carbon.identity.adaptive.guard.http;

/**
 * Minimal interface representing a guard-aware HTTP client wrapper.
 */
public interface BoundedHttpClient extends AutoCloseable {

    /**
     * Create a no-op HTTP client instance.
     *
     * @return Client that records no traffic and performs no operations on close.
     */
    static BoundedHttpClient noop() {

        return new BoundedHttpClient() {
            @Override
            public void recordBytesIn(long bytes) {
                // No-op
            }

            @Override
            public long getBytesIn() {
                return 0;
            }

            @Override
            public void close() {
                // No-op
            }
        };
    }

    /**
     * Record bytes received through this client.
     *
     * @param bytes Bytes consumed from HTTP responses.
     */
    void recordBytesIn(long bytes);

    /**
     * Retrieve the bytes recorded so far.
     *
     * @return Total bytes received.
     */
    long getBytesIn();

    @Override
    void close();
}
