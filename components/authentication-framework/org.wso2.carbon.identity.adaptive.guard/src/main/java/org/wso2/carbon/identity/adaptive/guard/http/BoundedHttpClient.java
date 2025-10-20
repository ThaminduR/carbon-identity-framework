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

package org.wso2.carbon.identity.adaptive.guard.http;

import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Simplified bounded HTTP client wrapper. The actual HTTP execution is handled by the adaptive
 * authentication framework. The guard uses this wrapper to keep track of bytes flowing through
 * the script.
 */
public class BoundedHttpClient implements Closeable {

    private final int maxBodyBytes;
    private final AtomicLong bytesIn = new AtomicLong();

    public BoundedHttpClient(int maxBodyKb) {

        this.maxBodyBytes = maxBodyKb <= 0 ? Integer.MAX_VALUE : maxBodyKb * 1024;
    }

    /**
     * Register bytes returned by an HTTP response.
     *
     * @param count Number of bytes read by the script.
     * @throws IOException If the configured limit has been exceeded.
     */
    public void registerBytes(long count) throws IOException {

        if (count <= 0) {
            return;
        }
        long updated = bytesIn.addAndGet(count);
        if (updated > maxBodyBytes) {
            throw new IOException("Adaptive guard HTTP budget exceeded");
        }
    }

    /**
     * Returns the total number of bytes consumed through HTTP responses.
     *
     * @return HTTP bytes consumed.
     */
    public long getBytesIn() {

        return bytesIn.get();
    }

    @Override
    public void close() {

        // Nothing to clean up; present for API parity.
    }
}
