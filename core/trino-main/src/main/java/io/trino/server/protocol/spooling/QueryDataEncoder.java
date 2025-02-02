/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.server.protocol.spooling;

import io.trino.Session;
import io.trino.client.spooling.DataAttributes;
import io.trino.server.protocol.OutputColumn;
import io.trino.spi.Page;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

public interface QueryDataEncoder
{
    interface Factory
    {
        QueryDataEncoder create(Session session, List<OutputColumn> columns);

        String encodingId();
    }

    DataAttributes encodeTo(OutputStream output, List<Page> pages)
            throws IOException;

    String encodingId();

    /**
     * Returns additional attributes that are passed to the QueryDataDecoder.Factory.create method.
     */
    default DataAttributes attributes()
    {
        return DataAttributes.empty();
    }
}
