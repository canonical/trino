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
package io.trino.client;

import okhttp3.Call;
import okhttp3.OkHttpClient;

import java.util.Optional;
import java.util.Set;

public final class StatementClientFactory
{
    private StatementClientFactory() {}

    public static StatementClient newStatementClient(Call.Factory httpCallFactory, ClientSession session, String query)
    {
        return new StatementClientV1(httpCallFactory, session, query, Optional.empty());
    }

    public static StatementClient newStatementClient(OkHttpClient httpClient, ClientSession session, String query, Optional<Set<String>> clientCapabilities)
    {
        return new StatementClientV1((Call.Factory) httpClient, session, query, clientCapabilities);
    }

    public static StatementClient newStatementClient(OkHttpClient httpClient, QueryDataDecoder.Factory decoderFactory, ClientSession session, String query, Optional<Set<String>> clientCapabilities)
    {
        return new StatementClientV1((Call.Factory) httpClient, Optional.of(decoderFactory), session, query, clientCapabilities);
    }
}
