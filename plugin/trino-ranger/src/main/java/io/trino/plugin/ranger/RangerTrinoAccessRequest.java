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
package io.trino.plugin.ranger;

import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;

import java.time.Instant;
import java.util.Date;
import java.util.Set;

import static java.util.Locale.ENGLISH;

class RangerTrinoAccessRequest
        extends RangerAccessRequestImpl
{
    public RangerTrinoAccessRequest(RangerTrinoResource resource, String user, Set<String> userGroups, Instant queryTime, String clientAddress, String clientType, String queryText, RangerTrinoAccessType trinoAccessType, String action)
    {
        super(resource, trinoAccessType.name().toLowerCase(ENGLISH), user, userGroups, null);

        setAction(action);
        setAccessTime(queryTime != null ? new Date(queryTime.getEpochSecond() * 1000) : new Date());
        setClientIPAddress(clientAddress);
        setClientType(clientType);
        setRequestData(queryText);
    }
}
