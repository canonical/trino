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
package io.trino.spooling.filesystem;

import io.airlift.units.DataSize;
import io.trino.filesystem.s3.S3FileSystemConfig;
import io.trino.filesystem.s3.S3FileSystemFactory;
import io.trino.spi.QueryId;
import io.trino.spi.protocol.SpooledLocation;
import io.trino.spi.protocol.SpooledSegmentHandle;
import io.trino.spi.protocol.SpoolingContext;
import io.trino.spi.protocol.SpoolingManager;
import io.trino.testing.containers.Minio;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Instant;
import java.util.Optional;

import static io.airlift.slice.Slices.utf8Slice;
import static io.opentelemetry.api.OpenTelemetry.noop;
import static io.trino.testing.containers.Minio.MINIO_REGION;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(PER_CLASS)
public class TestFileSystemSpoolingManager
{
    private Minio minio;

    @BeforeAll
    public void setup()
    {
        minio = Minio.builder().build();
        minio.start();
        minio.createBucket("test");
    }

    @AfterAll
    public void teardown()
    {
        minio.stop();
    }

    @Test
    public void testRetrieveSpooledSegment()
            throws Exception
    {
        SpoolingManager manager = getSpoolingManager();
        SpoolingContext context = new SpoolingContext(QueryId.valueOf("a"), 0);
        SpooledSegmentHandle spooledSegmentHandle = manager.create(context);
        try (OutputStream segment = manager.createOutputStream(spooledSegmentHandle)) {
            segment.write("data".getBytes(UTF_8));
        }

        try (InputStream output = manager.openInputStream(spooledSegmentHandle)) {
            byte[] buffer = new byte[4];
            assertThat(output.read(buffer)).isEqualTo(buffer.length);
            assertThat(buffer).isEqualTo("data".getBytes(UTF_8));
        }
    }

    @Test
    public void testAcknowledgedSegmentCantBeRetrievedAgain()
            throws Exception
    {
        SpoolingManager manager = getSpoolingManager();
        SpoolingContext context = new SpoolingContext(QueryId.valueOf("a"), 0);
        SpooledSegmentHandle spooledSegmentHandle = manager.create(context);
        try (OutputStream segment = manager.createOutputStream(spooledSegmentHandle)) {
            segment.write("data".getBytes(UTF_8));
        }

        try (InputStream output = manager.openInputStream(spooledSegmentHandle)) {
            byte[] buffer = new byte[4];
            assertThat(output.read(buffer)).isEqualTo(buffer.length);
            assertThat(buffer).isEqualTo("data".getBytes(UTF_8));
        }

        manager.acknowledge(spooledSegmentHandle);
        assertThatThrownBy(() -> manager.openInputStream(spooledSegmentHandle).read())
                .isInstanceOf(IOException.class)
                .hasMessage("Segment not found or expired");
    }

    @Test
    public void testHandleRoundTrip()
    {
        FileSystemSpooledSegmentHandle handle = new FileSystemSpooledSegmentHandle("test", Instant.now(), Optional.of(utf8Slice("superSecretKey")));

        SpooledLocation location = getSpoolingManager().location(handle);
        assertThat(getSpoolingManager().handle(location)).isEqualTo(handle);
    }

    private SpoolingManager getSpoolingManager()
    {
        FileSystemSpoolingConfig spoolingConfig = new FileSystemSpoolingConfig();
        spoolingConfig.setNativeS3Enabled(true);
        spoolingConfig.setLocation("s3://test");
        S3FileSystemConfig filesystemConfig = new S3FileSystemConfig()
                .setEndpoint(minio.getMinioAddress())
                .setRegion(MINIO_REGION)
                .setPathStyleAccess(true)
                .setAwsAccessKey(Minio.MINIO_ACCESS_KEY)
                .setAwsSecretKey(Minio.MINIO_SECRET_KEY)
                .setStreamingPartSize(DataSize.valueOf("5.5MB"));
        return new FileSystemSpoolingManager(spoolingConfig, new S3FileSystemFactory(noop(), filesystemConfig));
    }
}
