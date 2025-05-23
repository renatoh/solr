/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.solr.core;

import static org.apache.solr.core.FileSystemConfigSetService.METADATA_FILE;
import static org.hamcrest.Matchers.hasItem;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.io.file.PathUtils;
import org.apache.solr.SolrTestCaseJ4;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestFileSystemConfigSetService extends SolrTestCaseJ4 {
  private static Path configSetBase;
  private static FileSystemConfigSetService fileSystemConfigSetService;

  @BeforeClass
  public static void beforeClass() throws Exception {
    configSetBase = createTempDir();
    fileSystemConfigSetService = new FileSystemConfigSetService(configSetBase);
  }

  @AfterClass
  public static void afterClass() throws Exception {
    PathUtils.deleteDirectory(configSetBase);
    fileSystemConfigSetService = null;
  }

  @Test
  public void testIgnoresFileUploadsOutsideOfConfigSetDirectory() throws IOException {
    final var initialNumConfigs = fileSystemConfigSetService.listConfigs().size();
    final String configName = "fileEscapeTestConfig";
    final var specificConfigSetBase = configSetBase.resolve(configName);

    fileSystemConfigSetService.uploadConfig(configName, configset("cloud-minimal"));
    assertEquals(fileSystemConfigSetService.listConfigs().size(), initialNumConfigs + 1);
    assertTrue(fileSystemConfigSetService.checkConfigExists(configName));

    // This succeeds, as the file is an allowed type and the path doesn't attempt to escape the
    // configset's root
    byte[] testdata = "test data".getBytes(StandardCharsets.UTF_8);
    fileSystemConfigSetService.uploadFileToConfig(configName, "validPath", testdata, true);
    final var knownFiles = fileSystemConfigSetService.getAllConfigFiles(configName);
    assertThat(knownFiles, hasItem("validPath"));
    assertTrue(Files.exists(specificConfigSetBase.resolve("validPath")));

    // Each of these will fail "quietly" as ConfigSetService opts to log warnings but otherwise not
    // surface validation errors to enable bulk uploading
    final var invalidFilePaths = List.of("../escapePath", "foo/../../bar");
    for (String invalidFilePath : invalidFilePaths) {
      fileSystemConfigSetService.uploadFileToConfig(configName, invalidFilePath, testdata, true);
      assertFalse(Files.exists(specificConfigSetBase.resolve(invalidFilePath)));
    }
  }

  @Test
  public void testUploadAndDeleteConfig() throws IOException {
    final var initialNumConfigs = fileSystemConfigSetService.listConfigs().size();
    String configName = "testconfig";

    fileSystemConfigSetService.uploadConfig(configName, configset("cloud-minimal"));
    assertEquals(fileSystemConfigSetService.listConfigs().size(), initialNumConfigs + 1);
    assertTrue(fileSystemConfigSetService.checkConfigExists(configName));

    byte[] testdata = "test data".getBytes(StandardCharsets.UTF_8);
    fileSystemConfigSetService.uploadFileToConfig(configName, "testfile", testdata, true);

    // metadata is stored in .metadata.json
    fileSystemConfigSetService.setConfigMetadata(configName, new HashMap<>(Map.of("key1", "val1")));
    Map<String, Object> metadata = fileSystemConfigSetService.getConfigMetadata(configName);
    assertEquals("{key1=val1}", metadata.toString());

    List<String> allConfigFiles = fileSystemConfigSetService.getAllConfigFiles(configName);
    assertEquals("[schema.xml, solrconfig.xml, testfile]", allConfigFiles.toString());

    fileSystemConfigSetService.deleteFilesFromConfig(
        configName, List.of(METADATA_FILE, "testfile"));
    metadata = fileSystemConfigSetService.getConfigMetadata(configName);
    assertTrue(metadata.isEmpty());

    allConfigFiles = fileSystemConfigSetService.getAllConfigFiles(configName);
    assertEquals("[schema.xml, solrconfig.xml]", allConfigFiles.toString());

    fileSystemConfigSetService.copyConfig(configName, "copytestconfig");
    assertEquals(fileSystemConfigSetService.listConfigs().size(), initialNumConfigs + 2);

    allConfigFiles = fileSystemConfigSetService.getAllConfigFiles("copytestconfig");
    assertEquals("[schema.xml, solrconfig.xml]", allConfigFiles.toString());

    Path downloadConfig = createTempDir("downloadConfig");
    fileSystemConfigSetService.downloadConfig(configName, downloadConfig);

    List<String> configs = getFileList(downloadConfig);
    assertEquals("[schema.xml, solrconfig.xml]", configs.toString());

    Exception ex =
        assertThrows(
            IOException.class,
            () -> {
              fileSystemConfigSetService.uploadConfig("../dummy", createTempDir("tmp"));
            });
    assertTrue(ex.getMessage().startsWith("configName=../dummy is not found under configSetBase"));

    fileSystemConfigSetService.deleteConfig(configName);
    fileSystemConfigSetService.deleteConfig("copytestconfig");

    assertFalse(fileSystemConfigSetService.checkConfigExists(configName));
    assertFalse(fileSystemConfigSetService.checkConfigExists("copytestconfig"));
  }

  private static List<String> getFileList(Path confDir) throws IOException {
    try (Stream<Path> configs = Files.list(confDir)) {
      return configs
          .map(Path::getFileName)
          .map(Path::toString)
          .sorted()
          .collect(Collectors.toList());
    }
  }
}
