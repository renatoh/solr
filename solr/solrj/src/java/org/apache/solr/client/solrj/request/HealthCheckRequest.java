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

package org.apache.solr.client.solrj.request;

import static org.apache.solr.common.params.CommonParams.HEALTH_CHECK_HANDLER_PATH;

import java.util.OptionalInt;
import org.apache.solr.client.solrj.SolrRequest;
import org.apache.solr.client.solrj.response.HealthCheckResponse;
import org.apache.solr.common.params.ModifiableSolrParams;
import org.apache.solr.common.params.SolrParams;
import org.apache.solr.common.util.NamedList;

public class HealthCheckRequest extends SolrRequest<HealthCheckResponse> {
  public static final String PARAM_MAX_GENERATION_LAG = "maxGenerationLag";

  private OptionalInt maxLagAllowed = OptionalInt.empty();

  public HealthCheckRequest() {
    this(METHOD.GET, HEALTH_CHECK_HANDLER_PATH);
  }

  private HealthCheckRequest(METHOD m, String path) {
    super(m, path, SolrRequestType.ADMIN);
  }

  public void setMaxGenerationLag(int maxLagAllowed) {
    this.maxLagAllowed = OptionalInt.of(maxLagAllowed);
  }

  @Override
  public SolrParams getParams() {
    ModifiableSolrParams params = new ModifiableSolrParams();
    if (maxLagAllowed.isPresent()) {
      params.set(PARAM_MAX_GENERATION_LAG, maxLagAllowed.getAsInt());
    }
    return params;
  }

  @Override
  protected HealthCheckResponse createResponse(NamedList<Object> namedList) {
    // TODO: Accept requests w/ CloudSolrClient while ensuring that the request doesn't get routed
    // to an unintended recipient.
    return new HealthCheckResponse();
  }
}
