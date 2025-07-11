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
package org.apache.solr.update;

import static org.apache.solr.update.processor.DistributedUpdateProcessor.DistribPhase.FROMLEADER;
import static org.apache.solr.update.processor.DistributingUpdateProcessorFactory.DISTRIB_UPDATE_PARAM;

import com.carrotsearch.hppc.LongHashSet;
import com.carrotsearch.hppc.LongSet;
import com.codahale.metrics.Gauge;
import com.codahale.metrics.Meter;
import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.Future;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.apache.commons.io.file.PathUtils;
import org.apache.lucene.store.Directory;
import org.apache.lucene.util.BytesRef;
import org.apache.solr.common.SolrDocumentBase;
import org.apache.solr.common.SolrException;
import org.apache.solr.common.SolrException.ErrorCode;
import org.apache.solr.common.SolrInputDocument;
import org.apache.solr.common.params.MapSolrParams;
import org.apache.solr.common.params.ModifiableSolrParams;
import org.apache.solr.common.params.SolrParams;
import org.apache.solr.common.util.CollectionUtil;
import org.apache.solr.common.util.EnvUtils;
import org.apache.solr.common.util.ExecutorUtil;
import org.apache.solr.common.util.IOUtils;
import org.apache.solr.common.util.SolrNamedThreadFactory;
import org.apache.solr.common.util.SuppressForbidden;
import org.apache.solr.common.util.TimeSource;
import org.apache.solr.core.DirectoryFactory;
import org.apache.solr.core.PluginInfo;
import org.apache.solr.core.SolrCore;
import org.apache.solr.core.SolrInfoBean;
import org.apache.solr.core.SolrPaths;
import org.apache.solr.metrics.SolrMetricProducer;
import org.apache.solr.metrics.SolrMetricsContext;
import org.apache.solr.request.LocalSolrQueryRequest;
import org.apache.solr.request.SolrQueryRequest;
import org.apache.solr.request.SolrRequestInfo;
import org.apache.solr.response.SolrQueryResponse;
import org.apache.solr.search.SolrIndexSearcher;
import org.apache.solr.update.processor.DistributedUpdateProcessor;
import org.apache.solr.update.processor.UpdateRequestProcessor;
import org.apache.solr.update.processor.UpdateRequestProcessorChain;
import org.apache.solr.util.OrderedExecutor;
import org.apache.solr.util.RefCounted;
import org.apache.solr.util.TestInjection;
import org.apache.solr.util.TimeOut;
import org.apache.solr.util.plugin.PluginInfoInitialized;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This holds references to the transaction logs. It also keeps a map of unique key to location in
 * log (along with the update's version). This map is only cleared on soft or hard commit
 *
 * @lucene.experimental
 */
public class UpdateLog implements PluginInfoInitialized, SolrMetricProducer {
  private static final long STATUS_TIME = TimeUnit.NANOSECONDS.convert(60, TimeUnit.SECONDS);
  public static String LOG_FILENAME_PATTERN = "%s.%019d";
  public static String TLOG_NAME = "tlog";
  public static String BUFFER_TLOG_NAME = "buffer.tlog";

  private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
  private boolean debug = log.isDebugEnabled();
  private boolean trace = log.isTraceEnabled();
  private boolean usableForChildDocs;

  public enum SyncLevel {
    NONE,
    FLUSH,
    FSYNC;

    public static SyncLevel getSyncLevel(String level) {
      if (level == null) {
        return SyncLevel.FLUSH;
      }
      try {
        return SyncLevel.valueOf(level.toUpperCase(Locale.ROOT));
      } catch (Exception ex) {
        log.warn("There was an error reading the SyncLevel - default to {}", SyncLevel.FLUSH, ex);
        return SyncLevel.FLUSH;
      }
    }
  }

  // NOTE: when adding new states make sure to keep existing numbers, because external metrics
  // monitoring may depend on these values being stable.
  public enum State {
    REPLAYING(0),
    BUFFERING(1),
    APPLYING_BUFFERED(2),
    ACTIVE(3);
    private final int value;

    State(final int value) {
      this.value = value;
    }

    public int getValue() {
      return value;
    }
  }

  public static final int ADD = 0x01;
  public static final int DELETE = 0x02;
  public static final int DELETE_BY_QUERY = 0x03;
  public static final int COMMIT = 0x04;
  public static final int UPDATE_INPLACE = 0x08;
  // For backward-compatibility, we should delete this field in 9.0
  public static final int OPERATION_MASK = 0x0f; // mask off flags to get the operation

  /** The index of the flags value in an entry from the transaction log. */
  public static final int FLAGS_IDX = 0;

  /** The index of the _version_ value in an entry from the transaction log. */
  public static final int VERSION_IDX = 1;

  /**
   * The index of the previous pointer in an entry from the transaction log. This is only relevant
   * if flags (indexed at FLAGS_IDX) includes UPDATE_INPLACE.
   */
  public static final int PREV_POINTER_IDX = 2;

  /**
   * The index of the previous version in an entry from the transaction log. This is only relevant
   * if flags (indexed at FLAGS_IDX) includes UPDATE_INPLACE.
   */
  public static final int PREV_VERSION_IDX = 3;

  public static class RecoveryInfo {
    public long positionOfStart;

    public int adds;
    public int deletes;
    public int deleteByQuery;
    public AtomicInteger errors = new AtomicInteger(0);

    public boolean failed;

    @Override
    public String toString() {
      return "RecoveryInfo{adds="
          + adds
          + " deletes="
          + deletes
          + " deleteByQuery="
          + deleteByQuery
          + " errors="
          + errors
          + " positionOfStart="
          + positionOfStart
          + "}";
    }
  }

  protected long id = -1;
  protected volatile State state = State.ACTIVE;

  protected TransactionLog bufferTlog;
  protected TransactionLog tlog;
  protected TransactionLog prevTlog;
  protected TransactionLog prevTlogOnPrecommit;
  // list of recent logs, newest first
  protected final Deque<TransactionLog> logs = new ArrayDeque<>();
  protected Deque<TransactionLog> newestLogsOnStartup = new ArrayDeque<>();
  protected int numOldRecords; // number of records in the recent logs

  protected Map<BytesRef, LogPtr> map = new HashMap<>();
  protected Map<BytesRef, LogPtr> prevMap; // used while committing/reopening is happening
  protected Map<BytesRef, LogPtr> prevMap2; // used while committing/reopening is happening
  // the transaction log used to look up entries found in prevMap
  protected TransactionLog prevMapLog;
  // the transaction log used to look up entries found in prevMap2
  protected TransactionLog prevMapLog2;

  protected final int numDeletesToKeep = 1000;
  protected final int numDeletesByQueryToKeep = 100;
  protected int numRecordsToKeep;
  protected int maxNumLogsToKeep;
  protected boolean existOldBufferLog = false;

  // keep track of deletes only... this is not updated on an add
  protected LinkedHashMap<BytesRef, LogPtr> oldDeletes =
      new OldDeletesLinkedHashMap(this.numDeletesToKeep);

  private UpdateLocks updateLocks;

  /** Holds the query and the version for a DeleteByQuery command */
  public static class DBQ {
    public String q; // the query string
    public long version; // positive version of the DBQ

    @Override
    public String toString() {
      return "DBQ{version=" + version + ",q=" + q + "}";
    }
  }

  @SuppressWarnings("JdkObsolete")
  protected LinkedList<DBQ> deleteByQueries = new LinkedList<>();

  // Needs to be String because hdfs.Path is incompatible with nio.Path
  protected String[] tlogFiles;
  protected Path tlogDir;
  protected Closeable releaseTlogDir;
  protected Collection<String> globalStrings;

  protected String dataDir;

  protected VersionInfo versionInfo;

  protected SyncLevel defaultSyncLevel = SyncLevel.FLUSH;

  protected volatile UpdateHandler uhandler; // a core reload can change this reference!
  protected volatile boolean cancelApplyBufferUpdate;
  protected List<Long> startingVersions;

  // metrics
  protected Gauge<Integer> bufferedOpsGauge;
  protected Meter applyingBufferedOpsMeter;
  protected Meter replayOpsMeter;
  protected Meter copyOverOldUpdatesMeter;
  protected SolrMetricsContext solrMetricsContext;

  public static class LogPtr {
    final long pointer;
    final long version;
    // used for entries that are in-place updates and need a pointer to a previous update command
    final long previousPointer;

    /**
     * Creates an object that contains the position and version of an update. In this constructor,
     * the effective value of the previousPointer is -1.
     *
     * @param pointer Position in the transaction log of an update
     * @param version Version of the update at the given position
     */
    public LogPtr(long pointer, long version) {
      this(pointer, version, -1);
    }

    /**
     * @param pointer Position in the transaction log of an update
     * @param version Version of the update at the given position
     * @param previousPointer Position, in the transaction log, of an update on which the current
     *     update depends
     */
    public LogPtr(long pointer, long version, long previousPointer) {
      this.pointer = pointer;
      this.version = version;
      this.previousPointer = previousPointer;
    }

    @Override
    public String toString() {
      return "LogPtr(" + pointer + ")";
    }
  }

  public long getTotalLogsSize() {
    long size = 0;
    synchronized (this) {
      for (TransactionLog log : logs) {
        size += log.getLogSize();
      }
    }
    return size;
  }

  /**
   * @return the current transaction log's size (based on its output stream)
   */
  public synchronized long getCurrentLogSizeFromStream() {
    return tlog == null ? 0 : tlog.getLogSizeFromStream();
  }

  public long getTotalLogsNumber() {
    synchronized (this) {
      return logs.size();
    }
  }

  public VersionInfo getVersionInfo() {
    return versionInfo;
  }

  public UpdateLocks getLocks() {
    return updateLocks;
  }

  public int getNumRecordsToKeep() {
    return numRecordsToKeep;
  }

  public int getMaxNumLogsToKeep() {
    return maxNumLogsToKeep;
  }

  protected static int objToInt(Object obj, int def) {
    if (obj != null) {
      return Integer.parseInt(obj.toString());
    } else return def;
  }

  public static Path ulogToTlogDir(
      String coreName, Path ulogDirPath, Path instancePath, String coreDataDir) {
    final Path coreDataPath = ulogDirPath.getFileSystem().getPath(coreDataDir);
    boolean unscopedDataDir =
        !ulogDirPath.startsWith(instancePath) && !ulogDirPath.startsWith(coreDataPath);

    // if the ulog dataDir is unscoped (neither under core instanceDir, nor core dataDir),
    // then we must scope it to the core; otherwise, scope to purpose (TLOG_NAME).
    if (unscopedDataDir) {
      Path tlog = ulogDirPath.resolve(coreName);
      if (tlog.equals(instancePath)) {
        throw new IllegalArgumentException(
            "tlog path " + tlog + " conflicts with instance path " + instancePath);
      } else if (SolrPaths.normalizeDir(tlog.toString()).equals(coreDataDir)) {
        // NOTE: use string comparison above because `coreDataDir` might not be parseable
        // as a valid Path (e.g., it might be an hdfs Path).
        throw new IllegalArgumentException(
            "tlog path " + tlog + " conflicts with core data dir " + coreDataDir);
      }
      return tlog;
    } else {
      // the simple case
      return ulogDirPath.resolve(TLOG_NAME);
    }
  }

  @Override
  public void init(PluginInfo info) {
    dataDir = (String) info.initArgs.get("dir");
    defaultSyncLevel = SyncLevel.getSyncLevel((String) info.initArgs.get("syncLevel"));

    numRecordsToKeep = objToInt(info.initArgs.get("numRecordsToKeep"), 100);
    maxNumLogsToKeep = objToInt(info.initArgs.get("maxNumLogsToKeep"), 10);
    if (info.initArgs.get("numVersionBuckets") != null) {
      log.warn("numVersionBuckets is obsolete");
    }

    if (info.initArgs.get("versionBucketLockTimeoutMs") != null) {
      log.warn("versionBucketLockTimeoutMs is mostly replaced by docLockTimeoutMs");
    }
    int timeoutMs =
        objToInt(
            info.initArgs.getOrDefault(
                "docLockTimeoutMs", info.initArgs.get("versionBucketLockTimeoutMs")),
            EnvUtils.getPropertyAsLong("solr.update.docLockTimeoutMs", 0L).intValue());
    updateLocks = new UpdateLocks(timeoutMs);

    log.info(
        "Initializing UpdateLog: dataDir={} defaultSyncLevel={} numRecordsToKeep={} maxNumLogsToKeep={}",
        dataDir,
        defaultSyncLevel,
        numRecordsToKeep,
        maxNumLogsToKeep);
  }

  private final AtomicBoolean initialized = new AtomicBoolean();

  private String resolveDataDir(SolrCore core) {
    // we need to initialize with existing `this.dataDir`, because it may have been
    // set in `init(PluginInfo)` to the ulogDir specified in `<updateLog>` element
    // of `solrconfig.xml`
    String dataDir = this.dataDir;

    // ulogDir from CoreDescriptor overrides
    String ulogDir = core.getCoreDescriptor().getUlogDir();

    if (ulogDir != null) {
      dataDir = ulogDir;
    }

    if (dataDir == null || dataDir.length() == 0) {
      // NOTE: this method is called from within `UpdateHandler` ctor, and this method is called
      // _after_ `init(PluginInfo)`; so if ulogDir is specified in `<updateLog>` element of
      // `solrconfig.xml`, `dataDir` will _not_ be null here.
      dataDir = core.getDataDir();
    }

    return resolveDataDir(core, dataDir);
  }

  /**
   * This must be called when a new log is created, or for an existing log whenever the core or
   * update handler changes. It is called from the ctor of the specified {@link UpdateHandler}, so
   * the specified uhandler will not yet be completely constructed.
   *
   * <p>This method must be called <i>after</i> {@link #init(PluginInfo)} is called.
   */
  public void init(UpdateHandler uhandler, SolrCore core) {
    this.uhandler = uhandler;

    // on a reopen, return early; less work to do.
    if (!initialized.compareAndSet(false, true)) {
      // NOTE: we may not strictly _need_ fancy concurrency constructs here, since it looks like
      // `init(UpdateHandler, SolrCore` is never actually called concurrently in application code
      // (`TestHdfsUpdateLog.testFSThreadSafety()`, introduced by SOLR-7113, seems to be the only
      // place that requires true thread safety from this method?).
      if (debug) {
        log.debug(
            "UpdateHandler init: tlogDir={}, next id={}  this is a reopen or double init ... nothing else to do.",
            getTlogDir(),
            id);
      }
      core.getCoreMetricManager()
          .registerMetricProducer(SolrInfoBean.Category.TLOG.toString(), this);

      String reResolved = resolveDataDir(core);
      if (dataDir == null || !dataDir.equals(reResolved)) {
        // dataDir should already be initialized, and should not change. We recompute every time
        // in order to fail on attempted config changes, rather than simply silently ignore them.
        throw new IllegalStateException(
            "dataDir should not change on reload! computed " + reResolved + ", found " + dataDir);
      }
      return;
    }

    dataDir = resolveDataDir(core);

    initTlogDir(core);

    usableForChildDocs = core.getLatestSchema().isUsableForChildDocs();

    try {
      versionInfo = new VersionInfo(this);
    } catch (SolrException e) {
      log.error("Unable to use updateLog: ", e);
      throw new SolrException(
          SolrException.ErrorCode.SERVER_ERROR, "Unable to use updateLog: " + e.getMessage(), e);
    }

    // TODO: these startingVersions assume that we successfully recover from all non-complete tlogs.
    try (RecentUpdates startingUpdates = getRecentUpdates()) {
      startingVersions = startingUpdates.getVersions(numRecordsToKeep);

      // populate recent deletes list (since we can't get that info from the index)
      for (int i = startingUpdates.deleteList.size() - 1; i >= 0; i--) {
        DeleteUpdate du = startingUpdates.deleteList.get(i);
        oldDeletes.put(new BytesRef(du.id), new LogPtr(-1, du.version));
      }

      // populate recent deleteByQuery commands
      for (int i = startingUpdates.deleteByQueryList.size() - 1; i >= 0; i--) {
        Update update = startingUpdates.deleteByQueryList.get(i);
        @SuppressWarnings({"unchecked"})
        List<Object> dbq = (List<Object>) update.log.lookup(update.pointer);
        long version = (Long) dbq.get(1);
        String q = (String) dbq.get(2);
        trackDeleteByQuery(q, version);
      }
    }
    core.getCoreMetricManager().registerMetricProducer(SolrInfoBean.Category.TLOG.toString(), this);
  }

  protected final void maybeClearLog(SolrCore core) {
    if (!core.isReloaded() && !core.getDirectoryFactory().isPersistent()) {
      clearLog();
    }
  }

  /**
   * Resolves any relative path wrt the highest core-scoped level (whatever that means for a
   * particular implementation). For most filesystems, this will be the core instanceDir, but there
   * are other cases; e.g., HdfsUpdateLog will resolve paths relative to the core dataDir.
   *
   * <p>If the input path is already absolute, it will be returned unmodified.
   *
   * <p>This method should return the final, absolute, normalized path that defines the location of
   * the ulog dataDir. It should <i>not</i> bother to resolve the tlog dir, nor do any work
   * associated with initializing the tlog dir or its contents. Tlog dir initialization takes place
   * later (if necessary) in {@link #initTlogDir(SolrCore)}.
   */
  protected String resolveDataDir(SolrCore core, String path) {
    if (Path.of(path).isAbsolute()) {
      return path;
    }
    Path instancePath = core.getInstancePath();
    Path absolute = instancePath.resolve(path);
    if (!absolute.normalize().startsWith(instancePath.normalize())) {
      // relative path spec should not be able to escape core-scoped instanceDir
      throw new SolrException(ErrorCode.SERVER_ERROR, "Illegal relative ulog dir spec: " + path);
    }
    return absolute.toString();
  }

  /**
   * Based on {@link #dataDir} (whose initialization must be complete before this method is called),
   * this method is responsible for, in order:
   *
   * <ol>
   *   <li>resolving the tlog dir (in an implementation-dependent way)
   *   <li>clearing any existing entries (if applicable) by calling {@link #maybeClearLog(SolrCore)}
   *   <li>actually creating tlog files (and handling any existing tlog files, if necessary)
   * </ol>
   *
   * <p>Note: implementations of this method <i>must</i> call {@link #maybeClearLog(SolrCore)} after
   * resolving the tlog dir, and before creating any (or handling any existing) tlog files.
   */
  protected void initTlogDir(SolrCore core) {
    Path instancePath = core.getInstancePath();

    Path dataDirPath = Path.of(dataDir);

    // intentionally use assert side-effect assignment here. `Path.startsWith()` fails if the
    // argument is a different class, which is the case for `SolrCore.getInstancePath()`,
    // strictly in tests (lucene test-framework `FilterPath`).
    assert (instancePath = Path.of(instancePath.toUri())).getClass()
        == (dataDirPath = Path.of(dataDirPath.toUri())).getClass();

    tlogDir = ulogToTlogDir(core.getName(), dataDirPath, instancePath, core.getDataDir());

    maybeClearLog(core);

    // usage of tlog dir almost entirely bypasses `Directory` API; we only need to do this so that
    // we can remove the tlog dir via `DirectoryFactory.remove()`, which understands how to delete
    // in filesystem-specific ways.
    DirectoryFactory df = core.getDirectoryFactory();
    Directory d;
    try {
      d =
          df.get(
              tlogDir.toAbsolutePath().toString(),
              DirectoryFactory.DirContext.DEFAULT,
              DirectoryFactory.LOCK_TYPE_NONE);
      this.releaseTlogDir = () -> df.release(d);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }

    try {
      Files.createDirectories(tlogDir);
    } catch (IOException e) {
      throw new SolrException(ErrorCode.SERVER_ERROR, "Could not set up tlogs", e);
    }
    tlogFiles = getLogList(tlogDir);
    id = getLastLogId() + 1; // add 1 since we will create a new log for the next update

    if (debug) {
      log.debug(
          "UpdateHandler init: tlogDir={}, existing tlogs={}, next id={}",
          tlogDir,
          Arrays.asList(tlogFiles),
          id);
    }

    final String prefix = BUFFER_TLOG_NAME + '.';
    try (Stream<Path> bufferedTLogs = Files.walk(tlogDir, 1)) {
      existOldBufferLog =
          bufferedTLogs.anyMatch(path -> path.getFileName().toString().startsWith(prefix));
    } catch (IOException e) {
      // Existance of buffered t-logs indicates previous recovery failed and lets us skip peer sync
      // as an optimization. Failing to read them is non-fatal and almost not even worth logging
      // about
      log.debug(
          "Could not read {} directory searching for buffered transaction log files.", tlogDir, e);
      existOldBufferLog = false;
    }
    TransactionLog oldLog = null;
    for (String oldLogName : tlogFiles) {
      Path path = tlogDir.resolve(oldLogName);
      try {
        oldLog = newTransactionLog(path, null, true);
        // don't remove old logs on startup since more than one may be uncapped.
        addOldLog(oldLog, false);
      } catch (RuntimeException e) {
        // This could be a SolrException, why is it non-fatal?
        log.error("Failure to open existing log file (non fatal) {} ", path, e);
        deleteFile(path);
      }
    }

    // Record first two logs (oldest first) at startup for potential tlog recovery.
    // It's possible that at abnormal close both "tlog" and "prevTlog" were uncapped.
    for (TransactionLog ll : logs) {
      newestLogsOnStartup.addFirst(ll);
      if (newestLogsOnStartup.size() >= 2) break;
    }
  }

  @Override
  public void initializeMetrics(SolrMetricsContext parentContext, String scope) {
    solrMetricsContext = parentContext.getChildContext(this);
    bufferedOpsGauge =
        () -> {
          if (state == State.BUFFERING) {
            if (bufferTlog == null) return 0;
            // numRecords counts header as a record
            return bufferTlog.numRecords() - 1;
          }
          if (tlog == null) {
            return 0;
          } else if (state == State.APPLYING_BUFFERED) {
            // numRecords counts header as a record
            return tlog.numRecords()
                - 1
                - recoveryInfo.adds
                - recoveryInfo.deleteByQuery
                - recoveryInfo.deletes
                - recoveryInfo.errors.get();
          } else {
            return 0;
          }
        };

    solrMetricsContext.gauge(bufferedOpsGauge, true, "ops", scope, "buffered");
    solrMetricsContext.gauge(() -> logs.size(), true, "logs", scope, "replay", "remaining");
    solrMetricsContext.gauge(() -> getTotalLogsSize(), true, "bytes", scope, "replay", "remaining");
    applyingBufferedOpsMeter = solrMetricsContext.meter("ops", scope, "applyingBuffered");
    replayOpsMeter = solrMetricsContext.meter("ops", scope, "replay");
    copyOverOldUpdatesMeter = solrMetricsContext.meter("ops", scope, "copyOverOldUpdates");
    solrMetricsContext.gauge(() -> state.getValue(), true, "state", scope);
  }

  @Override
  public SolrMetricsContext getSolrMetricsContext() {
    return solrMetricsContext;
  }

  /**
   * Returns a new {@link org.apache.solr.update.TransactionLog}. Sub-classes can override this
   * method to change the implementation of the transaction log.
   */
  public TransactionLog newTransactionLog(
      Path tlogFile, Collection<String> globalStrings, boolean openExisting) {
    return new TransactionLog(tlogFile, globalStrings, openExisting);
  }

  public String getTlogDir() {
    return tlogDir.toAbsolutePath().toString();
  }

  public String getUlogDir() {
    return dataDir;
  }

  public List<Long> getStartingVersions() {
    return startingVersions;
  }

  public boolean existOldBufferLog() {
    return existOldBufferLog;
  }

  /* Takes over ownership of the log, keeping it until no longer needed
    and then decrementing its reference and dropping it.
  */
  protected synchronized void addOldLog(TransactionLog oldLog, boolean removeOld) {
    if (oldLog == null) return;

    numOldRecords += oldLog.numRecords();

    int currRecords = numOldRecords;

    if (oldLog != tlog && tlog != null) {
      currRecords += tlog.numRecords();
    }

    while (removeOld && logs.size() > 0) {
      TransactionLog log = logs.peekLast();
      int nrec = log.numRecords();
      // remove oldest log if we don't need it to keep at least numRecordsToKeep, or if
      // we already have the limit of 10 log files.
      if (currRecords - nrec >= numRecordsToKeep
          || (maxNumLogsToKeep > 0 && logs.size() >= maxNumLogsToKeep)) {
        currRecords -= nrec;
        numOldRecords -= nrec;
        logs.removeLast().decref(); // dereference so it will be deleted when no longer in use
        continue;
      }

      break;
    }

    // don't incref... we are taking ownership from the caller.
    logs.addFirst(oldLog);
  }

  /**
   * Does update from old tlogs (not from buffer tlog)? If yes we must skip writing {@code cmd} to
   * current tlog
   */
  private boolean updateFromOldTlogs(UpdateCommand cmd) {
    return (cmd.getFlags() & UpdateCommand.REPLAY) != 0 && state == State.REPLAYING;
  }

  public String[] getLogList(Path directory) {
    final String prefix = TLOG_NAME + '.';
    try (Stream<Path> files = Files.list(directory)) {
      return files
          .map((file) -> file.getFileName().toString())
          .filter((name) -> name.startsWith(prefix))
          .sorted()
          .toArray(String[]::new);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public long getLastLogId() {
    return id == -1 ? scanLastLogId(tlogFiles) : id;
  }

  static long scanLastLogId(String[] tlogFiles) {
    if (tlogFiles.length == 0) return -1;
    String last = tlogFiles[tlogFiles.length - 1];
    return Long.parseLong(last.substring(TLOG_NAME.length() + 1));
  }

  public void add(AddUpdateCommand cmd) {
    add(cmd, false);
  }

  public void add(AddUpdateCommand cmd, boolean clearCaches) {
    // don't log if we are replaying from another log
    // TODO: we currently need to log to maintain correct versioning, rtg, etc
    // if ((cmd.getFlags() & UpdateCommand.REPLAY) != 0) return;

    synchronized (this) {
      if ((cmd.getFlags() & UpdateCommand.BUFFERING) != 0) {
        ensureBufferTlog();
        bufferTlog.write(cmd);
        return;
      }

      long pos = -1;
      long prevPointer = getPrevPointerForUpdate(cmd);

      // don't log if we are replaying from another log
      if (!updateFromOldTlogs(cmd)) {
        ensureLog();
        pos = tlog.write(cmd, prevPointer);
      }

      if (!clearCaches) {
        // TODO: in the future we could support a real position for a REPLAY update.
        // Only currently would be useful for RTG while in recovery mode though.
        LogPtr ptr = new LogPtr(pos, cmd.getVersion(), prevPointer);

        map.put(cmd.getIndexedId(), ptr);

        if (trace) {
          log.trace(
              "TLOG: added id {} to {} {} map={}",
              cmd.getPrintableId(),
              tlog,
              ptr,
              System.identityHashCode(map));
        }

      } else {
        openRealtimeSearcher();
        if (log.isTraceEnabled()) {
          log.trace("TLOG: added id {} to {} clearCaches=true", cmd.getPrintableId(), tlog);
        }
      }
    }
  }

  /**
   * @return If cmd is an in-place update, then returns the pointer (in the tlog) of the previous
   *     update that the given update depends on. Returns -1 if this is not an in-place update, or
   *     if we can't find a previous entry in the tlog. Upon receiving a -1, it should be clear why
   *     it was -1: if the command's flags|UpdateLog.UPDATE_INPLACE is set, then this command is an
   *     in-place update whose previous update is in the index and not in the tlog; if that flag is
   *     not set, it is not an in-place update at all, and don't bother about the prevPointer value
   *     at all (which is -1 as a dummy value).)
   */
  private synchronized long getPrevPointerForUpdate(AddUpdateCommand cmd) {
    // note: sync required to ensure maps aren't changed out form under us
    if (cmd.isInPlaceUpdate()) {
      BytesRef indexedId = cmd.getIndexedId();
      for (Map<BytesRef, LogPtr> currentMap : Arrays.asList(map, prevMap, prevMap2)) {
        if (currentMap != null) {
          LogPtr prevEntry = currentMap.get(indexedId);
          if (null != prevEntry) {
            return prevEntry.pointer;
          }
        }
      }
    }
    return -1;
  }

  public void delete(DeleteUpdateCommand cmd) {
    BytesRef br = cmd.getIndexedId();

    synchronized (this) {
      if ((cmd.getFlags() & UpdateCommand.BUFFERING) != 0) {
        ensureBufferTlog();
        bufferTlog.writeDelete(cmd);
        return;
      }

      long pos = -1;
      if (!updateFromOldTlogs(cmd)) {
        ensureLog();
        pos = tlog.writeDelete(cmd);
      }

      LogPtr ptr = new LogPtr(pos, cmd.version);
      map.put(br, ptr);
      oldDeletes.put(br, ptr);

      if (trace) {
        log.trace(
            "TLOG: added delete for id {} to {} {} map={}",
            cmd.id,
            tlog,
            ptr,
            System.identityHashCode(map));
      }
    }
  }

  public void deleteByQuery(DeleteUpdateCommand cmd) {
    synchronized (this) {
      if ((cmd.getFlags() & UpdateCommand.BUFFERING) != 0) {
        ensureBufferTlog();
        bufferTlog.writeDeleteByQuery(cmd);
        return;
      }

      long pos = -1;
      if (!updateFromOldTlogs(cmd)) {
        ensureLog();
        pos = tlog.writeDeleteByQuery(cmd);
      }

      // skip purge our caches in case of tlog replica
      if ((cmd.getFlags() & UpdateCommand.IGNORE_INDEXWRITER) == 0) {
        // given that we just did a delete-by-query, we don't know what documents were
        // affected and hence we must purge our caches.
        openRealtimeSearcher();
        trackDeleteByQuery(cmd.getQuery(), cmd.getVersion());

        if (trace) {
          LogPtr ptr = new LogPtr(pos, cmd.getVersion());
          int hash = System.identityHashCode(map);
          log.trace("TLOG: added deleteByQuery {} to {} {} map = {}.", cmd.query, tlog, ptr, hash);
        }
      }
    }
  }

  /**
   * Opens a new realtime searcher and clears the id caches. This may also be called when we updates
   * are being buffered (from PeerSync/IndexFingerprint)
   */
  public void openRealtimeSearcher() {
    log.debug("openRealtimeSearcher");
    synchronized (this) {
      // We must cause a new IndexReader to be opened before anything looks at these caches again
      // so that a cache miss will read fresh data.
      try {
        RefCounted<SolrIndexSearcher> holder = uhandler.core.openNewSearcher(true, true);
        holder.decref();
      } catch (Exception e) {
        log.error("Error opening realtime searcher", e);
        return;
      }

      if (map != null) map.clear();
      if (prevMap != null) prevMap.clear();
      if (prevMap2 != null) prevMap2.clear();
    }
  }

  /** currently for testing only */
  public void deleteAll() {
    synchronized (this) {
      try {
        RefCounted<SolrIndexSearcher> holder = uhandler.core.openNewSearcher(true, true);
        holder.decref();
      } catch (Exception e) {
        log.error("Error opening realtime searcher for deleteByQuery", e);
      }

      if (map != null) map.clear();
      if (prevMap != null) prevMap.clear();
      if (prevMap2 != null) prevMap2.clear();

      oldDeletes.clear();
      deleteByQueries.clear();
    }
  }

  protected void trackDeleteByQuery(String q, long version) {
    version = Math.abs(version);
    DBQ dbq = new DBQ();
    dbq.q = q;
    dbq.version = version;

    synchronized (this) {
      if (deleteByQueries.isEmpty() || deleteByQueries.getFirst().version < version) {
        // common non-reordered case
        deleteByQueries.addFirst(dbq);
      } else {
        // find correct insertion point
        ListIterator<DBQ> iter = deleteByQueries.listIterator();
        iter.next(); // we already checked the first element in the previous "if" clause
        while (iter.hasNext()) {
          DBQ oldDBQ = iter.next();
          if (oldDBQ.version < version) {
            iter.previous();
            break;
          } else if (oldDBQ.version == version && oldDBQ.q.equals(q)) {
            // a duplicate
            return;
          }
        }
        iter.add(dbq); // this also handles the case of adding at the end when hasNext() == false
      }

      if (deleteByQueries.size() > numDeletesByQueryToKeep) {
        deleteByQueries.removeLast();
      }
    }
  }

  public List<DBQ> getDBQNewer(long version) {
    synchronized (this) {
      if (deleteByQueries.isEmpty() || deleteByQueries.getFirst().version < version) {
        // fast common case
        return null;
      }

      List<DBQ> dbqList = new ArrayList<>();
      for (DBQ dbq : deleteByQueries) {
        if (dbq.version <= version) break;
        dbqList.add(dbq);
      }
      return dbqList;
    }
  }

  protected void newMap() {
    prevMap2 = prevMap;
    prevMapLog2 = prevMapLog;

    prevMap = map;
    prevMapLog = tlog;

    map = new HashMap<>();
  }

  private void clearOldMaps() {
    prevMap = null;
    prevMap2 = null;
  }

  public boolean hasUncommittedChanges() {
    return tlog != null;
  }

  public void preCommit(CommitUpdateCommand cmd) {
    synchronized (this) {
      if (debug) {
        log.debug("TLOG: preCommit");
      }

      if (getState() != State.ACTIVE && (cmd.getFlags() & UpdateCommand.REPLAY) == 0) {
        // if we aren't in the active state, and this isn't a replay
        // from the recovery process, then we shouldn't mess with
        // the current transaction log.  This normally shouldn't happen
        // as DistributedUpdateProcessor will prevent this.  Commits
        // that don't use the processor are possible though.
        return;
      }

      // since we're changing the log, we must change the map.
      newMap();

      if (prevTlog != null) {
        globalStrings = prevTlog.getGlobalStrings();
      }

      // since document additions can happen concurrently with commit, create
      // a new transaction log first so that we know the old one is definitely
      // in the index.
      if (prevTlog != null) {
        // postCommit for prevTlog is not called, may be the index is corrupted
        // if we override prevTlog value, the correspond tlog will be leaked, close it first
        postCommit(cmd);
      }
      prevTlog = tlog;
      tlog = null;
      id++;
    }
  }

  public void postCommit(CommitUpdateCommand cmd) {
    synchronized (this) {
      if (debug) {
        log.debug("TLOG: postCommit");
      }
      if (prevTlog != null) {
        // if we made it through the commit, write a commit command to the log
        // TODO: check that this works to cap a tlog we were using to buffer so we don't replay on
        // startup.
        prevTlog.writeCommit(cmd);

        addOldLog(prevTlog, true);
        // the old log list will decref when no longer needed
        // prevTlog.decref();
        prevTlog = null;
      }
    }
  }

  public void preSoftCommit(CommitUpdateCommand cmd) {
    debug = log.isDebugEnabled(); // refresh our view of debugging occasionally
    trace = log.isTraceEnabled();

    synchronized (this) {
      if (!cmd.softCommit) return; // already handled this at the start of the hard commit
      newMap();

      // start adding documents to a new map since we won't know if
      // any added documents will make it into this commit or not.
      // But we do know that any updates already added will definitely
      // show up in the latest reader after the commit succeeds.
      map = new HashMap<>();

      if (debug) {
        log.debug(
            "TLOG: preSoftCommit: prevMap={} new map={}",
            System.identityHashCode(prevMap),
            System.identityHashCode(map));
      }
    }
  }

  public void postSoftCommit(CommitUpdateCommand cmd) {
    synchronized (this) {
      // We can clear out all old maps now that a new searcher has been opened.
      // This currently only works since DUH2 synchronizes around preCommit to avoid
      // it being called in the middle of a preSoftCommit, postSoftCommit sequence.
      // If this DUH2 synchronization were to be removed, preSoftCommit should
      // record what old maps were created and only remove those.

      if (debug) {
        SolrCore.verbose(
            "TLOG: postSoftCommit: disposing of prevMap="
                + System.identityHashCode(prevMap)
                + ", prevMap2="
                + System.identityHashCode(prevMap2));
      }
      clearOldMaps();
    }
  }

  /**
   * Goes over backwards, following the prevPointer, to merge all partial updates into the passed
   * doc. Stops at either a full document, or if there are no previous entries to follow in the
   * update log.
   *
   * @param id Binary representation of the unique key field
   * @param prevPointer Pointer to the previous entry in the ulog, based on which the current
   *     in-place update was made.
   * @param prevVersion Version of the previous entry in the ulog, based on which the current
   *     in-place update was made.
   * @param onlyTheseFields When a non-null set of field names is passed in, the resolve process
   *     only attempts to populate the given fields in this set. When this set is null, it resolves
   *     all fields.
   * @param latestPartialDoc Partial document that is to be populated
   * @return Returns 0 if a full document was found in the log, -1 if no full document was found. If
   *     full document was supposed to be found in the tlogs, but couldn't be found (because the
   *     logs were rotated) then the prevPointer is returned.
   */
  @SuppressWarnings({"unchecked"})
  public synchronized long applyPartialUpdates(
      BytesRef id,
      long prevPointer,
      long prevVersion,
      Set<String> onlyTheseFields,
      SolrDocumentBase<?, ?> latestPartialDoc) {

    SolrInputDocument partialUpdateDoc = null;

    List<TransactionLog> lookupLogs = Arrays.asList(tlog, prevMapLog, prevMapLog2);
    while (prevPointer >= 0) {
      // go through each partial update and apply it on the incoming doc one after another
      List<?> entry;
      entry = getEntryFromTLog(prevPointer, prevVersion, lookupLogs);
      if (entry == null) {
        // a previous update was supposed to be found, but wasn't found (due to log rotation)
        return prevPointer;
      }
      int flags = (int) entry.get(UpdateLog.FLAGS_IDX);

      // since updates can depend only upon ADD updates or other UPDATE_INPLACE updates, we assert
      // that we aren't getting something else
      if ((flags & UpdateLog.ADD) != UpdateLog.ADD
          && (flags & UpdateLog.UPDATE_INPLACE) != UpdateLog.UPDATE_INPLACE) {
        throw new SolrException(
            ErrorCode.INVALID_STATE,
            entry
                + " should've been either ADD or UPDATE_INPLACE update"
                + ", while looking for id="
                + new String(id.bytes, StandardCharsets.UTF_8));
      }
      // if this is an ADD (i.e. full document update), stop here
      if ((flags & UpdateLog.ADD) == UpdateLog.ADD) {
        partialUpdateDoc = (SolrInputDocument) entry.get(entry.size() - 1);
        applyOlderUpdates(latestPartialDoc, partialUpdateDoc, onlyTheseFields);
        return 0; // Full document was found in the tlog itself
      }
      if (entry.size() < 5) {
        throw new SolrException(
            ErrorCode.INVALID_STATE,
            entry
                + " is not a partial doc"
                + ", while looking for id="
                + new String(id.bytes, StandardCharsets.UTF_8));
      }
      // This update is an inplace update, get the partial doc. The input doc is always at last
      // position.
      partialUpdateDoc = (SolrInputDocument) entry.get(entry.size() - 1);
      applyOlderUpdates(latestPartialDoc, partialUpdateDoc, onlyTheseFields);
      prevPointer = (long) entry.get(UpdateLog.PREV_POINTER_IDX);
      prevVersion = (long) entry.get(UpdateLog.PREV_VERSION_IDX);

      if (onlyTheseFields != null && latestPartialDoc.keySet().containsAll(onlyTheseFields)) {
        return 0; // all the onlyTheseFields have been resolved, safe to abort now.
      }
    }

    return -1; // last full document is not supposed to be in tlogs, but it must be in the index
  }

  /** Add all fields from olderDoc into newerDoc if not already present in newerDoc */
  private void applyOlderUpdates(
      SolrDocumentBase<?, ?> newerDoc, SolrInputDocument olderDoc, Set<String> mergeFields) {
    for (String fieldName : olderDoc.getFieldNames()) {
      // if the newerDoc has this field, then this field from olderDoc can be ignored
      if (!newerDoc.containsKey(fieldName)
          && (mergeFields == null || mergeFields.contains(fieldName))) {
        Collection<Object> values = olderDoc.getFieldValues(fieldName);
        if (values == null) {
          newerDoc.addField(fieldName, null);
        } else {
          for (Object val : values) {
            newerDoc.addField(fieldName, val);
          }
        }
      }
    }
  }

  /**
   * Get the entry that has the given lookupVersion in the given lookupLogs at the lookupPointer
   * position.
   *
   * @return The entry if found, otherwise null
   */
  private synchronized List<?> getEntryFromTLog(
      long lookupPointer, long lookupVersion, List<TransactionLog> lookupLogs) {
    for (TransactionLog lookupLog : lookupLogs) {
      if (lookupLog != null && lookupLog.getLogSize() > lookupPointer) {
        lookupLog.incref();
        try {
          Object obj = null;

          try {
            obj = lookupLog.lookup(lookupPointer);
          } catch (Exception | Error ex) {
            // This can happen when trying to deserialize the entry at position lookupPointer,
            // but from a different tlog than the one containing the desired entry.
            // Just ignore the exception, so as to proceed to the next tlog.
            log.debug(
                "Exception reading the log (this is expected, don't worry)={}, for version={}. This can be ignored",
                lookupLog,
                lookupVersion);
          }

          if (obj != null && obj instanceof List<?> tmpEntry) {
            if (tmpEntry.size() >= 2
                &&
                // why not Objects.equals(lookupVersion, tmpEntry.get())?
                (tmpEntry.get(UpdateLog.VERSION_IDX) instanceof Long)
                && ((Long) tmpEntry.get(UpdateLog.VERSION_IDX)).equals(lookupVersion)) {
              return tmpEntry;
            }
          }
        } finally {
          lookupLog.decref();
        }
      }
    }
    return null;
  }

  public Object lookup(BytesRef indexedId) {
    LogPtr entry;
    TransactionLog lookupLog;

    synchronized (this) {
      entry = map.get(indexedId);
      lookupLog = tlog; // something found in "map" will always be in "tlog"
      // SolrCore.verbose("TLOG: lookup: for id ",indexedId.utf8ToString(),"in
      // map",System.identityHashCode(map),"got",entry,"lookupLog=",lookupLog);
      if (entry == null && prevMap != null) {
        entry = prevMap.get(indexedId);
        // something found in prevMap will always be found in prevMapLog (which could be tlog or
        // prevTlog)
        lookupLog = prevMapLog;
        // SolrCore.verbose("TLOG: lookup: for id ",indexedId.utf8ToString(),"in
        // prevMap",System.identityHashCode(map),"got",entry,"lookupLog=",lookupLog);
      }
      if (entry == null && prevMap2 != null) {
        entry = prevMap2.get(indexedId);
        // something found in prevMap2 will always be found in prevMapLog2 (which could be tlog or
        // prevTlog)
        lookupLog = prevMapLog2;
        // SolrCore.verbose("TLOG: lookup: for id ",indexedId.utf8ToString(),"in
        // prevMap2",System.identityHashCode(map),"got",entry,"lookupLog=",lookupLog);
      }

      if (entry == null) {
        return null;
      }
      lookupLog.incref();
    }

    try {
      // now do the lookup outside of the sync block for concurrency
      return lookupLog.lookup(entry.pointer);
    } finally {
      lookupLog.decref();
    }
  }

  // This method works like realtime-get... it only guarantees to return the latest
  // version of the *completed* update.  There can be updates in progress concurrently
  // that have already grabbed higher version numbers.  Higher level coordination or
  // synchronization is needed for stronger guarantees (as VersionUpdateProcessor does).
  public Long lookupVersion(BytesRef indexedId) {
    LogPtr entry;
    TransactionLog lookupLog;

    synchronized (this) {
      entry = map.get(indexedId);
      lookupLog = tlog; // something found in "map" will always be in "tlog"
      // SolrCore.verbose("TLOG: lookup ver: for id ",indexedId.utf8ToString(),"in
      // map",System.identityHashCode(map),"got",entry,"lookupLog=",lookupLog);
      if (entry == null && prevMap != null) {
        entry = prevMap.get(indexedId);
        // something found in prevMap will always be found in prevMapLog (which could be tlog or
        // prevTlog)
        lookupLog = prevMapLog;
        // SolrCore.verbose("TLOG: lookup ver: for id ",indexedId.utf8ToString(),"in
        // prevMap",System.identityHashCode(map),"got",entry,"lookupLog=",lookupLog);
      }
      if (entry == null && prevMap2 != null) {
        entry = prevMap2.get(indexedId);
        // something found in prevMap2 will always be found in prevMapLog2 (which could be tlog or
        // prevTlog)
        lookupLog = prevMapLog2;
        // SolrCore.verbose("TLOG: lookup ver: for id ",indexedId.utf8ToString(),"in
        // prevMap2",System.identityHashCode(map),"got",entry,"lookupLog=",lookupLog);
      }
    }

    if (entry != null) {
      return entry.version;
    }

    // Now check real index
    Long version = versionInfo.getVersionFromIndex(indexedId);

    if (version != null) {
      return version;
    }

    // We can't get any version info for deletes from the index, so if the doc
    // wasn't found, check a cache of recent deletes.

    synchronized (this) {
      entry = oldDeletes.get(indexedId);
    }

    if (entry != null) {
      return entry.version;
    }

    return null;
  }

  public void finish(SyncLevel syncLevel) {
    if (syncLevel == null) {
      syncLevel = defaultSyncLevel;
    }
    if (syncLevel == SyncLevel.NONE) {
      return;
    }

    TransactionLog currLog;
    synchronized (this) {
      currLog = tlog;
      if (currLog == null) return;
      currLog.incref();
    }

    try {
      currLog.finish(syncLevel);
    } finally {
      currLog.decref();
    }
  }

  public Future<RecoveryInfo> recoverFromLog() {
    recoveryInfo = new RecoveryInfo();

    List<TransactionLog> recoverLogs = new ArrayList<>(1);
    for (TransactionLog ll : newestLogsOnStartup) {
      if (!ll.try_incref()) continue;

      try {
        if (ll.endsWithCommit()) {
          ll.closeOutput();
          ll.decref();
          continue;
        }
      } catch (IOException e) {
        log.error("Error inspecting tlog {}", ll, e);
        ll.closeOutput();
        ll.decref();
        continue;
      }

      recoverLogs.add(ll);
    }

    if (recoverLogs.isEmpty()) return null;

    ExecutorCompletionService<RecoveryInfo> cs = new ExecutorCompletionService<>(recoveryExecutor);
    LogReplayer replayer = new LogReplayer(recoverLogs, false);

    updateLocks.blockUpdates();
    try {
      state = State.REPLAYING;

      // The deleteByQueries and oldDeletes lists
      // would've been populated by items from the logs themselves (which we
      // will replay now). So lets clear them out here before the replay.
      deleteByQueries.clear();
      oldDeletes.clear();
    } finally {
      updateLocks.unblockUpdates();
    }

    // At this point, we are guaranteed that any new updates coming in will see the state as
    // "replaying"

    return cs.submit(replayer, recoveryInfo);
  }

  /**
   * Replay current tlog, so all updates will be written to index. This is must do task for a tlog
   * replica become a new leader.
   *
   * @return future of this task
   */
  public Future<RecoveryInfo> recoverFromCurrentLog() {
    if (tlog == null) {
      return null;
    }
    map.clear();
    recoveryInfo = new RecoveryInfo();
    tlog.incref();

    ExecutorCompletionService<RecoveryInfo> cs = new ExecutorCompletionService<>(recoveryExecutor);
    LogReplayer replayer = new LogReplayer(Collections.singletonList(tlog), false, true);

    updateLocks.blockUpdates();
    try {
      state = State.REPLAYING;
    } finally {
      updateLocks.unblockUpdates();
    }

    return cs.submit(replayer, recoveryInfo);
  }

  /**
   * Block updates, append a commit at current tlog, then copy over buffer updates to new tlog and
   * bring back ulog to active state. So any updates which hasn't made it to the index is preserved
   * in the current tlog, this also make RTG work
   *
   * @param cuc any updates that have version larger than the version of cuc will be copied over
   */
  public void copyOverBufferingUpdates(CommitUpdateCommand cuc) {
    updateLocks.blockUpdates();
    try {
      synchronized (this) {
        state = State.ACTIVE;
        if (bufferTlog == null) {
          return;
        }
        // by calling this, we won't switch to new tlog (compared to applyBufferedUpdates())
        // if we switch to new tlog we can possible lose updates on the next fetch
        copyOverOldUpdates(cuc.getVersion(), bufferTlog);
        dropBufferTlog();
      }
    } finally {
      updateLocks.unblockUpdates();
    }
  }

  /**
   * Block updates, append a commit at current tlog, then copy over updates to a new tlog. So any
   * updates which hasn't made it to the index is preserved in the current tlog
   *
   * @param cuc any updates that have version larger than the version of cuc will be copied over
   */
  public void commitAndSwitchToNewTlog(CommitUpdateCommand cuc) {
    updateLocks.blockUpdates();
    try {
      synchronized (this) {
        if (tlog == null) {
          return;
        }
        preCommit(cuc);
        try {
          copyOverOldUpdates(cuc.getVersion());
        } finally {
          postCommit(cuc);
        }
      }
    } finally {
      updateLocks.unblockUpdates();
    }
  }

  public void copyOverOldUpdates(long commitVersion) {
    TransactionLog oldTlog = prevTlog;
    if (oldTlog == null && !logs.isEmpty()) {
      oldTlog = logs.getFirst();
    }
    if (oldTlog == null || oldTlog.refcount.get() == 0) {
      return;
    }

    try {
      if (oldTlog.endsWithCommit()) return;
    } catch (IOException e) {
      log.warn("Exception reading log", e);
      return;
    }
    copyOverOldUpdates(commitVersion, oldTlog);
  }

  /**
   * Copy over updates from prevTlog or last tlog (in tlog folder) to a new tlog
   *
   * @param commitVersion any updates that have version larger than the commitVersion will be copied
   *     over
   */
  public void copyOverOldUpdates(long commitVersion, TransactionLog oldTlog) {
    copyOverOldUpdatesMeter.mark();

    SolrQueryRequest req = new LocalSolrQueryRequest(uhandler.core, new ModifiableSolrParams());
    TransactionLog.LogReader logReader = null;
    Object o = null;
    try {
      logReader = oldTlog.getReader(0);
      while ((o = logReader.next()) != null) {
        try {
          List<?> entry = (List<?>) o;
          int operationAndFlags = (Integer) entry.get(0);
          int oper = operationAndFlags & OPERATION_MASK;
          long version = (Long) entry.get(1);
          if (Math.abs(version) > commitVersion) {
            switch (oper) {
              case UpdateLog.UPDATE_INPLACE:
              case UpdateLog.ADD:
                {
                  AddUpdateCommand cmd =
                      convertTlogEntryToAddUpdateCommand(req, entry, oper, version);
                  cmd.setFlags(UpdateCommand.IGNORE_AUTOCOMMIT);
                  add(cmd);
                  break;
                }
              case UpdateLog.DELETE:
                {
                  byte[] idBytes = (byte[]) entry.get(2);
                  DeleteUpdateCommand cmd = new DeleteUpdateCommand(req);
                  cmd.setIndexedId(new BytesRef(idBytes));
                  cmd.setVersion(version);
                  cmd.setFlags(UpdateCommand.IGNORE_AUTOCOMMIT);
                  delete(cmd);
                  break;
                }

              case UpdateLog.DELETE_BY_QUERY:
                {
                  String query = (String) entry.get(2);
                  DeleteUpdateCommand cmd = new DeleteUpdateCommand(req);
                  cmd.query = query;
                  cmd.setVersion(version);
                  cmd.setFlags(UpdateCommand.IGNORE_AUTOCOMMIT);
                  deleteByQuery(cmd);
                  break;
                }

              default:
                throw new SolrException(
                    SolrException.ErrorCode.SERVER_ERROR, "Unknown Operation! " + oper);
            }
          }
        } catch (ClassCastException e) {
          log.warn("Unexpected log entry or corrupt log.  Entry={}", o, e);
        }
      }
      // Prev tlog will be closed, so nullify prevMap
      if (prevTlog == oldTlog) {
        prevMap = null;
      }
    } catch (IOException e) {
      log.error("Exception reading versions from log", e);
    } catch (InterruptedException e) {
      log.warn("Exception reading log", e);
    } finally {
      if (logReader != null) logReader.close();
    }
  }

  protected void ensureBufferTlog() {
    if (bufferTlog != null) return;
    String newLogName =
        String.format(Locale.ROOT, LOG_FILENAME_PATTERN, BUFFER_TLOG_NAME, System.nanoTime());
    bufferTlog = newTransactionLog(tlogDir.resolve(newLogName), globalStrings, false);
    bufferTlog.isBuffer = true;
  }

  // Cleanup old buffer tlogs
  protected void deleteBufferLogs() {
    try (Stream<Path> tlogs = Files.walk(tlogDir, 1)) {
      final String prefix = BUFFER_TLOG_NAME + '.';
      tlogs
          .filter(Files::isRegularFile)
          .filter(path -> path.getFileName().toString().startsWith(prefix))
          .forEach(UpdateLog::deleteFile);
    } catch (IOException e) {
      log.warn("Could not clean up buffered transaction logs in {}", tlogDir, e);
    }
  }

  /**
   * Ensures a transaction log is ready. It is either the current one, or a new one. This method
   * must be called with the synchronization monitor on this {@link UpdateLog}.
   */
  protected void ensureLog() {
    if (tlog == null) {
      Path newLogPath;
      int numAttempts = 0;
      while (true) {
        String newLogName = String.format(Locale.ROOT, LOG_FILENAME_PATTERN, TLOG_NAME, id);
        newLogPath = tlogDir.resolve(newLogName);
        // We expect that the log file does not exist since id is designed to give the index of the
        // next transaction log to create. But in very rare cases, the log files listed in the
        // init() method may be stale here (file system delay?), and id may point to an existing
        // file.
        if (!Files.exists(newLogPath)) {
          break;
        }
        // If the "new" log file already exists, refresh the log list and recompute id.
        // Ideally we would want to include the missing log in the old logs tracking (see init()),
        // but the init() method is not designed to be executed twice. Given that in the rare cases
        // we have seen this missing log, the log was always empty (file size 0), then we simply
        // refresh log list and update the id.
        try {
          log.error(
              "New transaction log already exists {} size={}, skipping it",
              newLogPath,
              Files.size(newLogPath));
        } catch (IOException e) {
          log.error("New transaction log already exists {} size unknown, skipping it", newLogPath);
        }
        if (++numAttempts >= 2) {
          throw new SolrException(
              ErrorCode.SERVER_ERROR, "Cannot recover from already existing logs");
        }
        tlogFiles = getLogList(tlogDir);
        id = scanLastLogId(tlogFiles) + 1; // add 1 since we create a new log
      }
      tlog = newTransactionLog(newLogPath, globalStrings, false);
    }
  }

  private void doClose(TransactionLog theLog, boolean writeCommit) {
    if (theLog != null) {
      if (writeCommit) {
        // record a commit
        log.info("Recording current closed for {} log={}", uhandler.core, theLog);
        CommitUpdateCommand cmd =
            new CommitUpdateCommand(
                new LocalSolrQueryRequest(
                    uhandler.core, new ModifiableSolrParams((SolrParams) null)),
                false);
        theLog.writeCommit(cmd);
      }

      theLog.deleteOnClose = false;
      theLog.decref();
      theLog.forceClose();
    }
  }

  public void close(boolean committed) {
    close(committed, false);
  }

  @SuppressWarnings("try")
  public void close(boolean committed, boolean deleteOnClose) {
    try (Closeable c = releaseTlogDir) {
      recoveryExecutor.shutdown(); // no new tasks

      synchronized (this) {

        // Don't delete the old tlogs, we want to be able to replay from them and retrieve old
        // versions

        doClose(prevTlog, committed);
        doClose(tlog, committed);

        for (TransactionLog log : logs) {
          if (log == prevTlog || log == tlog) continue;
          log.deleteOnClose = false;
          log.decref();
          log.forceClose();
        }

        if (bufferTlog != null) {
          // should not delete bufferTlog on close, existing bufferTlog is a sign for skip peerSync
          bufferTlog.deleteOnClose = false;
          bufferTlog.decref();
          bufferTlog.forceClose();
        }
      }

      try {
        ExecutorUtil.shutdownAndAwaitTermination(recoveryExecutor);
      } catch (Exception e) {
        log.error("Exception shutting down recoveryExecutor", e);
      }
    } catch (IOException e) {
      log.warn("exception releasing tlog dir", e);
    }
  }

  protected static class Update {
    public TransactionLog log;
    long version;
    long previousVersion; // for in-place updates
    public long pointer;
  }

  protected static class DeleteUpdate {
    public long version;
    public byte[] id;

    public DeleteUpdate(long version, byte[] id) {
      this.version = version;
      this.id = id;
    }
  }

  public class RecentUpdates implements Closeable {
    final Deque<TransactionLog> logList; // newest first
    List<List<Update>> updateList;
    HashMap<Long, Update> updates;
    public List<Update> deleteByQueryList;
    public List<DeleteUpdate> deleteList;
    Set<Long> bufferUpdates = new HashSet<>();

    public RecentUpdates(Deque<TransactionLog> logList) {
      this.logList = logList;
      boolean success = false;
      try {
        update();
        success = true;
      } finally {
        // defensive: if some unknown exception is thrown,
        // make sure we close so that the tlogs are decref'd
        if (!success) {
          close();
        }
      }
    }

    public List<Long> getVersions(int n) {
      return getVersions(n, Long.MAX_VALUE);
    }

    public Set<Long> getBufferUpdates() {
      return Collections.unmodifiableSet(bufferUpdates);
    }

    public List<Long> getVersions(int n, long maxVersion) {
      List<Long> ret = new ArrayList<>(n);
      LongSet set = new LongHashSet(n);
      final int nInput = n;

      for (List<Update> singleList : updateList) {
        for (Update ptr : singleList) {
          if (Math.abs(ptr.version) > Math.abs(maxVersion)) continue;
          if (!set.add(ptr.version)) {
            if (debug) {
              log.debug(
                  "getVersions(n={}, maxVersion={}) not returning duplicate version = {}",
                  nInput,
                  maxVersion,
                  ptr.version);
            }
            continue;
          }
          ret.add(ptr.version);
          if (--n <= 0) return ret;
        }
      }

      return ret;
    }

    public Object lookup(long version) {
      Update update = updates.get(version);
      if (update == null) return null;

      return update.log.lookup(update.pointer);
    }

    /** Returns the list of deleteByQueries that happened after the given version */
    public List<Object> getDeleteByQuery(long afterVersion, LongSet updateVersions) {
      List<Object> result = new ArrayList<>(deleteByQueryList.size());
      for (Update update : deleteByQueryList) {
        if (Math.abs(update.version) > afterVersion) {
          if (updateVersions.add(update.version)) {
            Object dbq = update.log.lookup(update.pointer);
            result.add(dbq);
          } else {
            if (debug) {
              log.debug(
                  "UpdateLog.RecentUpdates.getDeleteByQuery(afterVersion={}) not returning duplicate version = {}",
                  afterVersion,
                  update.version);
            }
          }
        }
      }
      return result;
    }

    private void update() {
      int numUpdates = 0;
      updateList = new ArrayList<>(logList.size());
      deleteByQueryList = new ArrayList<>();
      deleteList = new ArrayList<>();
      updates = CollectionUtil.newHashMap(numRecordsToKeep);

      for (TransactionLog oldLog : logList) {
        List<Update> updatesForLog = new ArrayList<>();

        TransactionLog.ReverseReader reader = null;
        try {
          reader = oldLog.getReverseReader();

          while (numUpdates < numRecordsToKeep) {
            Object o = null;
            try {
              o = reader.next();
              if (o == null) break;

              // should currently be a List<Oper,Ver,Doc/Id>
              List<?> entry = (List<?>) o;

              // TODO: refactor this out so we get common error handling
              int opAndFlags = (Integer) entry.get(UpdateLog.FLAGS_IDX);
              int oper = opAndFlags & UpdateLog.OPERATION_MASK;
              long version = (Long) entry.get(UpdateLog.VERSION_IDX);

              if (oldLog.isBuffer) bufferUpdates.add(version);

              switch (oper) {
                case UpdateLog.ADD:
                case UpdateLog.UPDATE_INPLACE:
                case UpdateLog.DELETE:
                case UpdateLog.DELETE_BY_QUERY:
                  Update update = new Update();
                  update.log = oldLog;
                  update.pointer = reader.position();
                  update.version = version;

                  if (oper == UpdateLog.UPDATE_INPLACE) {
                    if (entry.size() == 5) {
                      update.previousVersion = (Long) entry.get(UpdateLog.PREV_VERSION_IDX);
                    }
                  }
                  updatesForLog.add(update);
                  updates.put(version, update);

                  if (oper == UpdateLog.DELETE_BY_QUERY) {
                    deleteByQueryList.add(update);
                  } else if (oper == UpdateLog.DELETE) {
                    deleteList.add(new DeleteUpdate(version, (byte[]) entry.get(2)));
                  }

                  break;

                case UpdateLog.COMMIT:
                  break;
                default:
                  throw new SolrException(
                      SolrException.ErrorCode.SERVER_ERROR, "Unknown Operation! " + oper);
              }
            } catch (ClassCastException cl) {
              log.warn("Unexpected log entry or corrupt log.  Entry={}", o, cl);
              // would be caused by a corrupt transaction log
            } catch (Exception ex) {
              log.warn("Exception reverse reading log", ex);
              break;
            }

            numUpdates++;
          }

        } catch (IOException | AssertionError e) {
          // catch AssertionError to handle certain test failures correctly failure to read a log
          // record isn't fatal
          log.error("Exception reading versions from log", e);
        } finally {
          if (reader != null) reader.close();
        }

        updateList.add(updatesForLog);
      }
    }

    @Override
    public void close() {
      for (TransactionLog log : logList) {
        log.decref();
      }
    }

    public long getMaxRecentVersion() {
      long maxRecentVersion = 0L;
      if (updates != null) {
        for (Long key : updates.keySet())
          maxRecentVersion = Math.max(maxRecentVersion, Math.abs(key.longValue()));
      }
      return maxRecentVersion;
    }
  }

  /** The RecentUpdates object returned must be closed after use */
  public RecentUpdates getRecentUpdates() {
    Deque<TransactionLog> logList;
    synchronized (this) {
      logList = new ArrayDeque<>(logs);
      for (TransactionLog log : logList) {
        log.incref();
      }
      if (prevTlog != null) {
        prevTlog.incref();
        logList.addFirst(prevTlog);
      }
      if (tlog != null) {
        tlog.incref();
        logList.addFirst(tlog);
      }
      if (bufferTlog != null) {
        bufferTlog.incref();
        logList.addFirst(bufferTlog);
      }
    }

    // TODO: what if I hand out a list of updates, then do an update, then hand out another list
    // (and one of the updates I originally handed out fell off the list).  Over-request?
    return new RecentUpdates(logList);
  }

  public void bufferUpdates() {
    // recovery trips this assert under some race - even when it checks the state first
    // assert state == State.ACTIVE;

    // block all updates to eliminate race conditions
    // reading state and acting on it in the distributed update processor
    updateLocks.blockUpdates();
    try {
      if (state != State.ACTIVE && state != State.BUFFERING) {
        // we don't currently have support for handling other states
        log.warn("Unexpected state for bufferUpdates: {}, Ignoring request", state);
        return;
      }
      dropBufferTlog();
      deleteBufferLogs();

      recoveryInfo = new RecoveryInfo();

      if (log.isInfoEnabled()) {
        log.info("Starting to buffer updates. {}", this);
      }

      state = State.BUFFERING;
    } finally {
      updateLocks.unblockUpdates();
    }
  }

  /** Returns true if we were able to drop buffered updates and return to the ACTIVE state */
  public boolean dropBufferedUpdates() {
    updateLocks.blockUpdates();
    try {
      if (state != State.BUFFERING) return false;

      if (log.isInfoEnabled()) {
        log.info("Dropping buffered updates {}", this);
      }

      dropBufferTlog();

      state = State.ACTIVE;
    } finally {
      updateLocks.unblockUpdates();
    }
    return true;
  }

  private void dropBufferTlog() {
    synchronized (this) {
      if (bufferTlog != null) {
        bufferTlog.decref();
        bufferTlog = null;
      }
    }
  }

  /** Returns the Future to wait on, or null if no replay was needed */
  public Future<RecoveryInfo> applyBufferedUpdates() {
    // recovery trips this assert under some race - even when
    // it checks the state first
    // assert state == State.BUFFERING;

    // block all updates to eliminate race conditions
    // reading state and acting on it in the update processor
    updateLocks.blockUpdates();
    try {
      cancelApplyBufferUpdate = false;
      if (state != State.BUFFERING) return null;

      synchronized (this) {
        // handle case when no updates were received.
        if (bufferTlog == null) {
          state = State.ACTIVE;
          return null;
        }
        bufferTlog.incref();
      }

      state = State.APPLYING_BUFFERED;
    } finally {
      updateLocks.unblockUpdates();
    }

    if (ExecutorUtil.isShutdown(recoveryExecutor)) {
      throw new RuntimeException("executor is not running...");
    }
    ExecutorCompletionService<RecoveryInfo> cs = new ExecutorCompletionService<>(recoveryExecutor);
    LogReplayer replayer = new LogReplayer(Collections.singletonList(bufferTlog), true);
    return cs.submit(
        () -> {
          replayer.run();
          dropBufferTlog();
        },
        recoveryInfo);
  }

  public State getState() {
    return state;
  }

  @Override
  public String toString() {
    return "FSUpdateLog{state=" + getState() + ", tlog=" + tlog + "}";
  }

  public static Runnable testing_logReplayHook; // called before each log read
  public static Runnable testing_logReplayFinishHook; // called when log replay has finished

  protected RecoveryInfo recoveryInfo;

  class LogReplayer implements Runnable {
    private final SolrParams BASE_REPLAY_PARAMS =
        new MapSolrParams(
            Map.of(
                DISTRIB_UPDATE_PARAM,
                FROMLEADER.toString(),
                DistributedUpdateProcessor.LOG_REPLAY,
                "true"));

    private Logger loglog = log; // set to something different?

    Deque<TransactionLog> translogs;
    TransactionLog.LogReader tlogReader;
    boolean activeLog;
    // state where we lock out other updates and finish those updates that snuck in before we locked
    boolean finishing = false;
    boolean debug = loglog.isDebugEnabled();
    boolean inSortedOrder;

    public LogReplayer(List<TransactionLog> translogs, boolean activeLog) {
      this.translogs = new ArrayDeque<>();
      this.translogs.addAll(translogs);
      this.activeLog = activeLog;
    }

    public LogReplayer(List<TransactionLog> translogs, boolean activeLog, boolean inSortedOrder) {
      this(translogs, activeLog);
      this.inSortedOrder = inSortedOrder;
    }

    private SolrQueryRequest req;
    private SolrQueryResponse rsp;

    @Override
    public void run() {
      req = new LocalSolrQueryRequest(uhandler.core, BASE_REPLAY_PARAMS);
      rsp = new SolrQueryResponse();
      // setting request info will help logging
      SolrRequestInfo.setRequestInfo(new SolrRequestInfo(req, rsp));

      try {
        for (; ; ) {
          TransactionLog translog = translogs.pollFirst();
          if (translog == null) break;
          doReplay(translog);
        }
      } catch (SolrException e) {
        if (e.code() == ErrorCode.SERVICE_UNAVAILABLE.code) {
          log.error("Replay failed service unavailable", e);
          recoveryInfo.failed = true;
        } else {
          recoveryInfo.errors.incrementAndGet();
          log.error("Replay failed due to exception", e);
        }
      } catch (Exception e) {
        recoveryInfo.errors.incrementAndGet();
        log.error("Replay failed due to exception", e);
      } finally {
        // change the state while updates are still blocked to prevent races
        state = State.ACTIVE;
        if (finishing) {
          updateLocks.unblockUpdates();
        }

        // clean up in case we hit some unexpected exception and didn't get
        // to more transaction logs
        for (TransactionLog translog : translogs) {
          log.error("ERROR: didn't get to recover from tlog {}", translog);
          translog.decref();
        }
      }

      loglog.warn("Log replay finished. recoveryInfo={}", recoveryInfo);

      if (testing_logReplayFinishHook != null) testing_logReplayFinishHook.run();

      SolrRequestInfo.clearRequestInfo();
    }

    public void doReplay(TransactionLog translog) {
      try {
        loglog.warn(
            "Starting log replay {}  active={} starting pos={} inSortedOrder={}",
            translog,
            activeLog,
            recoveryInfo.positionOfStart,
            inSortedOrder);
        long lastStatusTime = System.nanoTime();
        try {
          if (inSortedOrder) {
            tlogReader = translog.getSortedReader(recoveryInfo.positionOfStart);
          } else {
            tlogReader = translog.getReader(recoveryInfo.positionOfStart);
          }
        } catch (IOException e) {
          throw new UncheckedIOException(e);
        }

        // NOTE: we don't currently handle a core reload during recovery.  This would cause the core
        // to change underneath us.

        // Use a pool of URPs using a ThreadLocal to have them per-thread.  URPs aren't threadsafe.
        UpdateRequestProcessorChain processorChain = req.getCore().getUpdateProcessingChain(null);
        Collection<UpdateRequestProcessor> procPool =
            Collections.synchronizedList(new ArrayList<>());
        ThreadLocal<UpdateRequestProcessor> procThreadLocal =
            ThreadLocal.withInitial(
                () -> {
                  // SolrQueryRequest is not thread-safe, so use a copy when creating URPs
                  final var localRequest =
                      new LocalSolrQueryRequest(uhandler.core, BASE_REPLAY_PARAMS);
                  var proc = processorChain.createProcessor(localRequest, rsp);
                  procPool.add(proc);
                  return proc;
                });

        OrderedExecutor<BytesRef> executor =
            inSortedOrder ? null : req.getCoreContainer().getReplayUpdatesExecutor();
        AtomicInteger pendingTasks = new AtomicInteger(0);
        AtomicReference<SolrException> exceptionOnExecuteUpdate = new AtomicReference<>();

        long commitVersion = 0;
        int operationAndFlags = 0;
        long nextCount = 0;

        for (; ; ) {
          Object o = null;
          if (cancelApplyBufferUpdate) break;
          try {
            if (testing_logReplayHook != null) testing_logReplayHook.run();
            if (nextCount++ % 1000 == 0) {
              long now = System.nanoTime();
              if (now - lastStatusTime > STATUS_TIME) {
                lastStatusTime = now;
                long cpos = tlogReader.currentPos();
                long csize = tlogReader.currentSize();
                if (log.isInfoEnabled()) {
                  loglog.info(
                      "log replay status {} active={} starting pos={} current pos={} current size={} % read={}",
                      translog,
                      activeLog,
                      recoveryInfo.positionOfStart,
                      cpos,
                      csize,
                      Math.floor(cpos / (double) csize * 100.));
                }
              }
            }

            o = null;
            o = tlogReader.next();
            if (o == null && activeLog) {
              if (!finishing) {
                // about to block all the updates including the tasks in the executor
                // therefore we must wait for them to be finished
                waitForAllUpdatesGetExecuted(pendingTasks);
                // from this point, remain updates will be executed in a single thread
                executor = null;
                // block to prevent new adds, but don't immediately unlock since
                // we could be starved from ever completing recovery.  Only unlock
                // after we've finished this recovery.
                // NOTE: our own updates won't be blocked since the thread holding a write lock can
                // lock a read lock.
                updateLocks.blockUpdates();
                finishing = true;
                o = tlogReader.next();
              } else {
                // we had previously blocked updates, so this "null" from the log is final.

                // Wait until our final commit to change the state and unlock.
                // This is only so no new updates are written to the current log file, and is
                // only an issue if we crash before the commit (and we are paying attention
                // to incomplete log files).
                //
                // versionInfo.unblockUpdates();
              }
            }
          } catch (Exception e) {
            log.error("Exception during replay", e);
          }

          if (o == null) break;
          // fail fast
          if (exceptionOnExecuteUpdate.get() != null) throw exceptionOnExecuteUpdate.get();

          try {

            // should currently be a List<Oper,Ver,Doc/Id>
            List<?> entry = (List<?>) o;
            operationAndFlags = (Integer) entry.get(UpdateLog.FLAGS_IDX);
            int oper = operationAndFlags & OPERATION_MASK;
            long version = (Long) entry.get(UpdateLog.VERSION_IDX);

            switch (oper) {
              case UpdateLog.UPDATE_INPLACE: // fall through to ADD
              case UpdateLog.ADD:
                {
                  recoveryInfo.adds++;
                  AddUpdateCommand cmd =
                      convertTlogEntryToAddUpdateCommand(req, entry, oper, version);
                  cmd.setFlags(UpdateCommand.REPLAY | UpdateCommand.IGNORE_AUTOCOMMIT);
                  if (debug) log.debug("{} {}", oper == ADD ? "add" : "update", cmd);
                  execute(cmd, executor, pendingTasks, procThreadLocal, exceptionOnExecuteUpdate);
                  break;
                }
              case UpdateLog.DELETE:
                {
                  recoveryInfo.deletes++;
                  byte[] idBytes = (byte[]) entry.get(2);
                  DeleteUpdateCommand cmd = new DeleteUpdateCommand(req);
                  cmd.setIndexedId(new BytesRef(idBytes));
                  cmd.setVersion(version);
                  cmd.setFlags(UpdateCommand.REPLAY | UpdateCommand.IGNORE_AUTOCOMMIT);
                  if (debug) log.debug("delete {}", cmd);
                  execute(cmd, executor, pendingTasks, procThreadLocal, exceptionOnExecuteUpdate);
                  break;
                }

              case UpdateLog.DELETE_BY_QUERY:
                {
                  recoveryInfo.deleteByQuery++;
                  String query = (String) entry.get(2);
                  DeleteUpdateCommand cmd = new DeleteUpdateCommand(req);
                  cmd.query = query;
                  cmd.setVersion(version);
                  cmd.setFlags(UpdateCommand.REPLAY | UpdateCommand.IGNORE_AUTOCOMMIT);
                  if (debug) log.debug("deleteByQuery {}", cmd);
                  waitForAllUpdatesGetExecuted(pendingTasks);
                  // DBQ will be executed in the same thread
                  execute(cmd, null, pendingTasks, procThreadLocal, exceptionOnExecuteUpdate);
                  break;
                }
              case UpdateLog.COMMIT:
                {
                  commitVersion = version;
                  break;
                }

              default:
                throw new SolrException(
                    SolrException.ErrorCode.SERVER_ERROR, "Unknown Operation! " + oper);
            }

            if (rsp.getException() != null) {
              loglog.error("REPLAY_ERR: Exception replaying log {}", rsp.getException());
              throw rsp.getException();
            }
            if (state == State.REPLAYING) {
              replayOpsMeter.mark();
            } else if (state == State.APPLYING_BUFFERED) {
              applyingBufferedOpsMeter.mark();
            } else {
              // XXX should not happen?
            }
          } catch (ClassCastException cl) {
            recoveryInfo.errors.incrementAndGet();
            loglog.warn("REPLAY_ERR: Unexpected log entry or corrupt log.  Entry={}", o, cl);
            // would be caused by a corrupt transaction log
          } catch (Exception ex) {
            recoveryInfo.errors.incrementAndGet();
            loglog.warn("REPLAY_ERR: Exception replaying log", ex);
            // something wrong with the request?
          }
          assert TestInjection.injectUpdateLogReplayRandomPause();
        }

        waitForAllUpdatesGetExecuted(pendingTasks);
        if (exceptionOnExecuteUpdate.get() != null) throw exceptionOnExecuteUpdate.get();

        CommitUpdateCommand cmd = new CommitUpdateCommand(req, false);
        cmd.setVersion(commitVersion);
        cmd.softCommit = false;
        cmd.waitSearcher = true;
        cmd.setFlags(UpdateCommand.REPLAY);
        try {
          if (debug) log.debug("commit {}", cmd);
          // this should cause a commit to be added to the incomplete log and avoid it being
          // replayed again after a restart.
          uhandler.commit(cmd);
        } catch (IOException ex) {
          recoveryInfo.errors.incrementAndGet();
          loglog.error("Replay exception: final commit.", ex);
        }

        if (!activeLog) {
          // if we are replaying an old tlog file, we need to add a commit to the end
          // so we don't replay it again if we restart right after.
          translog.writeCommit(cmd);
        }

        for (UpdateRequestProcessor proc : procPool) {
          try {
            proc.finish();
          } catch (IOException ex) {
            recoveryInfo.errors.incrementAndGet();
            loglog.error("Replay exception: finish()", ex);
          } finally {
            IOUtils.closeQuietly(proc);
          }
        }

      } finally {
        if (tlogReader != null) tlogReader.close();
        translog.decref();
      }
    }

    private void waitForAllUpdatesGetExecuted(AtomicInteger pendingTasks) {
      TimeOut timeOut =
          new TimeOut(Integer.MAX_VALUE, TimeUnit.MILLISECONDS, TimeSource.CURRENT_TIME);
      try {
        timeOut.waitFor(
            "Timeout waiting for replay updates finish",
            () -> {
              // TODO handle the case when there are no progress after a long time
              return pendingTasks.get() == 0;
            });
      } catch (TimeoutException e) {
        throw new SolrException(ErrorCode.SERVER_ERROR, e);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new SolrException(ErrorCode.SERVER_ERROR, e);
      }
    }

    private BytesRef getIndexedId(UpdateCommand cmd) {
      if (cmd instanceof AddUpdateCommand) {
        return ((AddUpdateCommand) cmd).getIndexedId();
      }
      if (cmd instanceof DeleteUpdateCommand) {
        return ((DeleteUpdateCommand) cmd).getIndexedId();
      }
      return null;
    }

    private void execute(
        UpdateCommand cmd,
        OrderedExecutor<BytesRef> executor,
        AtomicInteger pendingTasks,
        ThreadLocal<UpdateRequestProcessor> procTl,
        AtomicReference<SolrException> exceptionHolder) {
      assert cmd instanceof AddUpdateCommand || cmd instanceof DeleteUpdateCommand;

      if (executor != null) {
        executor.execute(
            getIndexedId(cmd),
            () -> {
              try {
                // fail fast
                if (exceptionHolder.get() != null) return;
                invokeCmdOnProc(cmd, procTl.get());
              } catch (IOException e) {
                recoveryInfo.errors.incrementAndGet();
                loglog.warn("REPLAY_ERR: IOException reading log", e);
                // could be caused by an incomplete flush if recovering from log
              } catch (SolrException e) {
                if (e.code() == ErrorCode.SERVICE_UNAVAILABLE.code) {
                  exceptionHolder.compareAndSet(null, e);
                  return;
                }
                recoveryInfo.errors.incrementAndGet();
                loglog.warn("REPLAY_ERR: SolrException reading log", e);
              } finally {
                pendingTasks.decrementAndGet();
              }
            });
        pendingTasks.incrementAndGet();
      } else {
        try {
          invokeCmdOnProc(cmd, procTl.get());
        } catch (IOException e) {
          recoveryInfo.errors.incrementAndGet();
          loglog.warn("REPLAY_ERR: IOException replaying log", e);
          // could be caused by an incomplete flush if recovering from log
        } catch (SolrException e) {
          if (e.code() == ErrorCode.SERVICE_UNAVAILABLE.code) {
            throw e;
          }
          recoveryInfo.errors.incrementAndGet();
          loglog.warn("REPLAY_ERR: SolrException replaying log", e);
        }
      }
    }

    private void invokeCmdOnProc(UpdateCommand cmd, UpdateRequestProcessor proc)
        throws IOException {
      if (cmd instanceof AddUpdateCommand) {
        proc.processAdd((AddUpdateCommand) cmd);
      } else {
        proc.processDelete((DeleteUpdateCommand) cmd);
      }
    }
  }

  /**
   * Given a entry from the transaction log containing a document, return a new AddUpdateCommand
   * that can be applied to ADD the document or do an UPDATE_INPLACE.
   *
   * @param req The request to use as the owner of the new AddUpdateCommand
   * @param entry Entry from the transaction log that contains the document to be added
   * @param operation The value of the operation flag; this must be either ADD or UPDATE_INPLACE --
   *     if it is UPDATE_INPLACE then the previous version will also be read from the entry
   * @param version Version already obtained from the entry.
   */
  public static AddUpdateCommand convertTlogEntryToAddUpdateCommand(
      SolrQueryRequest req, List<?> entry, int operation, long version) {
    assert operation == UpdateLog.ADD || operation == UpdateLog.UPDATE_INPLACE;
    SolrInputDocument sdoc = (SolrInputDocument) entry.get(entry.size() - 1);
    AddUpdateCommand cmd = new AddUpdateCommand(req);
    cmd.solrDoc = sdoc;
    cmd.setVersion(version);

    if (operation == UPDATE_INPLACE) {
      long prevVersion = (Long) entry.get(UpdateLog.PREV_VERSION_IDX);
      cmd.prevVersion = prevVersion;
    }
    return cmd;
  }

  ThreadPoolExecutor recoveryExecutor =
      new ExecutorUtil.MDCAwareThreadPoolExecutor(
          0,
          Integer.MAX_VALUE,
          1,
          TimeUnit.SECONDS,
          new SynchronousQueue<Runnable>(),
          new SolrNamedThreadFactory("recoveryExecutor"));

  public static void deleteFile(Path file) {
    boolean success = false;
    try {
      Files.deleteIfExists(file);
      success = true;
    } catch (Exception e) {
      log.error("Error deleting file: {}", file, e);
    }

    if (!success) {
      try {
        PathUtils.deleteOnExit(file);
      } catch (Exception e) {
        log.error("Error deleting file on exit: {}", file, e);
      }
    }
  }

  /** Clears the logs on the file system. Only call before init. */
  public void clearLog() {
    Path tlogPath = tlogDir;
    if (Files.exists(tlogPath)) {
      try (Stream<Path> paths = Files.walk(tlogPath)) {
        paths
            .filter(Files::isRegularFile)
            .forEach(
                path -> {
                  try {
                    Files.delete(path);
                  } catch (IOException cause) {
                    // NOTE: still throws SecurityException as before.
                    log.error("Could not remove tlog file: {}", path, cause);
                  }
                });
      } catch (IOException e) {
        log.error("Could not clear old tlogs in {}", tlogPath);
      }
    }
  }

  @SuppressForbidden(reason = "extends linkedhashmap")
  private static class OldDeletesLinkedHashMap extends LinkedHashMap<BytesRef, LogPtr> {
    private final int numDeletesToKeepInternal;

    public OldDeletesLinkedHashMap(int numDeletesToKeep) {
      super(numDeletesToKeep);
      this.numDeletesToKeepInternal = numDeletesToKeep;
    }

    @Override
    protected boolean removeEldestEntry(Map.Entry<BytesRef, LogPtr> eldest) {
      return size() > numDeletesToKeepInternal;
    }
  }
}
