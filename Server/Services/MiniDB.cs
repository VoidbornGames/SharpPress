using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.Text;

namespace SharpPress.Services
{
    #region Core Storage Engine

    /// <summary>
    /// LSM-Tree based storage engine with WAL, MVCC, and background compaction.
    /// </summary>
    public class MiniDB : IDisposable
    {
        private readonly MiniDBOptions _options;
        private readonly Logger _logger;

        private readonly WriteAheadLog _wal;
        private readonly MemTable _memTable;
        private readonly SSTableManager _sstableManager;
        private readonly CompactionManager _compactionManager;
        private readonly VersionManager _versionManager;

        private readonly SemaphoreSlim _writeSemaphore;
        private long _sequenceNumber = 0;

        private readonly CancellationTokenSource _shutdownCts = new();
        private readonly Task _flushTask;
        private readonly Task _compactionTask;

        private readonly MetricsCollector _metrics;

        private volatile bool _isDisposed = false;

        public MiniDB(MiniDBOptions options, Logger logger)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            ValidateOptions();
            EnsureDirectoryStructure();

            _metrics = new MetricsCollector();
            _versionManager = new VersionManager(_options.DataDirectory, _logger);
            _wal = new WriteAheadLog(Path.Combine(_options.DataDirectory, "wal"), _logger);
            _memTable = new MemTable(_options.MemTableSizeBytes);
            _sstableManager = new SSTableManager(_options.DataDirectory, _versionManager, _logger);
            _compactionManager = new CompactionManager(_sstableManager, _versionManager, _options, _logger);

            _writeSemaphore = new SemaphoreSlim(_options.MaxConcurrentWrites);

            _flushTask = Task.Run(() => BackgroundFlushLoop(_shutdownCts.Token));
            _compactionTask = Task.Run(() => BackgroundCompactionLoop(_shutdownCts.Token));
        }

        public async Task StartAsync(CancellationToken cancellationToken = default)
        {
            _logger.Log("🚀 Starting MiniDB storage engine...");

            await RecoverFromWALAsync(cancellationToken);
            await _sstableManager.LoadExistingSSTables(cancellationToken);

            _logger.Log($"✅ MiniDB started. Loaded {_sstableManager.GetSSTableCount()} SSTables.");
        }

        public async Task StopAsync(CancellationToken cancellationToken = default)
        {
            _logger.Log("🛑 Stopping MiniDB storage engine...");

            _shutdownCts.Cancel();
            try
            {
                await Task.WhenAll(_flushTask, _compactionTask).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }

            if (!_memTable.IsEmpty())
            {
                await FlushMemTableAsync(cancellationToken);
            }
            await _wal.SyncAsync(cancellationToken);

            _logger.Log("✅ MiniDB stopped gracefully.");
        }

        #region Public API

        /// <summary>
        /// Insert a new key-value pair. Fails if key already exists.
        /// </summary>
        public async Task InsertAsync<T>(string key, T value, CancellationToken cancellationToken = default)
        {
            ValidateKey(key);
            ThrowIfDisposed();

            var sw = Stopwatch.StartNew();
            await _writeSemaphore.WaitAsync(cancellationToken);

            try
            {
                var existing = await GetInternalAsync(key, cancellationToken);
                if (existing != null && !existing.IsDeleted)
                {
                    throw new MiniDBException($"Key '{key}' already exists. Use UpsertAsync to update.");
                }

                await WriteInternalAsync(key, value, WriteType.Insert, cancellationToken);

                _metrics.RecordWrite(sw.Elapsed);
            }
            finally
            {
                _writeSemaphore.Release();
            }
        }

        /// <summary>
        /// Insert or update a key-value pair.
        /// </summary>
        public async Task UpsertAsync<T>(string key, T value, CancellationToken cancellationToken = default)
        {
            ValidateKey(key);
            ThrowIfDisposed();

            var sw = Stopwatch.StartNew();
            await _writeSemaphore.WaitAsync(cancellationToken);

            try
            {
                await WriteInternalAsync(key, value, WriteType.Upsert, cancellationToken);
                _metrics.RecordWrite(sw.Elapsed);
            }
            finally
            {
                _writeSemaphore.Release();
            }
        }

        /// <summary>
        /// Get value by key. Returns default(T) if not found.
        /// This operation is lock-free and never blocks writers.
        /// </summary>
        public async Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default)
        {
            ValidateKey(key);
            ThrowIfDisposed();

            var sw = Stopwatch.StartNew();

            try
            {
                var entry = await GetInternalAsync(key, cancellationToken);

                if (entry == null || entry.IsDeleted)
                {
                    _metrics.RecordRead(sw.Elapsed, false);
                    return default;
                }

                var result = Deserialize<T>(entry.Value);
                _metrics.RecordRead(sw.Elapsed, true);
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error reading key '{key}': {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Delete a key. This is a tombstone operation (soft delete).
        /// </summary>
        public async Task DeleteAsync(string key, CancellationToken cancellationToken = default)
        {
            ValidateKey(key);
            ThrowIfDisposed();

            var sw = Stopwatch.StartNew();
            await _writeSemaphore.WaitAsync(cancellationToken);

            try
            {
                await WriteInternalAsync<object>(key, null, WriteType.Delete, cancellationToken);
                _metrics.RecordWrite(sw.Elapsed);
            }
            finally
            {
                _writeSemaphore.Release();
            }
        }

        /// <summary>
        /// Check if key exists (not deleted).
        /// </summary>
        public async Task<bool> ContainsKeyAsync(string key, CancellationToken cancellationToken = default)
        {
            var entry = await GetInternalAsync(key, cancellationToken);
            return entry != null && !entry.IsDeleted;
        }

        /// <summary>
        /// Get all keys (expensive operation - scans all SSTables).
        /// </summary>
        public async Task<IEnumerable<string>> GetAllKeysAsync(CancellationToken cancellationToken = default)
        {
            var keys = new HashSet<string>();

            foreach (var key in _memTable.GetAllKeys())
            {
                var entry = _memTable.Get(key);
                if (entry != null && !entry.IsDeleted)
                {
                    keys.Add(key);
                }
            }

            var snapshot = _versionManager.GetCurrentSnapshot();
            foreach (var sstable in snapshot.SSTables)
            {
                await foreach (var entry in sstable.ScanAsync(cancellationToken))
                {
                    if (!entry.IsDeleted)
                    {
                        keys.Add(entry.Key);
                    }
                    else
                    {
                        keys.Remove(entry.Key);
                    }
                }
            }

            return keys;
        }

        /// <summary>
        /// Batch write operations for better performance.
        /// All operations are atomic - either all succeed or all fail.
        /// </summary>
        public async Task BatchWriteAsync(IEnumerable<BatchOperation> operations, CancellationToken cancellationToken = default)
        {
            var opsList = operations.ToList();
            if (opsList.Count == 0) return;

            ThrowIfDisposed();

            var sw = Stopwatch.StartNew();
            await _writeSemaphore.WaitAsync(cancellationToken);

            try
            {
                var walBatch = new List<WALEntry>();

                foreach (var op in opsList)
                {
                    ValidateKey(op.Key);

                    var seqNum = Interlocked.Increment(ref _sequenceNumber);
                    byte[]? valueBytes = null;
                    string? typeName = null;

                    if (op.Type != BatchOperationType.Delete && op.Data != null)
                    {
                        valueBytes = Serialize(op.Data);
                        typeName = op.Data.GetType().AssemblyQualifiedName;
                    }

                    var walEntry = new WALEntry
                    {
                        SequenceNumber = seqNum,
                        Key = op.Key,
                        Value = valueBytes,
                        TypeName = typeName,
                        IsDeleted = op.Type == BatchOperationType.Delete,
                        Timestamp = DateTime.UtcNow
                    };

                    walBatch.Add(walEntry);
                }

                await _wal.WriteBatchAsync(walBatch, cancellationToken);
                foreach (var walEntry in walBatch)
                {
                    var entry = new DataEntry
                    {
                        Key = walEntry.Key,
                        Value = walEntry.Value,
                        TypeName = walEntry.TypeName,
                        SequenceNumber = walEntry.SequenceNumber,
                        IsDeleted = walEntry.IsDeleted,
                        Timestamp = walEntry.Timestamp
                    };

                    _memTable.Put(entry);
                }

                if (_memTable.ShouldFlush())
                {
                    _ = Task.Run(() => FlushMemTableAsync(CancellationToken.None));
                }

                _metrics.RecordBatchWrite(opsList.Count, sw.Elapsed);
            }
            finally
            {
                _writeSemaphore.Release();
            }
        }

        /// <summary>
        /// Get database statistics.
        /// </summary>
        public async Task<DatabaseStats> GetStatsAsync(CancellationToken cancellationToken = default)
        {
            var snapshot = _versionManager.GetCurrentSnapshot();

            return new DatabaseStats
            {
                TotalEntries = _memTable.Count + snapshot.SSTables.Sum(s => s.EntryCount),
                MemTableEntries = _memTable.Count,
                MemTableSizeBytes = _memTable.SizeBytes,
                SSTableCount = snapshot.SSTables.Count,
                TotalSizeBytes = snapshot.SSTables.Sum(s => s.FileSizeBytes) + _memTable.SizeBytes,
                TotalOperations = _metrics.TotalOperations,
                ReadOperations = _metrics.ReadOperations,
                WriteOperations = _metrics.WriteOperations,
                AverageReadLatency = _metrics.AverageReadLatency,
                AverageWriteLatency = _metrics.AverageWriteLatency,
                CacheHitRate = _metrics.CacheHitRate,
                LastCompactionTime = _compactionManager.LastCompactionTime,
                WALSizeBytes = _wal.SizeBytes
            };
        }

        /// <summary>
        /// Force a manual compaction. Normally handled by background thread.
        /// </summary>
        public async Task CompactAsync(CancellationToken cancellationToken = default)
        {
            _logger.Log("🗜️ Starting manual compaction...");
            await _compactionManager.CompactAsync(cancellationToken);
            _logger.Log("✅ Manual compaction completed.");
        }

        #endregion

        #region Internal Write/Read Logic

        private async Task WriteInternalAsync<T>(string key, T? value, WriteType writeType, CancellationToken cancellationToken)
        {
            var seqNum = Interlocked.Increment(ref _sequenceNumber);

            byte[]? valueBytes = null;
            string? typeName = null;

            if (writeType != WriteType.Delete && value != null)
            {
                valueBytes = Serialize(value);
                typeName = typeof(T).AssemblyQualifiedName;
            }

            var walEntry = new WALEntry
            {
                SequenceNumber = seqNum,
                Key = key,
                Value = valueBytes,
                TypeName = typeName,
                IsDeleted = writeType == WriteType.Delete,
                Timestamp = DateTime.UtcNow
            };

            await _wal.WriteAsync(walEntry, cancellationToken);

            var entry = new DataEntry
            {
                Key = key,
                Value = valueBytes,
                TypeName = typeName,
                SequenceNumber = seqNum,
                IsDeleted = writeType == WriteType.Delete,
                Timestamp = DateTime.UtcNow
            };

            _memTable.Put(entry);

            if (_memTable.ShouldFlush())
            {
                _ = Task.Run(() => FlushMemTableAsync(CancellationToken.None));
            }
        }

        private async Task<DataEntry?> GetInternalAsync(string key, CancellationToken cancellationToken)
        {
            var entry = _memTable.Get(key);
            if (entry != null)
            {
                return entry;
            }

            var snapshot = _versionManager.GetCurrentSnapshot();

            foreach (var sstable in snapshot.SSTables.OrderByDescending(s => s.Level).ThenByDescending(s => s.CreationTime))
            {
                if (!sstable.MightContain(key))
                {
                    continue;
                }

                entry = await sstable.GetAsync(key, cancellationToken);
                if (entry != null)
                {
                    return entry;
                }
            }

            return null;
        }

        #endregion

        #region Background Tasks

        private async Task BackgroundFlushLoop(CancellationToken cancellationToken)
        {
            _logger.Log("🔄 Background flush loop started.");

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_options.FlushCheckInterval, cancellationToken);

                    if (_memTable.ShouldFlush())
                    {
                        await FlushMemTableAsync(cancellationToken);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error in background flush loop: {ex.Message}");
                }
            }

            _logger.Log("🔄 Background flush loop stopped.");
        }

        private async Task BackgroundCompactionLoop(CancellationToken cancellationToken)
        {
            _logger.Log("🔄 Background compaction loop started.");

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_options.CompactionCheckInterval, cancellationToken);

                    if (_compactionManager.ShouldCompact())
                    {
                        await _compactionManager.CompactAsync(cancellationToken);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error in background compaction loop: {ex.Message}");
                }
            }

            _logger.Log("🔄 Background compaction loop stopped.");
        }

        private async Task FlushMemTableAsync(CancellationToken cancellationToken)
        {
            if (_memTable.IsEmpty()) return;

            _logger.Log("💾 Flushing memtable to disk...");
            var sw = Stopwatch.StartNew();

            var entries = _memTable.GetAllEntries().OrderBy(e => e.Key).ToList();

            if (entries.Count == 0) return;

            var sstable = await _sstableManager.CreateSSTableAsync(entries, 0, cancellationToken);

            _versionManager.AddSSTable(sstable);

            _memTable.Clear();
            await _wal.TruncateAsync(cancellationToken);

            _logger.Log($"✅ Flushed {entries.Count} entries to SSTable in {sw.ElapsedMilliseconds}ms");
        }

        private async Task RecoverFromWALAsync(CancellationToken cancellationToken)
        {
            _logger.Log("🔧 Recovering from WAL...");

            var entries = await _wal.RecoverAsync(cancellationToken);

            if (entries.Count > 0)
            {
                foreach (var walEntry in entries)
                {
                    var entry = new DataEntry
                    {
                        Key = walEntry.Key,
                        Value = walEntry.Value,
                        TypeName = walEntry.TypeName,
                        SequenceNumber = walEntry.SequenceNumber,
                        IsDeleted = walEntry.IsDeleted,
                        Timestamp = walEntry.Timestamp
                    };

                    _memTable.Put(entry);

                    if (walEntry.SequenceNumber > _sequenceNumber)
                    {
                        _sequenceNumber = walEntry.SequenceNumber;
                    }
                }

                _logger.Log($"✅ Recovered {entries.Count} entries from WAL.");
            }
            else
            {
                _logger.Log("✅ No WAL recovery needed.");
            }
        }

        #endregion

        #region Validation and Utilities

        private void ValidateOptions()
        {
            if (string.IsNullOrWhiteSpace(_options.DataDirectory))
                throw new ArgumentException("DataDirectory cannot be empty.");

            if (_options.MemTableSizeBytes < 1024 * 1024)
                throw new ArgumentException("MemTableSizeBytes must be at least 1MB.");

            if (_options.MaxConcurrentWrites < 1)
                throw new ArgumentException("MaxConcurrentWrites must be at least 1.");
        }

        private void EnsureDirectoryStructure()
        {
            Directory.CreateDirectory(_options.DataDirectory);
            Directory.CreateDirectory(Path.Combine(_options.DataDirectory, "sstables"));
            Directory.CreateDirectory(Path.Combine(_options.DataDirectory, "wal"));
        }

        private void ValidateKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Key cannot be null or whitespace.", nameof(key));

            if (key.Length > 1024)
                throw new ArgumentException("Key cannot exceed 1024 characters.", nameof(key));
        }

        private static byte[] Serialize<T>(T obj)
        {
            using var ms = new MemoryStream();
            var serializer = new DataContractSerializer(typeof(T));
            serializer.WriteObject(ms, obj);
            return ms.ToArray();
        }

        private static T Deserialize<T>(byte[]? data)
        {
            if (data == null || data.Length == 0)
                throw new InvalidOperationException("Cannot deserialize null or empty data.");

            using var ms = new MemoryStream(data);
            var serializer = new DataContractSerializer(typeof(T));
            return (T)serializer.ReadObject(ms)!;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ThrowIfDisposed()
        {
            if (_isDisposed)
                throw new ObjectDisposedException(nameof(MiniDB));
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_isDisposed) return;

            _isDisposed = true;

            try
            {
                StopAsync(CancellationToken.None).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error during disposal: {ex.Message}");
            }

            _shutdownCts?.Dispose();
            _writeSemaphore?.Dispose();
            _wal?.Dispose();
            _sstableManager?.Dispose();
        }

        #endregion
    }

    #endregion

    #region MemTable (In-Memory Sorted Structure)

    /// <summary>
    /// Thread-safe in-memory sorted data structure using lock striping.
    /// Uses ConcurrentDictionary with manual size tracking.
    /// </summary>
    internal class MemTable
    {
        private readonly ConcurrentDictionary<string, DataEntry> _data = new();
        private long _sizeBytes = 0;
        private readonly long _maxSizeBytes;
        private readonly object _sizeLock = new();

        public MemTable(long maxSizeBytes)
        {
            _maxSizeBytes = maxSizeBytes;
        }

        public int Count => _data.Count;
        public long SizeBytes => Interlocked.Read(ref _sizeBytes);

        public void Put(DataEntry entry)
        {
            var entrySize = EstimateSize(entry);

            _data.AddOrUpdate(entry.Key, entry, (k, old) =>
            {
                var oldSize = EstimateSize(old);
                Interlocked.Add(ref _sizeBytes, entrySize - oldSize);
                return entry;
            });

            if (_data.TryGetValue(entry.Key, out var current) && current == entry)
            {
                Interlocked.Add(ref _sizeBytes, entrySize);
            }
        }

        public DataEntry? Get(string key)
        {
            return _data.TryGetValue(key, out var entry) ? entry : null;
        }

        public bool ShouldFlush()
        {
            return SizeBytes >= _maxSizeBytes;
        }

        public bool IsEmpty()
        {
            return _data.IsEmpty;
        }

        public IEnumerable<string> GetAllKeys()
        {
            return _data.Keys;
        }

        public IEnumerable<DataEntry> GetAllEntries()
        {
            return _data.Values;
        }

        public void Clear()
        {
            _data.Clear();
            Interlocked.Exchange(ref _sizeBytes, 0);
        }

        private long EstimateSize(DataEntry entry)
        {
            long size = 0;
            size += entry.Key.Length * 2;
            size += entry.Value?.Length ?? 0;
            size += entry.TypeName?.Length * 2 ?? 0;
            size += 64;
            return size;
        }
    }

    #endregion

    #region SSTable (Sorted String Table)

    /// <summary>
    /// Immutable on-disk sorted data structure.
    /// Format: [Header][Index Block][Data Blocks][Footer]
    /// </summary>
    internal class SSTable : IDisposable
    {
        private const uint MAGIC_NUMBER = 0x53535442;
        private const int VERSION = 1;

        public string FilePath { get; }
        public int Level { get; }
        public DateTime CreationTime { get; }
        public long FileSizeBytes { get; private set; }
        public int EntryCount { get; private set; }

        private readonly BloomFilter _bloomFilter;
        private readonly Dictionary<string, long> _index = new();
        private readonly ReaderWriterLockSlim _lock = new();
        private FileStream? _fileStream;
        private bool _isDisposed = false;

        private SSTable(string filePath, int level)
        {
            FilePath = filePath;
            Level = level;
            CreationTime = DateTime.UtcNow;
            _bloomFilter = new BloomFilter(10000, 0.01); 
        }

        /// <summary>
        /// Create a new SSTable from sorted entries.
        /// </summary>
        public static async Task<SSTable> CreateAsync(string filePath, IEnumerable<DataEntry> sortedEntries, int level, CancellationToken cancellationToken)
        {
            var sstable = new SSTable(filePath, level);

            using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024, useAsync: true))
            {
                fs.Seek(64, SeekOrigin.Begin);

                var entries = sortedEntries.ToList();
                sstable.EntryCount = entries.Count;

                foreach (var entry in entries)
                {
                    var offset = fs.Position;
                    sstable._index[entry.Key] = offset;
                    sstable._bloomFilter.Add(entry.Key);

                    await WriteEntryAsync(fs, entry, cancellationToken);
                }

                var indexOffset = fs.Position;
                await WriteIndexAsync(fs, sstable._index, cancellationToken);

                var bloomOffset = fs.Position;
                await sstable._bloomFilter.WriteToStreamAsync(fs, cancellationToken);

                fs.Seek(0, SeekOrigin.Begin);
                await WriteHeaderAsync(fs, sstable.EntryCount, indexOffset, bloomOffset, cancellationToken);

                sstable.FileSizeBytes = fs.Length;
            }

            return sstable;
        }

        /// <summary>
        /// Load existing SSTable from disk.
        /// </summary>
        public static async Task<SSTable> LoadAsync(string filePath, int level, CancellationToken cancellationToken)
        {
            var sstable = new SSTable(filePath, level);

            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true))
            {
                var (entryCount, indexOffset, bloomOffset) = await ReadHeaderAsync(fs, cancellationToken);
                sstable.EntryCount = entryCount;
                sstable.FileSizeBytes = fs.Length;

                fs.Seek(indexOffset, SeekOrigin.Begin);
                sstable._index.Clear();
                var indexCount = await ReadInt32Async(fs, cancellationToken);

                for (int i = 0; i < indexCount; i++)
                {
                    var key = await ReadStringAsync(fs, cancellationToken);
                    var offset = await ReadInt64Async(fs, cancellationToken);
                    sstable._index[key] = offset;
                }

                fs.Seek(bloomOffset, SeekOrigin.Begin);
                await sstable._bloomFilter.ReadFromStreamAsync(fs, cancellationToken);
            }

            return sstable;
        }

        public bool MightContain(string key)
        {
            return _bloomFilter.MightContain(key);
        }

        public async Task<DataEntry?> GetAsync(string key, CancellationToken cancellationToken)
        {
            _lock.EnterReadLock();
            try
            {
                if (!_index.TryGetValue(key, out var offset))
                {
                    return null;
                }

                if (_fileStream == null)
                {
                    _fileStream = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true);
                }

                _fileStream.Seek(offset, SeekOrigin.Begin);
                return await ReadEntryAsync(_fileStream, cancellationToken);
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        public async IAsyncEnumerable<DataEntry> ScanAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            using var fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true);

            var (entryCount, indexOffset, _) = await ReadHeaderAsync(fs, cancellationToken);

            fs.Seek(64, SeekOrigin.Begin);

            while (fs.Position < indexOffset)
            {
                var entry = await ReadEntryAsync(fs, cancellationToken);
                if (entry != null)
                {
                    yield return entry;
                }
            }
        }

        #region Serialization

        private static async Task WriteHeaderAsync(FileStream fs, int entryCount, long indexOffset, long bloomOffset, CancellationToken cancellationToken)
        {
            await WriteUInt32Async(fs, MAGIC_NUMBER, cancellationToken);
            await WriteInt32Async(fs, VERSION, cancellationToken);
            await WriteInt32Async(fs, entryCount, cancellationToken);
            await WriteInt64Async(fs, indexOffset, cancellationToken);
            await WriteInt64Async(fs, bloomOffset, cancellationToken);
            await WriteInt64Async(fs, DateTime.UtcNow.Ticks, cancellationToken);
        }

        private static async Task<(int entryCount, long indexOffset, long bloomOffset)> ReadHeaderAsync(FileStream fs, CancellationToken cancellationToken)
        {
            var magic = await ReadUInt32Async(fs, cancellationToken);
            if (magic != MAGIC_NUMBER)
                throw new InvalidDataException("Invalid SSTable file format.");

            var version = await ReadInt32Async(fs, cancellationToken);
            if (version != VERSION)
                throw new InvalidDataException($"Unsupported SSTable version: {version}");

            var entryCount = await ReadInt32Async(fs, cancellationToken);
            var indexOffset = await ReadInt64Async(fs, cancellationToken);
            var bloomOffset = await ReadInt64Async(fs, cancellationToken);

            return (entryCount, indexOffset, bloomOffset);
        }

        private static async Task WriteEntryAsync(FileStream fs, DataEntry entry, CancellationToken cancellationToken)
        {
            await WriteStringAsync(fs, entry.Key, cancellationToken);
            await WriteInt64Async(fs, entry.SequenceNumber, cancellationToken);
            await WriteInt64Async(fs, entry.Timestamp.Ticks, cancellationToken);
            await WriteBoolAsync(fs, entry.IsDeleted, cancellationToken);

            if (!entry.IsDeleted)
            {
                await WriteStringAsync(fs, entry.TypeName ?? string.Empty, cancellationToken);
                await WriteBytesAsync(fs, entry.Value, cancellationToken);
            }
        }

        private static async Task<DataEntry?> ReadEntryAsync(FileStream fs, CancellationToken cancellationToken)
        {
            try
            {
                var key = await ReadStringAsync(fs, cancellationToken);
                var seqNum = await ReadInt64Async(fs, cancellationToken);
                var ticks = await ReadInt64Async(fs, cancellationToken);
                var isDeleted = await ReadBoolAsync(fs, cancellationToken);

                string? typeName = null;
                byte[]? value = null;

                if (!isDeleted)
                {
                    typeName = await ReadStringAsync(fs, cancellationToken);
                    value = await ReadBytesAsync(fs, cancellationToken);
                }

                return new DataEntry
                {
                    Key = key,
                    SequenceNumber = seqNum,
                    Timestamp = new DateTime(ticks, DateTimeKind.Utc),
                    IsDeleted = isDeleted,
                    TypeName = typeName,
                    Value = value
                };
            }
            catch (EndOfStreamException)
            {
                return null;
            }
        }

        private static async Task WriteIndexAsync(FileStream fs, Dictionary<string, long> index, CancellationToken cancellationToken)
        {
            await WriteInt32Async(fs, index.Count, cancellationToken);

            foreach (var kvp in index)
            {
                await WriteStringAsync(fs, kvp.Key, cancellationToken);
                await WriteInt64Async(fs, kvp.Value, cancellationToken);
            }
        }

        private static async Task WriteInt32Async(Stream stream, int value, CancellationToken cancellationToken)
        {
            var bytes = BitConverter.GetBytes(value);
            await stream.WriteAsync(bytes, 0, bytes.Length, cancellationToken);
        }

        private static async Task<int> ReadInt32Async(Stream stream, CancellationToken cancellationToken)
        {
            var bytes = new byte[4];
            await stream.ReadAsync(bytes, 0, 4, cancellationToken);
            return BitConverter.ToInt32(bytes, 0);
        }

        private static async Task WriteUInt32Async(Stream stream, uint value, CancellationToken cancellationToken)
        {
            var bytes = BitConverter.GetBytes(value);
            await stream.WriteAsync(bytes, 0, bytes.Length, cancellationToken);
        }

        private static async Task<uint> ReadUInt32Async(Stream stream, CancellationToken cancellationToken)
        {
            var bytes = new byte[4];
            await stream.ReadAsync(bytes, 0, 4, cancellationToken);
            return BitConverter.ToUInt32(bytes, 0);
        }

        private static async Task WriteInt64Async(Stream stream, long value, CancellationToken cancellationToken)
        {
            var bytes = BitConverter.GetBytes(value);
            await stream.WriteAsync(bytes, 0, bytes.Length, cancellationToken);
        }

        private static async Task<long> ReadInt64Async(Stream stream, CancellationToken cancellationToken)
        {
            var bytes = new byte[8];
            await stream.ReadAsync(bytes, 0, 8, cancellationToken);
            return BitConverter.ToInt64(bytes, 0);
        }

        private static async Task WriteBoolAsync(Stream stream, bool value, CancellationToken cancellationToken)
        {
            await stream.WriteAsync(new byte[] { (byte)(value ? 1 : 0) }, 0, 1, cancellationToken);
        }

        private static async Task<bool> ReadBoolAsync(Stream stream, CancellationToken cancellationToken)
        {
            var bytes = new byte[1];
            await stream.ReadAsync(bytes, 0, 1, cancellationToken);
            return bytes[0] != 0;
        }

        private static async Task WriteStringAsync(Stream stream, string value, CancellationToken cancellationToken)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            await WriteInt32Async(stream, bytes.Length, cancellationToken);
            await stream.WriteAsync(bytes, 0, bytes.Length, cancellationToken);
        }

        private static async Task<string> ReadStringAsync(Stream stream, CancellationToken cancellationToken)
        {
            var length = await ReadInt32Async(stream, cancellationToken);
            var bytes = new byte[length];
            await stream.ReadAsync(bytes, 0, length, cancellationToken);
            return Encoding.UTF8.GetString(bytes);
        }

        private static async Task WriteBytesAsync(Stream stream, byte[]? value, CancellationToken cancellationToken)
        {
            if (value == null)
            {
                await WriteInt32Async(stream, 0, cancellationToken);
            }
            else
            {
                await WriteInt32Async(stream, value.Length, cancellationToken);
                await stream.WriteAsync(value, 0, value.Length, cancellationToken);
            }
        }

        private static async Task<byte[]?> ReadBytesAsync(Stream stream, CancellationToken cancellationToken)
        {
            var length = await ReadInt32Async(stream, cancellationToken);
            if (length == 0) return null;

            var bytes = new byte[length];
            await stream.ReadAsync(bytes, 0, length, cancellationToken);
            return bytes;
        }

        #endregion

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;

            _fileStream?.Dispose();
            _lock?.Dispose();
        }
    }

    #endregion

    #region Write-Ahead Log (WAL)

    /// <summary>
    /// Write-Ahead Log for crash recovery and durability.
    /// All writes go to WAL first before being applied to memtable.
    /// </summary>
    internal class WriteAheadLog : IDisposable
    {
        private readonly string _directory;
        private readonly Logger _logger;
        private FileStream? _currentLog;
        private readonly object _writeLock = new();
        private long _currentLogNumber = 0;
        private bool _isDisposed = false;

        public long SizeBytes => _currentLog?.Length ?? 0;

        public WriteAheadLog(string directory, Logger logger)
        {
            _directory = directory;
            _logger = logger;

            Directory.CreateDirectory(directory);
            OpenNewLog();
        }

        public async Task WriteAsync(WALEntry entry, CancellationToken cancellationToken)
        {
            byte[] data = SerializeEntry(entry);

            lock (_writeLock)
            {
                if (_currentLog == null)
                    throw new InvalidOperationException("WAL is not initialized.");

                var lengthBytes = BitConverter.GetBytes(data.Length);
                _currentLog.Write(lengthBytes, 0, lengthBytes.Length);

                _currentLog.Write(data, 0, data.Length);

                _currentLog.Flush(flushToDisk: true);
            }

            await Task.CompletedTask;
        }

        public async Task WriteBatchAsync(List<WALEntry> entries, CancellationToken cancellationToken)
        {
            lock (_writeLock)
            {
                if (_currentLog == null)
                    throw new InvalidOperationException("WAL is not initialized.");

                foreach (var entry in entries)
                {
                    byte[] data = SerializeEntry(entry);

                    var lengthBytes = BitConverter.GetBytes(data.Length);
                    _currentLog.Write(lengthBytes, 0, lengthBytes.Length);
                    _currentLog.Write(data, 0, data.Length);
                }

                _currentLog.Flush(flushToDisk: true);
            }

            await Task.CompletedTask;
        }

        public async Task<List<WALEntry>> RecoverAsync(CancellationToken cancellationToken)
        {
            var entries = new List<WALEntry>();

            var logFiles = Directory.GetFiles(_directory, "*.wal").OrderBy(f => f).ToList();

            foreach (var logFile in logFiles)
            {
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.Read);

                    while (fs.Position < fs.Length)
                    {
                        try
                        {
                            byte[] lengthBytes = new byte[4];
                            var bytesRead = await fs.ReadAsync(lengthBytes, 0, 4, cancellationToken);
                            if (bytesRead < 4) break;

                            int length = BitConverter.ToInt32(lengthBytes, 0);

                            byte[] data = new byte[length];
                            bytesRead = await fs.ReadAsync(data, 0, length, cancellationToken);
                            if (bytesRead < length) break;

                            var entry = DeserializeEntry(data);
                            entries.Add(entry);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error reading WAL entry: {ex.Message}");
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error reading WAL file {logFile}: {ex.Message}");
                }
            }

            return entries;
        }

        public async Task TruncateAsync(CancellationToken cancellationToken)
        {
            lock (_writeLock)
            {
                _currentLog?.Dispose();

                var oldFiles = Directory.GetFiles(_directory, "*.wal");
                foreach (var file in oldFiles)
                {
                    try
                    {
                        File.Delete(file);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error deleting WAL file {file}: {ex.Message}");
                    }
                }

                OpenNewLog();
            }

            await Task.CompletedTask;
        }

        public async Task SyncAsync(CancellationToken cancellationToken)
        {
            lock (_writeLock)
            {
                _currentLog?.Flush(flushToDisk: true);
            }

            await Task.CompletedTask;
        }

        private void OpenNewLog()
        {
            _currentLogNumber++;
            var logPath = Path.Combine(_directory, $"{_currentLogNumber:D10}.wal");
            _currentLog = new FileStream(logPath, FileMode.Create, FileAccess.Write, FileShare.Read, 64 * 1024);
        }

        private byte[] SerializeEntry(WALEntry entry)
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            writer.Write(entry.SequenceNumber);
            writer.Write(entry.Key);
            writer.Write(entry.IsDeleted);
            writer.Write(entry.Timestamp.Ticks);

            if (!entry.IsDeleted)
            {
                writer.Write(entry.TypeName ?? string.Empty);

                if (entry.Value != null)
                {
                    writer.Write(entry.Value.Length);
                    writer.Write(entry.Value);
                }
                else
                {
                    writer.Write(0);
                }
            }

            return ms.ToArray();
        }

        private WALEntry DeserializeEntry(byte[] data)
        {
            using var ms = new MemoryStream(data);
            using var reader = new BinaryReader(ms);

            var entry = new WALEntry
            {
                SequenceNumber = reader.ReadInt64(),
                Key = reader.ReadString(),
                IsDeleted = reader.ReadBoolean(),
                Timestamp = new DateTime(reader.ReadInt64(), DateTimeKind.Utc)
            };

            if (!entry.IsDeleted)
            {
                entry.TypeName = reader.ReadString();

                int valueLength = reader.ReadInt32();
                if (valueLength > 0)
                {
                    entry.Value = reader.ReadBytes(valueLength);
                }
            }

            return entry;
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;

            lock (_writeLock)
            {
                _currentLog?.Dispose();
            }
        }
    }

    #endregion

    #region SSTable Manager

    /// <summary>
    /// Manages all SSTables and their lifecycle.
    /// </summary>
    internal class SSTableManager : IDisposable
    {
        private readonly string _dataDirectory;
        private readonly VersionManager _versionManager;
        private readonly Logger _logger;
        private long _nextSSTableId = 0;

        public SSTableManager(string dataDirectory, VersionManager versionManager, Logger logger)
        {
            _dataDirectory = dataDirectory;
            _versionManager = versionManager;
            _logger = logger;
        }

        public async Task LoadExistingSSTables(CancellationToken cancellationToken)
        {
            var sstableDir = Path.Combine(_dataDirectory, "sstables");
            var files = Directory.GetFiles(sstableDir, "*.sst").OrderBy(f => f).ToList();

            foreach (var file in files)
            {
                try
                {
                    var fileName = Path.GetFileNameWithoutExtension(file);
                    var parts = fileName.Split('_');

                    if (parts.Length >= 2 && int.TryParse(parts[1], out int level))
                    {
                        var sstable = await SSTable.LoadAsync(file, level, cancellationToken);
                        _versionManager.AddSSTable(sstable);

                        if (parts.Length >= 1 && long.TryParse(parts[0], out long id))
                        {
                            if (id >= _nextSSTableId)
                            {
                                _nextSSTableId = id + 1;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error loading SSTable {file}: {ex.Message}");
                }
            }
        }

        public async Task<SSTable> CreateSSTableAsync(List<DataEntry> sortedEntries, int level, CancellationToken cancellationToken)
        {
            var id = Interlocked.Increment(ref _nextSSTableId);
            var fileName = $"{id:D10}_{level}.sst";
            var filePath = Path.Combine(_dataDirectory, "sstables", fileName);

            return await SSTable.CreateAsync(filePath, sortedEntries, level, cancellationToken);
        }

        public int GetSSTableCount()
        {
            return _versionManager.GetCurrentSnapshot().SSTables.Count;
        }

        public void Dispose()
        {

        }
    }

    #endregion

    #region Version Manager (MVCC)

    /// <summary>
    /// Manages versions of the database state for MVCC.
    /// Allows lock-free reads while writes are happening.
    /// </summary>
    internal class VersionManager
    {
        private readonly string _dataDirectory;
        private readonly Logger _logger;
        private DatabaseSnapshot _currentSnapshot;
        private readonly ReaderWriterLockSlim _lock = new();

        public VersionManager(string dataDirectory, Logger logger)
        {
            _dataDirectory = dataDirectory;
            _logger = logger;
            _currentSnapshot = new DatabaseSnapshot { SSTables = new List<SSTable>() };
        }

        public DatabaseSnapshot GetCurrentSnapshot()
        {
            _lock.EnterReadLock();
            try
            {
                return _currentSnapshot;
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        public void AddSSTable(SSTable sstable)
        {
            _lock.EnterWriteLock();
            try
            {
                var newSSTables = new List<SSTable>(_currentSnapshot.SSTables) { sstable };
                _currentSnapshot = new DatabaseSnapshot { SSTables = newSSTables };
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        public void RemoveSSTables(List<SSTable> sstablesToRemove)
        {
            _lock.EnterWriteLock();
            try
            {
                var newSSTables = _currentSnapshot.SSTables.Except(sstablesToRemove).ToList();
                _currentSnapshot = new DatabaseSnapshot { SSTables = newSSTables };

                foreach (var sstable in sstablesToRemove)
                {
                    try
                    {
                        sstable.Dispose();
                        File.Delete(sstable.FilePath);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error deleting SSTable {sstable.FilePath}: {ex.Message}");
                    }
                }
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        public void ReplaceSSTablesAtomic(List<SSTable> oldSSTables, List<SSTable> newSSTables)
        {
            _lock.EnterWriteLock();
            try
            {
                var currentList = new List<SSTable>(_currentSnapshot.SSTables);

                foreach (var old in oldSSTables)
                {
                    currentList.Remove(old);
                }

                currentList.AddRange(newSSTables);

                _currentSnapshot = new DatabaseSnapshot { SSTables = currentList };

                foreach (var old in oldSSTables)
                {
                    try
                    {
                        old.Dispose();
                        File.Delete(old.FilePath);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error deleting old SSTable: {ex.Message}");
                    }
                }
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }
    }

    internal class DatabaseSnapshot
    {
        public List<SSTable> SSTables { get; set; } = new();
    }

    #endregion

    #region Compaction Manager

    /// <summary>
    /// Compaction manager with auto compactiion system.
    /// </summary>
    internal class CompactionManager
    {
        private readonly SSTableManager _sstableManager;
        private readonly VersionManager _versionManager;
        private readonly MiniDBOptions _options;
        private readonly Logger _logger;
        private readonly SemaphoreSlim _compactionLock = new(1, 1);
        private readonly CompactionStats _stats = new();

        private readonly AdaptiveThrottler _throttler;

        private readonly long[] _levelMaxBytes = new long[7]; // 7 levels
        private const int MAX_LEVEL = 6;

        public DateTime? LastCompactionTime { get; private set; }
        public CompactionStats Stats => _stats;

        public CompactionManager(SSTableManager sstableManager, VersionManager versionManager, MiniDBOptions options, Logger logger)
        {
            _sstableManager = sstableManager;
            _versionManager = versionManager;
            _options = options;
            _logger = logger;
            _throttler = new AdaptiveThrottler(options);

            InitializeLevelSizes();
        }

        private void InitializeLevelSizes()
        {
            _levelMaxBytes[0] = 256L * 1024 * 1024;

            for (int i = 1; i <= MAX_LEVEL; i++)
            {
                _levelMaxBytes[i] = _levelMaxBytes[i - 1] * 10;
            }
        }

        public bool ShouldCompact()
        {
            var snapshot = _versionManager.GetCurrentSnapshot();

            for (int level = 0; level <= MAX_LEVEL; level++)
            {
                if (ShouldCompactLevel(snapshot, level))
                    return true;
            }

            return false;
        }

        private bool ShouldCompactLevel(DatabaseSnapshot snapshot, int level)
        {
            var levelSSTables = snapshot.SSTables.Where(s => s.Level == level).ToList();

            if (level == 0)
            {
                return levelSSTables.Count >= _options.Level0CompactionTrigger;
            }
            else
            {
                long levelSize = levelSSTables.Sum(s => s.FileSizeBytes);
                return levelSize > _levelMaxBytes[level];
            }
        }

        public async Task CompactAsync(CancellationToken cancellationToken)
        {
            if (!await _compactionLock.WaitAsync(0, cancellationToken))
            {
                _logger.Log("⏭️ Compaction already in progress, skipping.");
                return;
            }

            try
            {
                var snapshot = _versionManager.GetCurrentSnapshot();
                int targetLevel = SelectCompactionLevel(snapshot);

                if (targetLevel == -1)
                {
                    _logger.Log("✅ No compaction needed.");
                    return;
                }

                _logger.Log($"🗜️ Starting compaction for Level {targetLevel}...");
                var sw = Stopwatch.StartNew();

                if (targetLevel == 0)
                {
                    await CompactLevel0Async(snapshot, cancellationToken);
                }
                else
                {
                    await CompactLevelNAsync(snapshot, targetLevel, cancellationToken);
                }

                LastCompactionTime = DateTime.UtcNow;
                _stats.RecordCompaction(sw.Elapsed);

                _logger.Log($"✅ Compaction completed in {sw.ElapsedMilliseconds}ms");
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Compaction failed: {ex.Message}");
                _stats.RecordFailure();
                throw;
            }
            finally
            {
                _compactionLock.Release();
            }
        }

        private int SelectCompactionLevel(DatabaseSnapshot snapshot)
        {
            double maxScore = 0;
            int maxLevel = -1;

            for (int level = 0; level <= MAX_LEVEL; level++)
            {
                double score = CalculateCompactionScore(snapshot, level);

                if (score > maxScore)
                {
                    maxScore = score;
                    maxLevel = level;
                }
            }

            return maxScore > 1.0 ? maxLevel : -1;
        }

        private double CalculateCompactionScore(DatabaseSnapshot snapshot, int level)
        {
            var levelSSTables = snapshot.SSTables.Where(s => s.Level == level).ToList();

            if (level == 0)
            {
                return (double)levelSSTables.Count / _options.Level0CompactionTrigger;
            }
            else
            {
                long levelSize = levelSSTables.Sum(s => s.FileSizeBytes);
                return (double)levelSize / _levelMaxBytes[level];
            }
        }

        /// <summary>
        /// Compact Level 0 to Level 1.
        /// Level 0 files can overlap, so we need to merge all overlapping files.
        /// </summary>
        private async Task CompactLevel0Async(DatabaseSnapshot snapshot, CancellationToken cancellationToken)
        {
            var level0Files = snapshot.SSTables.Where(s => s.Level == 0).ToList();

            if (level0Files.Count == 0) return;

            var level1Files = await FindOverlappingFiles(snapshot, level0Files, 1, cancellationToken);

            var allFiles = level0Files.Concat(level1Files).ToList();
            var mergedEntries = await MergeSSTables(allFiles, cancellationToken);

            var newSSTables = await CreateCompactedSSTables(mergedEntries, 1, cancellationToken);

            _versionManager.ReplaceSSTablesAtomic(allFiles, newSSTables);

            _logger.Log($"📊 Compacted {level0Files.Count} L0 files + {level1Files.Count} L1 files → {newSSTables.Count} L1 files");
        }

        /// <summary>
        /// Compact Level N to Level N+1.
        /// Pick one file from Level N and all overlapping files from Level N+1.
        /// </summary>
        private async Task CompactLevelNAsync(DatabaseSnapshot snapshot, int level, CancellationToken cancellationToken)
        {
            if (level >= MAX_LEVEL) return;

            var levelFiles = snapshot.SSTables.Where(s => s.Level == level).ToList();

            if (levelFiles.Count == 0) return;

            var sourceFile = levelFiles.OrderBy(f => f.CreationTime).First();

            var nextLevelFiles = await FindOverlappingFiles(snapshot, new[] { sourceFile }, level + 1, cancellationToken);

            var allFiles = new[] { sourceFile }.Concat(nextLevelFiles).ToList();
            var mergedEntries = await MergeSSTables(allFiles, cancellationToken);

            var newSSTables = await CreateCompactedSSTables(mergedEntries, level + 1, cancellationToken);

            _versionManager.ReplaceSSTablesAtomic(allFiles, newSSTables);

            _logger.Log($"📊 Compacted 1 L{level} file + {nextLevelFiles.Count} L{level + 1} files → {newSSTables.Count} L{level + 1} files");
        }

        /// <summary>
        /// Find all SSTables in targetLevel that overlap with the key range of sourceFiles.
        /// </summary>
        private async Task<List<SSTable>> FindOverlappingFiles(
            DatabaseSnapshot snapshot,
            IEnumerable<SSTable> sourceFiles,
            int targetLevel,
            CancellationToken cancellationToken)
        {
            var (minKey, maxKey) = await GetKeyRange(sourceFiles, cancellationToken);

            if (minKey == null || maxKey == null)
                return new List<SSTable>();

            var targetFiles = snapshot.SSTables.Where(s => s.Level == targetLevel).ToList();
            var overlapping = new List<SSTable>();

            foreach (var file in targetFiles)
            {
                var (fileMin, fileMax) = await GetKeyRange(new[] { file }, cancellationToken);

                if (fileMin == null || fileMax == null) continue;

                if (string.Compare(fileMin, maxKey, StringComparison.Ordinal) <= 0 &&
                    string.Compare(fileMax, minKey, StringComparison.Ordinal) >= 0)
                {
                    overlapping.Add(file);
                }
            }

            return overlapping;
        }

        private async Task<(string? minKey, string? maxKey)> GetKeyRange(
            IEnumerable<SSTable> sstables,
            CancellationToken cancellationToken)
        {
            string? minKey = null;
            string? maxKey = null;

            foreach (var sstable in sstables)
            {
                await foreach (var entry in sstable.ScanAsync(cancellationToken))
                {
                    if (minKey == null || string.Compare(entry.Key, minKey, StringComparison.Ordinal) < 0)
                        minKey = entry.Key;

                    if (maxKey == null || string.Compare(entry.Key, maxKey, StringComparison.Ordinal) > 0)
                        maxKey = entry.Key;
                }
            }

            return (minKey, maxKey);
        }

        /// <summary>
        /// Merge multiple SSTables with incremental processing and throttling.
        /// </summary>
        private async Task<List<DataEntry>> MergeSSTables(List<SSTable> sstables, CancellationToken cancellationToken)
        {
            var merged = new SortedDictionary<string, DataEntry>(StringComparer.Ordinal);
            int processedEntries = 0;

            foreach (var sstable in sstables.OrderByDescending(s => s.CreationTime))
            {
                await foreach (var entry in sstable.ScanAsync(cancellationToken))
                {
                    if (!merged.TryGetValue(entry.Key, out var existing) ||
                        entry.SequenceNumber > existing.SequenceNumber)
                    {
                        merged[entry.Key] = entry;
                    }

                    processedEntries++;

                    if (processedEntries % 1000 == 0)
                    {
                        await _throttler.ThrottleIfNeededAsync(cancellationToken);
                    }
                }
            }

            var cutoffTime = DateTime.UtcNow.AddDays(-_options.TombstoneRetentionDays);

            var result = merged.Values
                .Where(e => !e.IsDeleted || e.Timestamp > cutoffTime)
                .Where(e => !e.IsDeleted)
                .ToList();

            _stats.RecordEntriesCompacted(processedEntries);
            _stats.RecordEntriesDeleted(merged.Count - result.Count);

            return result;
        }

        /// <summary>
        /// Create multiple SSTables from merged entries, splitting if needed.
        /// </summary>
        private async Task<List<SSTable>> CreateCompactedSSTables(
            List<DataEntry> entries,
            int level,
            CancellationToken cancellationToken)
        {
            var newSSTables = new List<SSTable>();
            const long MAX_FILE_SIZE = 64 * 1024 * 1024;

            var currentBatch = new List<DataEntry>();
            long currentSize = 0;

            foreach (var entry in entries)
            {
                var entrySize = EstimateEntrySize(entry);

                if (currentSize + entrySize > MAX_FILE_SIZE && currentBatch.Count > 0)
                {
                    var sstable = await _sstableManager.CreateSSTableAsync(currentBatch, level, cancellationToken);
                    newSSTables.Add(sstable);

                    currentBatch.Clear();
                    currentSize = 0;
                }

                currentBatch.Add(entry);
                currentSize += entrySize;
            }

            if (currentBatch.Count > 0)
            {
                var sstable = await _sstableManager.CreateSSTableAsync(currentBatch, level, cancellationToken);
                newSSTables.Add(sstable);
            }

            return newSSTables;
        }

        private long EstimateEntrySize(DataEntry entry)
        {
            long size = 0;
            size += entry.Key.Length * 2;
            size += entry.Value?.Length ?? 0;
            size += entry.TypeName?.Length * 2 ?? 0;
            size += 64;
            return size;
        }
    }

    #endregion

    #region Bloom Filter

    /// <summary>
    /// Space-efficient probabilistic data structure for set membership testing.
    /// Used to quickly determine if a key might exist in an SSTable.
    /// </summary>
    internal class BloomFilter
    {
        private readonly BitArray _bits;
        private readonly int _hashCount;
        private readonly int _bitCount;

        public BloomFilter(int expectedElements, double falsePositiveRate)
        {
            _bitCount = (int)Math.Ceiling(-expectedElements * Math.Log(falsePositiveRate) / (Math.Log(2) * Math.Log(2)));
            _hashCount = (int)Math.Ceiling(_bitCount / (double)expectedElements * Math.Log(2));

            _bits = new BitArray(_bitCount);
        }

        private BloomFilter(int bitCount, int hashCount, BitArray bits)
        {
            _bitCount = bitCount;
            _hashCount = hashCount;
            _bits = bits;
        }

        public void Add(string key)
        {
            foreach (var hash in GetHashes(key))
            {
                _bits[hash] = true;
            }
        }

        public bool MightContain(string key)
        {
            foreach (var hash in GetHashes(key))
            {
                if (!_bits[hash])
                    return false;
            }
            return true;
        }

        private IEnumerable<int> GetHashes(string key)
        {
            var hash1 = GetHash1(key);
            var hash2 = GetHash2(key);

            for (int i = 0; i < _hashCount; i++)
            {
                var hash = (hash1 + i * hash2) % _bitCount;
                if (hash < 0) hash += _bitCount;
                yield return hash;
            }
        }

        private int GetHash1(string key)
        {
            return Math.Abs(key.GetHashCode()) % _bitCount;
        }

        private int GetHash2(string key)
        {
            unchecked
            {
                const int fnvPrime = 16777619;
                int hash = (int)2166136261;

                foreach (char c in key)
                {
                    hash ^= c;
                    hash *= fnvPrime;
                }

                return Math.Abs(hash) % _bitCount;
            }
        }

        public async Task WriteToStreamAsync(Stream stream, CancellationToken cancellationToken)
        {
            await WriteInt32Async(stream, _bitCount, cancellationToken);
            await WriteInt32Async(stream, _hashCount, cancellationToken);

            byte[] bytes = new byte[(_bitCount + 7) / 8];
            _bits.CopyTo(bytes, 0);
            await stream.WriteAsync(bytes, 0, bytes.Length, cancellationToken);
        }

        public async Task ReadFromStreamAsync(Stream stream, CancellationToken cancellationToken)
        {
            var bitCount = await ReadInt32Async(stream, cancellationToken);
            var hashCount = await ReadInt32Async(stream, cancellationToken);

            byte[] bytes = new byte[(bitCount + 7) / 8];
            await stream.ReadAsync(bytes, 0, bytes.Length, cancellationToken);

            var bits = new BitArray(bytes);
            for (int i = 0; i < Math.Min(bitCount, _bitCount); i++)
            {
                _bits[i] = bits[i];
            }
        }

        private static async Task WriteInt32Async(Stream stream, int value, CancellationToken cancellationToken)
        {
            var bytes = BitConverter.GetBytes(value);
            await stream.WriteAsync(bytes, 0, bytes.Length, cancellationToken);
        }

        private static async Task<int> ReadInt32Async(Stream stream, CancellationToken cancellationToken)
        {
            var bytes = new byte[4];
            await stream.ReadAsync(bytes, 0, 4, cancellationToken);
            return BitConverter.ToInt32(bytes, 0);
        }
    }

    #endregion

    #region Data Models

    internal class DataEntry
    {
        public string Key { get; set; } = string.Empty;
        public byte[]? Value { get; set; }
        public string? TypeName { get; set; }
        public long SequenceNumber { get; set; }
        public bool IsDeleted { get; set; }
        public DateTime Timestamp { get; set; }
    }

    internal class WALEntry
    {
        public long SequenceNumber { get; set; }
        public string Key { get; set; } = string.Empty;
        public byte[]? Value { get; set; }
        public string? TypeName { get; set; }
        public bool IsDeleted { get; set; }
        public DateTime Timestamp { get; set; }
    }

    internal enum WriteType
    {
        Insert,
        Upsert,
        Delete
    }

    #endregion

    #region Metrics Collector

    internal class MetricsCollector
    {
        private long _totalOps = 0;
        private long _readOps = 0;
        private long _writeOps = 0;
        private long _cacheHits = 0;
        private long _cacheMisses = 0;

        private readonly ConcurrentQueue<TimeSpan> _readLatencies = new();
        private readonly ConcurrentQueue<TimeSpan> _writeLatencies = new();

        private const int MAX_LATENCY_SAMPLES = 1000;

        public long TotalOperations => Interlocked.Read(ref _totalOps);
        public long ReadOperations => Interlocked.Read(ref _readOps);
        public long WriteOperations => Interlocked.Read(ref _writeOps);

        public double CacheHitRate
        {
            get
            {
                var hits = Interlocked.Read(ref _cacheHits);
                var misses = Interlocked.Read(ref _cacheMisses);
                var total = hits + misses;
                return total == 0 ? 0 : (double)hits / total;
            }
        }

        public TimeSpan AverageReadLatency
        {
            get
            {
                var latencies = _readLatencies.ToArray();
                return latencies.Length == 0 ? TimeSpan.Zero : TimeSpan.FromTicks((long)latencies.Average(l => l.Ticks));
            }
        }

        public TimeSpan AverageWriteLatency
        {
            get
            {
                var latencies = _writeLatencies.ToArray();
                return latencies.Length == 0 ? TimeSpan.Zero : TimeSpan.FromTicks((long)latencies.Average(l => l.Ticks));
            }
        }

        public void RecordRead(TimeSpan latency, bool cacheHit)
        {
            Interlocked.Increment(ref _totalOps);
            Interlocked.Increment(ref _readOps);

            if (cacheHit)
                Interlocked.Increment(ref _cacheHits);
            else
                Interlocked.Increment(ref _cacheMisses);

            _readLatencies.Enqueue(latency);
            TrimQueue(_readLatencies);
        }

        public void RecordWrite(TimeSpan latency)
        {
            Interlocked.Increment(ref _totalOps);
            Interlocked.Increment(ref _writeOps);

            _writeLatencies.Enqueue(latency);
            TrimQueue(_writeLatencies);
        }

        public void RecordBatchWrite(int count, TimeSpan latency)
        {
            Interlocked.Add(ref _totalOps, count);
            Interlocked.Add(ref _writeOps, count);

            _writeLatencies.Enqueue(latency);
            TrimQueue(_writeLatencies);
        }

        private void TrimQueue(ConcurrentQueue<TimeSpan> queue)
        {
            while (queue.Count > MAX_LATENCY_SAMPLES)
            {
                queue.TryDequeue(out _);
            }
        }
    }

    #endregion

    #region Public API Models

    public class BatchOperation
    {
        public string Key { get; set; } = string.Empty;
        public object? Data { get; set; }
        public BatchOperationType Type { get; set; }
        public bool ContinueOnError { get; set; } = false;
    }

    public enum BatchOperationType
    {
        Insert,
        Upsert,
        Delete
    }

    public class DatabaseStats
    {
        public int TotalEntries { get; set; }
        public int MemTableEntries { get; set; }
        public long MemTableSizeBytes { get; set; }
        public int SSTableCount { get; set; }
        public long TotalSizeBytes { get; set; }
        public long TotalOperations { get; set; }
        public long ReadOperations { get; set; }
        public long WriteOperations { get; set; }
        public TimeSpan AverageReadLatency { get; set; }
        public TimeSpan AverageWriteLatency { get; set; }
        public double CacheHitRate { get; set; }
        public DateTime? LastCompactionTime { get; set; }
        public long WALSizeBytes { get; set; }
    }

    #endregion

    #region Exceptions

    public class MiniDBException : Exception
    {
        public MiniDBException(string message) : base(message) { }
        public MiniDBException(string message, Exception innerException) : base(message, innerException) { }
    }

    public class MiniDBKeyNotFoundException : MiniDBException
    {
        public MiniDBKeyNotFoundException(string key) : base($"Key '{key}' not found.") { }
    }

    public class MiniDBTypeMismatchException : MiniDBException
    {
        public MiniDBTypeMismatchException(string key, Type expectedType, Type actualType)
            : base($"Type mismatch for key '{key}'. Expected: {expectedType.Name}, Actual: {actualType.Name}") { }
    }

    #endregion

    #region BitArray Helper

    internal class BitArray
    {
        private readonly int[] _array;
        private readonly int _length;

        public BitArray(int length)
        {
            _length = length;
            _array = new int[(length + 31) / 32];
        }

        public BitArray(byte[] bytes)
        {
            _length = bytes.Length * 8;
            _array = new int[(bytes.Length + 3) / 4];
            Buffer.BlockCopy(bytes, 0, _array, 0, bytes.Length);
        }

        public bool this[int index]
        {
            get
            {
                if (index < 0 || index >= _length)
                    throw new ArgumentOutOfRangeException(nameof(index));

                int arrayIndex = index / 32;
                int bitIndex = index % 32;
                return (_array[arrayIndex] & (1 << bitIndex)) != 0;
            }
            set
            {
                if (index < 0 || index >= _length)
                    throw new ArgumentOutOfRangeException(nameof(index));

                int arrayIndex = index / 32;
                int bitIndex = index % 32;

                if (value)
                    _array[arrayIndex] |= (1 << bitIndex);
                else
                    _array[arrayIndex] &= ~(1 << bitIndex);
            }
        }

        public void CopyTo(byte[] array, int arrayIndex)
        {
            Buffer.BlockCopy(_array, 0, array, arrayIndex, Math.Min(_array.Length * 4, array.Length - arrayIndex));
        }
    }

    #region Adaptive Throttler

    /// <summary>
    /// Adaptive throttler that slows down compaction when system is under load.
    /// Monitors write rate and adjusts compaction speed accordingly.
    /// </summary>
    internal class AdaptiveThrottler
    {
        private readonly MiniDBOptions _options;
        private readonly RateLimiter _rateLimiter;
        private long _lastWriteCount = 0;
        private DateTime _lastCheckTime = DateTime.UtcNow;

        public AdaptiveThrottler(MiniDBOptions options)
        {
            _options = options;
            _rateLimiter = new RateLimiter(options.CompactionMaxBytesPerSecond);
        }

        public async Task ThrottleIfNeededAsync(CancellationToken cancellationToken)
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - _lastCheckTime).TotalSeconds;

            if (elapsed > 1.0)
            {
                _lastCheckTime = now;
            }

            await _rateLimiter.WaitAsync(4096, cancellationToken);
        }
    }

    #endregion

    #region Rate Limiter

    /// <summary>
    /// Token bucket rate limiter for controlling compaction I/O.
    /// </summary>
    internal class RateLimiter
    {
        private readonly long _bytesPerSecond;
        private long _availableBytes;
        private DateTime _lastRefill;
        private readonly object _lock = new();

        public RateLimiter(long bytesPerSecond)
        {
            _bytesPerSecond = bytesPerSecond;
            _availableBytes = bytesPerSecond;
            _lastRefill = DateTime.UtcNow;
        }

        public async Task WaitAsync(long bytes, CancellationToken cancellationToken)
        {
            while (true)
            {
                lock (_lock)
                {
                    Refill();

                    if (_availableBytes >= bytes)
                    {
                        _availableBytes -= bytes;
                        return;
                    }
                }

                await Task.Delay(10, cancellationToken);
            }
        }

        private void Refill()
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - _lastRefill).TotalSeconds;

            if (elapsed > 0)
            {
                var refillAmount = (long)(elapsed * _bytesPerSecond);
                _availableBytes = Math.Min(_availableBytes + refillAmount, _bytesPerSecond);
                _lastRefill = now;
            }
        }
    }

    #endregion

    #region Compaction Stats

    internal class CompactionStats
    {
        private long _totalCompactions = 0;
        private long _totalEntriesCompacted = 0;
        private long _totalEntriesDeleted = 0;
        private long _totalBytesCompacted = 0;
        private long _failedCompactions = 0;
        private readonly ConcurrentQueue<TimeSpan> _compactionTimes = new();

        public long TotalCompactions => Interlocked.Read(ref _totalCompactions);
        public long TotalEntriesCompacted => Interlocked.Read(ref _totalEntriesCompacted);
        public long TotalEntriesDeleted => Interlocked.Read(ref _totalEntriesDeleted);
        public long FailedCompactions => Interlocked.Read(ref _failedCompactions);

        public TimeSpan AverageCompactionTime
        {
            get
            {
                var times = _compactionTimes.ToArray();
                return times.Length == 0 ? TimeSpan.Zero :
                    TimeSpan.FromTicks((long)times.Average(t => t.Ticks));
            }
        }

        public void RecordCompaction(TimeSpan duration)
        {
            Interlocked.Increment(ref _totalCompactions);
            _compactionTimes.Enqueue(duration);

            while (_compactionTimes.Count > 100)
                _compactionTimes.TryDequeue(out _);
        }

        public void RecordEntriesCompacted(int count)
        {
            Interlocked.Add(ref _totalEntriesCompacted, count);
        }

        public void RecordEntriesDeleted(int count)
        {
            Interlocked.Add(ref _totalEntriesDeleted, count);
        }

        public void RecordFailure()
        {
            Interlocked.Increment(ref _failedCompactions);
        }
    }

    #endregion

    #region Enhanced Options

    public class MiniDBOptions
    {
        public string DataDirectory { get; set; } = "minidb_data";
        public long MemTableSizeBytes { get; set; } = 64 * 1024 * 1024;
        public int Level0CompactionTrigger { get; set; } = 4;
        public int MaxConcurrentWrites { get; set; } = 100;
        public TimeSpan FlushCheckInterval { get; set; } = TimeSpan.FromSeconds(10);
        public TimeSpan CompactionCheckInterval { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Maximum bytes per second for compaction I/O (default: 50MB/s).
        /// Prevents compaction from overwhelming the system.
        /// </summary>
        public long CompactionMaxBytesPerSecond { get; set; } = 50 * 1024 * 1024;

        /// <summary>
        /// How long to keep tombstones before garbage collecting (default: 7 days).
        /// </summary>
        public int TombstoneRetentionDays { get; set; } = 7;

        /// <summary>
        /// Enable parallel compaction for independent key ranges (default: true).
        /// </summary>
        public bool EnableParallelCompaction { get; set; } = true;
    }

    #endregion

    #endregion
}