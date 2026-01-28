using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpPress.Services
{
    public class MiniDBOptions
    {
        public string DataDirectory { get; set; } = "Database";
        public long MemTableSizeBytes { get; set; } = 128 * 1024 * 1024;
        public int BlockSizeBytes { get; set; } = 4096;
        public long BlockCacheSizeBytes { get; set; } = 512 * 1024 * 1024;
        public int MaxConcurrentWrites { get; set; } = 1000;
        public bool EnableCompression { get; set; } = true;
        public int Level0CompactionTrigger { get; set; } = 4;
        public int TargetFileSizeBase { get; set; } = 64 * 1024 * 1024;
        public int FlushIntervalMs { get; set; } = 1000;
    }

    public class MiniDB : IDisposable
    {
        private readonly MiniDBOptions _options;
        private readonly Logger _logger;
        private readonly string _directory;
        private MemTable _memTable;
        private readonly Wal _wal;
        private readonly TableCache _tableCache;
        private readonly VersionSet _versions;
        private readonly SemaphoreSlim _writeLock;
        private readonly ManualResetEventSlim _bgWorkEvent = new();
        private readonly CancellationTokenSource _cts = new();
        private long _logNumber;
        private long _sequence;
        private volatile bool _disposed;
        private Task _bgTask;
        private bool _started = false;

        public MiniDB(MiniDBOptions options, Logger logger)
        {
            _options = options ?? new MiniDBOptions();
            _logger = logger ?? new Logger();
            _directory = Path.GetFullPath(_options.DataDirectory);
            Directory.CreateDirectory(_directory);
            Directory.CreateDirectory(Path.Combine(_directory, "wal"));
            Directory.CreateDirectory(Path.Combine(_directory, "sst"));

            _writeLock = new SemaphoreSlim(_options.MaxConcurrentWrites, _options.MaxConcurrentWrites);
            _tableCache = new TableCache(_options, _directory);
            _versions = new VersionSet(_directory, _options, _tableCache, _logger);
            _memTable = new MemTable(_options.MemTableSizeBytes);
            _wal = new Wal(Path.Combine(_directory, "wal"), ref _logNumber);
        }

        public async Task StartAsync()
        {
            if (_started) return;

            _logger.Log("Starting MiniDB...");

            var recovered = _wal.Recover();
            _sequence = recovered.Item1;

            foreach (var entry in recovered.Item2)
            {
                _memTable.Add(entry.Sequence, entry.Key, entry.Value, entry.Type);
            }

            _versions.Load();
            _started = true;
            _bgTask = Task.Run(BackgroundLoop);

            _logger.Log("MiniDB Started.");
        }

        public async Task StopAsync()
        {
            if (!_started) return;

            _cts.Cancel();
            _bgWorkEvent.Set();

            if (_bgTask != null)
            {
                await _bgTask;
            }

            if (_memTable.ApproximateMemoryUsage() > 0)
            {
                await CompactMemTable();
            }

            _wal.Dispose();
            _tableCache.Dispose();
            _bgWorkEvent.Dispose();
            _writeLock.Dispose();
            _cts.Dispose();

            _disposed = true;
            _started = false;
            _logger.Log("💽 MiniDB Stopped.");
        }

        public async Task PutAsync(string key, byte[] value)
        {
            CheckDisposed();
            ValidateKey(key);
            if (value == null) throw new ArgumentNullException(nameof(value));

            await _writeLock.WaitAsync();
            try
            {
                var seq = Interlocked.Increment(ref _sequence);
                var batch = new WriteBatch { Sequence = seq };
                batch.Put(key, value);
                await WriteBatchInternal(batch);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task DeleteAsync(string key)
        {
            CheckDisposed();
            ValidateKey(key);

            await _writeLock.WaitAsync();
            try
            {
                var seq = Interlocked.Increment(ref _sequence);
                var batch = new WriteBatch { Sequence = seq };
                batch.Delete(key);
                await WriteBatchInternal(batch);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async Task<byte[]> GetAsync(string key)
        {
            CheckDisposed();
            ValidateKey(key);

            var memValue = _memTable.Get(key);
            if (memValue != null)
            {
                if (memValue.Type == EntryType.Delete) return null;
                return memValue.Value;
            }

            var immValue = _versions.GetImmutable(key);
            if (immValue != null)
            {
                if (immValue.Type == EntryType.Delete) return null;
                return immValue.Value;
            }

            return await _versions.GetAsync(key);
        }

        private async Task WriteBatchInternal(WriteBatch batch)
        {
            _wal.AddRecord(batch);
            foreach (var entry in batch.Entries)
            {
                _memTable.Add(batch.Sequence, entry.Key, entry.Value, entry.Type);
            }

            if (_memTable.ApproximateMemoryUsage() >= _options.MemTableSizeBytes)
            {
                _bgWorkEvent.Set();
            }
        }

        private async Task BackgroundLoop()
        {
            while (!_cts.IsCancellationRequested)
            {
                _bgWorkEvent.Wait(100);
                _bgWorkEvent.Reset();

                if (_disposed) break;

                if (_memTable.ApproximateMemoryUsage() >= _options.MemTableSizeBytes)
                {
                    await CompactMemTable();
                }

                if (_versions.NeedsCompaction())
                {
                    await _versions.DoCompaction();
                }
            }
        }

        private async Task CompactMemTable()
        {
            var imm = _memTable;
            _memTable = new MemTable(_options.MemTableSizeBytes);

            var meta = new FileMetaData
            {
                Number = _versions.NewFileNumber(),
                Size = 0,
                Smallest = new InternalKey(""),
                Largest = new InternalKey("")
            };

            var path = Path.Combine(_directory, "sst", $"{meta.Number}.sst");
            var file = new SSTableWriter(path, _options);
            var iter = imm.NewIterator();
            iter.SeekToFirst();

            bool first = true;
            while (iter.Valid())
            {
                var key = iter.Key();
                var val = iter.Value();
                var type = iter.Type();

                if (first)
                {
                    meta.Smallest = new InternalKey(key);
                    meta.Largest = new InternalKey(key);
                    first = false;
                }
                else
                {
                    if (string.CompareOrdinal(key, meta.Smallest.UserKey) < 0) meta.Smallest = new InternalKey(key);
                    if (string.CompareOrdinal(key, meta.Largest.UserKey) > 0) meta.Largest = new InternalKey(key);
                }

                meta.Size += file.Add(key, type, val);
                iter.Next();
            }
            file.Finish();

            _versions.LogAndApply(0, meta);
            _versions.SetImmutable(imm.GetStore());
            _wal.DeleteLog(_logNumber);
        }

        private void ValidateKey(string key)
        {
            if (string.IsNullOrEmpty(key)) throw new ArgumentException("Key cannot be empty");
            if (Encoding.UTF8.GetByteCount(key) > 512) throw new ArgumentException("Key too long");
        }

        private void CheckDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(MiniDB));
        }

        public void Dispose()
        {
            if (_disposed) return;
            StopAsync().GetAwaiter().GetResult();
        }
    }

    internal class MemTable
    {
        private readonly ConcurrentDictionary<string, MemEntry> _store;
        private readonly long _maxSize;
        private long _currentSize;

        public MemTable(long maxSizeBytes)
        {
            _maxSize = maxSizeBytes;
            _store = new ConcurrentDictionary<string, MemEntry>();
        }

        public void Add(long sequence, string key, byte[] value, EntryType type)
        {
            var size = key.Length * 2 + (value?.Length ?? 0) + 16;
            var entry = new MemEntry(sequence, key, value, type);
            _store.AddOrUpdate(key, entry, (k, v) =>
            {
                Interlocked.Add(ref _currentSize, -EstimateSize(v));
                return entry;
            });
            Interlocked.Add(ref _currentSize, size);
        }

        public MemEntry Get(string key)
        {
            return _store.TryGetValue(key, out var entry) ? entry : null;
        }

        public long ApproximateMemoryUsage() => Interlocked.Read(ref _currentSize);

        public MemIterator NewIterator() => new MemIterator(_store.Values.OrderByDescending(x => x.Sequence));

        public ConcurrentDictionary<string, MemEntry> GetStore() => _store;

        private long EstimateSize(MemEntry e) => e.Key.Length * 2 + (e.Value?.Length ?? 0) + 16;
    }

    internal class MemEntry
    {
        public long Sequence { get; }
        public string Key { get; }
        public byte[] Value { get; }
        public EntryType Type { get; }

        public MemEntry(long seq, string key, byte[] value, EntryType type)
        {
            Sequence = seq;
            Key = key;
            Value = value;
            Type = type;
        }
    }

    internal class MemIterator
    {
        private readonly List<MemEntry> _entries;
        private int _index;

        public MemIterator(IEnumerable<MemEntry> entries)
        {
            _entries = entries.ToList();
        }

        public void SeekToFirst() => _index = 0;
        public void Next() => _index++;
        public bool Valid() => _index >= 0 && _index < _entries.Count;
        public string Key() => _entries[_index].Key;
        public byte[] Value() => _entries[_index].Value;
        public EntryType Type() => _entries[_index].Type;
    }

    internal class Wal
    {
        private readonly string _dir;
        private FileStream _writer;
        private readonly object _sync = new();

        public Wal(string dir, ref long logNumber)
        {
            _dir = dir;
            var files = Directory.GetFiles(_dir, "*.log").OrderBy(Path.GetFileNameWithoutExtension).ToList();
            if (files.Any())
            {
                var last = files.Last();
                logNumber = long.Parse(Path.GetFileNameWithoutExtension(last));
                _writer = new FileStream(Path.Combine(_dir, $"{logNumber + 1}.log"), FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
                logNumber++;
            }
            else
            {
                logNumber = 1;
                _writer = new FileStream(Path.Combine(_dir, $"{logNumber}.log"), FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
            }
        }

        public void AddRecord(WriteBatch batch)
        {
            byte[] data;
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(batch.Sequence);
                bw.Write(batch.Entries.Count);
                foreach (var e in batch.Entries)
                {
                    bw.Write((byte)e.Type);
                    bw.Write(e.Key);
                    bw.Write(e.Value?.Length ?? 0);
                    if (e.Value != null) bw.Write(e.Value);
                }
                data = ms.ToArray();
            }

            lock (_sync)
            {
                var len = data.Length;
                _writer.Write(BitConverter.GetBytes(len), 0, 4);
                _writer.Write(data, 0, len);
            }
        }

        public (long, List<MemEntry>) Recover()
        {
            var files = Directory.GetFiles(_dir, "*.log").OrderBy(Path.GetFileNameWithoutExtension).ToArray();
            long maxSeq = 0;
            var entries = new List<MemEntry>();

            foreach (var f in files)
            {
                try
                {
                    using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, FileOptions.SequentialScan);
                    using var br = new BinaryReader(fs);

                    while (fs.Position < fs.Length)
                    {
                        var lenBytes = br.ReadBytes(4);
                        if (lenBytes.Length < 4) break;
                        var len = BitConverter.ToInt32(lenBytes, 0);
                        if (len <= 0 || len > fs.Length - fs.Position) break;

                        var data = br.ReadBytes(len);

                        using var ms = new MemoryStream(data);
                        using var batchBr = new BinaryReader(ms);

                        var seq = batchBr.ReadInt64();
                        if (seq > maxSeq) maxSeq = seq;

                        var count = batchBr.ReadInt32();
                        for (int i = 0; i < count; i++)
                        {
                            var type = (EntryType)batchBr.ReadByte();
                            var key = batchBr.ReadString();
                            var valLen = batchBr.ReadInt32();
                            byte[] val = valLen > 0 ? batchBr.ReadBytes(valLen) : null;

                            entries.Add(new MemEntry(seq, key, val, type));
                        }
                    }
                }
                catch { }
            }

            return (maxSeq, entries);
        }

        public void DeleteLog(long number)
        {
            try
            {
                File.Delete(Path.Combine(_dir, $"{number}.log"));
            }
            catch { }
        }

        public void Dispose()
        {
            _writer?.Dispose();
        }
    }

    internal enum EntryType { Value, Delete }

    internal class WriteBatch
    {
        public long Sequence { get; set; }
        public List<BatchEntry> Entries { get; } = new();

        public void Put(string k, byte[] v) => Entries.Add(new BatchEntry { Type = EntryType.Value, Key = k, Value = v });
        public void Delete(string k) => Entries.Add(new BatchEntry { Type = EntryType.Delete, Key = k, Value = null });
    }

    internal class BatchEntry
    {
        public EntryType Type { get; set; }
        public string Key { get; set; }
        public byte[] Value { get; set; }
    }

    internal class SSTableWriter
    {
        private readonly FileStream _file;
        private readonly MiniDBOptions _options;
        private readonly List<BlockBuilder> _blocks;
        private readonly BlockBuilder _indexBlock;
        private FilterBlock _filterBlock;
        private long _offset;

        public SSTableWriter(string path, MiniDBOptions options)
        {
            _options = options;
            _file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough);
            _blocks = new List<BlockBuilder>();
            _indexBlock = new BlockBuilder(options);
            _filterBlock = new FilterBlock();
            _offset = 0;
        }

        public int Add(string key, EntryType type, byte[] value)
        {
            if (_blocks.Count == 0 || _blocks.Last().EstimateSize() >= _options.BlockSizeBytes)
            {
                if (_blocks.Count > 0)
                {
                    FlushBlock();
                }
                _blocks.Add(new BlockBuilder(_options));
            }

            var block = _blocks.Last();
            block.Add(key, type, value);
            _filterBlock.AddKey(key);
            return (int)(block.EstimateSize());
        }

        private void FlushBlock()
        {
            var block = _blocks.Last();
            var data = block.Finish();

            var handle = new BlockHandle { Offset = _offset, Size = data.Length };
            _indexBlock.Add(block.LastKey(), EntryType.Value, handle.Encode());

            _file.Write(data, 0, data.Length);
            _offset += data.Length;
        }

        public void Finish()
        {
            if (_blocks.Count > 0) FlushBlock();

            var filterData = _filterBlock.Generate();
            var indexData = _indexBlock.Finish();
            var footer = new Footer { IndexOffset = _offset, IndexSize = indexData.Length, FilterOffset = _offset + indexData.Length, FilterSize = filterData.Length };

            _file.Write(indexData, 0, indexData.Length);
            _file.Write(filterData, 0, filterData.Length);
            var footerBytes = footer.Encode();
            _file.Write(footerBytes, 0, footerBytes.Length);
            _file.Flush(true);
        }

        public void Dispose() => _file.Dispose();
    }

    internal class SSTableReader
    {
        private readonly string _file;
        private readonly FileStream _fs;
        private readonly Footer _footer;
        private readonly TableCache _cache;
        private readonly FilterBlock _filter;
        private readonly long _fileSize;
        private readonly MiniDBOptions _options;

        public SSTableReader(string file, TableCache cache, MiniDBOptions options)
        {
            _file = file;
            _fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
            _fileSize = _fs.Length;
            _cache = cache;
            _options = options;

            var footerBytes = new byte[Footer.Length];
            _fs.Seek(-Footer.Length, SeekOrigin.End);
            _fs.Read(footerBytes, 0, Footer.Length);
            _footer = Footer.Decode(footerBytes);

            _fs.Seek(_footer.FilterOffset, SeekOrigin.Begin);
            var filterBytes = new byte[_footer.FilterSize];
            _fs.Read(filterBytes, 0, filterBytes.Length);
            _filter = new FilterBlock(filterBytes);
        }

        public async Task<byte[]> GetAsync(string key)
        {
            if (!_filter.KeyMayMatch(key)) return null;

            var indexBlock = await _cache.GetBlock(_file, _footer.IndexOffset, _footer.IndexSize);
            var indexIter = new BlockIterator(indexBlock, _options);
            indexIter.Seek(key);

            if (!indexIter.Valid()) return null;

            var handle = BlockHandle.Decode(indexIter.Value());
            var dataBlock = await _cache.GetBlock(_file, handle.Offset, handle.Size);
            var dataIter = new BlockIterator(dataBlock, _options);
            dataIter.Seek(key);

            if (dataIter.Valid() && dataIter.Key() == key)
            {
                if (dataIter.Type() == EntryType.Delete) return null;
                return dataIter.Value();
            }

            return null;
        }

        public void Dispose() => _fs.Dispose();
    }

    internal class TableCache
    {
        private readonly MiniDBOptions _options;
        private readonly string _directory;
        private readonly ConcurrentDictionary<long, SSTableReader> _tables;
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<long, CacheEntry>> _blockCache;
        private long _cacheSize;
        private readonly long _maxCacheSize;

        public TableCache(MiniDBOptions options, string directory)
        {
            _options = options;
            _directory = directory;
            _tables = new ConcurrentDictionary<long, SSTableReader>();
            _blockCache = new ConcurrentDictionary<string, ConcurrentDictionary<long, CacheEntry>>();
            _maxCacheSize = options.BlockCacheSizeBytes;
        }

        public async Task<byte[]> GetAsync(long fileNumber, string key)
        {
            var path = Path.Combine(_directory, "sst", $"{fileNumber}.sst");
            var reader = GetTable(fileNumber);
            return await reader.GetAsync(key);
        }

        public SSTableReader GetTable(long fileNumber)
        {
            var path = Path.Combine(_directory, "sst", $"{fileNumber}.sst");
            return _tables.GetOrAdd(fileNumber, n => new SSTableReader(path, this, _options));
        }

        public async Task<byte[]> GetBlock(string file, long offset, int size)
        {
            var fileCache = _blockCache.GetOrAdd(file, f => new ConcurrentDictionary<long, CacheEntry>());

            if (fileCache.TryGetValue(offset, out var entry))
            {
                entry.LastAccess = DateTime.UtcNow.Ticks;
                return entry.Data;
            }

            byte[] data;
            using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan))
            {
                fs.Seek(offset, SeekOrigin.Begin);
                data = new byte[size];
                await fs.ReadAsync(data, 0, size);
            }

            if (_options.EnableCompression)
            {
                data = Decompress(data);
            }

            var current = Interlocked.Add(ref _cacheSize, size);
            if (current > _maxCacheSize)
            {
                Evict();
            }

            fileCache[offset] = new CacheEntry { Data = data, Size = size, LastAccess = DateTime.UtcNow.Ticks };
            return data;
        }

        public void EvictFile(long fileNumber)
        {
            if (_tables.TryRemove(fileNumber, out var reader))
            {
                reader.Dispose();
            }

            var path = Path.Combine(_directory, "sst", $"{fileNumber}.sst");
            if (_blockCache.TryRemove(path, out var fileCache))
            {
                long removedSize = 0;
                foreach (var entry in fileCache.Values)
                {
                    removedSize += entry.Size;
                }
                Interlocked.Add(ref _cacheSize, -removedSize);
            }
        }

        private void Evict()
        {
            var list = _blockCache.SelectMany(x => x.Value.Select(y => (File: x.Key, Offset: y.Key, Entry: y.Value))).ToList();
            list.Sort((a, b) => a.Entry.LastAccess.CompareTo(b.Entry.LastAccess));

            long removed = 0;
            foreach (var item in list)
            {
                if (removed > _maxCacheSize / 4) break;
                if (_blockCache.TryGetValue(item.File, out var fCache))
                {
                    if (fCache.TryRemove(item.Offset, out _))
                    {
                        removed += item.Entry.Size;
                    }
                }
            }
            Interlocked.Add(ref _cacheSize, -removed);
        }

        private byte[] Decompress(byte[] data)
        {
            try
            {
                using var output = new MemoryStream();
                using (var input = new MemoryStream(data))
                using (var ds = new DeflateStream(input, CompressionMode.Decompress))
                {
                    ds.CopyTo(output);
                }
                return output.ToArray();
            }
            catch
            {
                return data;
            }
        }

        public void Dispose()
        {
            foreach (var t in _tables.Values) t.Dispose();
        }

        private class CacheEntry
        {
            public byte[] Data;
            public int Size;
            public long LastAccess;
        }
    }

    internal class BlockBuilder
    {
        private readonly List<byte[]> _buffer;
        private readonly List<int> _restarts;
        private readonly MiniDBOptions _options;
        private string _lastKey;
        private int _counter;
        private bool _finished;

        public BlockBuilder(MiniDBOptions options)
        {
            _options = options;
            _buffer = new List<byte[]>();
            _restarts = new List<int>();
            _counter = 0;
        }

        public void Add(string key, EntryType type, byte[] value)
        {
            var shared = 0;
            if (_counter > 0)
            {
                var minLen = Math.Min(_lastKey.Length, key.Length);
                while (shared < minLen && _lastKey[shared] == key[shared]) shared++;
            }

            var nonShared = key.Length - shared;
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            bw.Write((uint)shared);
            bw.Write((uint)nonShared);
            bw.Write((byte)type);
            bw.Write((uint)(value?.Length ?? 0));

            if (nonShared > 0)
            {
                var keyBytes = Encoding.UTF8.GetBytes(key.Substring(shared));
                bw.Write(keyBytes);
            }
            if (value != null) bw.Write(value);

            _buffer.Add(ms.ToArray());
            _lastKey = key;
            _counter++;

            if (_counter >= 16)
            {
                _restarts.Add(_buffer.Sum(x => x.Length));
                _counter = 0;
            }
        }

        public int EstimateSize()
        {
            var size = _buffer.Sum(x => x.Length);
            size += _restarts.Count * 4;
            size += 4;
            return size;
        }

        public string LastKey() => _lastKey;

        public byte[] Finish()
        {
            if (_finished) throw new InvalidOperationException();
            _finished = true;

            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            foreach (var b in _buffer) bw.Write(b);
            foreach (var r in _restarts) bw.Write(r);
            bw.Write(_restarts.Count);

            var data = ms.ToArray();

            if (_options.EnableCompression)
            {
                try
                {
                    using var outMs = new MemoryStream();
                    using (var dStream = new DeflateStream(outMs, CompressionLevel.Optimal))
                    {
                        dStream.Write(data, 0, data.Length);
                    }
                    return outMs.ToArray();
                }
                catch
                {
                    return data;
                }
            }

            return data;
        }
    }

    internal class BlockIterator
    {
        private readonly byte[] _data;
        private readonly List<int> _restarts;
        private int _offset;
        private readonly MiniDBOptions _options;
        private string _currentKey;
        private byte[] _currentValue;
        private EntryType _currentType;

        public BlockIterator(byte[] data, MiniDBOptions options)
        {
            _data = data;
            _options = options;
            var restartCount = BitConverter.ToInt32(data, data.Length - 4);
            _restarts = new List<int>();
            for (int i = 0; i < restartCount; i++)
            {
                _restarts.Add(BitConverter.ToInt32(data, data.Length - 4 - (i + 1) * 4));
            }
        }

        public void Seek(string key)
        {
            int left = 0;
            int right = _restarts.Count - 1;

            if (_restarts.Count == 0) return;

            while (left < right)
            {
                var mid = (left + right + 1) / 2;
                _offset = _restarts[mid];
                ParseEntryAt(_offset);
                if (string.Compare(_currentKey, key, StringComparison.Ordinal) < 0)
                {
                    left = mid;
                }
                else
                {
                    right = mid - 1;
                }
            }

            _offset = _restarts[left];
            ParseEntryAt(_offset);

            while (Valid() && string.Compare(_currentKey, key, StringComparison.Ordinal) < 0)
            {
                Next();
            }
        }

        public bool Valid()
        {
            return _offset >= 0 && _offset < _data.Length - 4 - (_restarts.Count * 4);
        }

        public void Next()
        {
            ParseEntryAt(_offset);
            var shared = BitConverter.ToUInt32(_data, _offset);
            var nonShared = BitConverter.ToUInt32(_data, _offset + 4);
            var valLen = BitConverter.ToUInt32(_data, _offset + 9);
            var entrySize = 13 + (int)nonShared + (int)valLen;
            _offset += entrySize;
        }

        public string Key() => _currentKey;
        public byte[] Value() => _currentValue;
        public EntryType Type() => _currentType;

        private void ParseEntryAt(int offset)
        {
            if (offset < 0 || offset + 13 > _data.Length)
            {
                _currentKey = null;
                return;
            }
            var shared = BitConverter.ToUInt32(_data, offset);
            var nonShared = BitConverter.ToUInt32(_data, offset + 4);
            _currentType = (EntryType)_data[offset + 8];
            var valLen = BitConverter.ToUInt32(_data, offset + 9);

            var keyOffset = offset + 13;
            var valOffset = keyOffset + (int)nonShared;

            if (keyOffset + (int)nonShared > _data.Length || valOffset + (int)valLen > _data.Length)
            {
                _currentKey = null;
                return;
            }

            if (_currentKey != null && shared > 0)
            {
                var newKey = new char[shared + nonShared];
                for (int i = 0; i < shared; i++) newKey[i] = _currentKey[i];
                for (int i = 0; i < nonShared; i++) newKey[i + (int)shared] = (char)_data[keyOffset + i];
                _currentKey = new string(newKey);
            }
            else
            {
                _currentKey = Encoding.UTF8.GetString(_data, keyOffset, (int)nonShared);
            }

            _currentValue = valLen > 0 ? new byte[valLen] : null;
            if (valLen > 0)
            {
                Buffer.BlockCopy(_data, valOffset, _currentValue, 0, (int)valLen);
            }
        }
    }

    internal class FilterBlock
    {
        private const int FILTER_BASE_LG = 11;
        private List<ulong> _filter;
        private List<uint> _offsets;
        private string _lastKey;

        public FilterBlock()
        {
            _filter = new List<ulong>();
            _offsets = new List<uint>();
        }

        public FilterBlock(byte[] data)
        {
            var n = BitConverter.ToInt32(data, 0);
            var baseLg = data[4];
            _offsets = new List<uint>(n);
            int pos = 5;
            for (int i = 0; i <= n; i++)
            {
                _offsets.Add(BitConverter.ToUInt32(data, pos));
                pos += 4;
            }
            var filterData = new byte[data.Length - pos];
            Buffer.BlockCopy(data, pos, filterData, 0, filterData.Length);

            _filter = new List<ulong>(filterData.Length / 8);
            for (int i = 0; i < filterData.Length; i += 8)
            {
                _filter.Add(BitConverter.ToUInt64(filterData, i));
            }
        }

        public void AddKey(string key)
        {
            var hash = Hash(key);
            var idx = hash & 0x7fffffff;

            var delta = idx >> 17 | idx << 15;

            if (_filter.Count == 0) _filter.Capacity = 1000;

            while (_filter.Count <= (int)(idx % (uint)_filter.Capacity))
            {
                _filter.Add(0);
            }

            var arrayIdx = (int)(idx % (uint)_filter.Count);
            _filter[arrayIdx] |= delta | (1UL << (int)(idx % 64));
            _lastKey = key;
        }

        public bool KeyMayMatch(string key)
        {
            if (_filter.Count == 0) return true;
            var h = Hash(key);
            var i = (int)(h >> 17);
            if (i < 0 || i >= _filter.Count) return true;
            return (_filter[i] & (1UL << (int)(h & 63))) != 0;
        }

        public byte[] Generate()
        {
            using var ms = new MemoryStream();
            var bw = new BinaryWriter(ms);
            bw.Write(_offsets.Count - 1);
            bw.Write((byte)FILTER_BASE_LG);
            foreach (var o in _offsets) bw.Write(o);

            var filterBytes = new byte[_filter.Count * 8];
            Buffer.BlockCopy(_filter.ToArray(), 0, filterBytes, 0, filterBytes.Length);
            bw.Write(filterBytes);

            return ms.ToArray();
        }

        private uint Hash(string key)
        {
            var bytes = Encoding.UTF8.GetBytes(key);
            uint h = 0xDEADBEEF;
            foreach (var b in bytes)
            {
                h += b;
                h += h << 10;
                h ^= h >> 6;
            }
            h += h << 3;
            h ^= h >> 11;
            h += h << 15;
            return h;
        }
    }

    internal struct BlockHandle
    {
        public long Offset;
        public int Size;

        public byte[] Encode()
        {
            var bytes = new byte[12];
            Buffer.BlockCopy(BitConverter.GetBytes(Offset), 0, bytes, 0, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(Size), 0, bytes, 8, 4);
            return bytes;
        }

        public static BlockHandle Decode(byte[] data)
        {
            return new BlockHandle
            {
                Offset = BitConverter.ToInt64(data, 0),
                Size = BitConverter.ToInt32(data, 8)
            };
        }
    }

    internal struct Footer
    {
        public const int Length = 48;
        public long IndexOffset;
        public int IndexSize;
        public long FilterOffset;
        public int FilterSize;

        public byte[] Encode()
        {
            var bytes = new byte[Length];
            var i = 0;
            Buffer.BlockCopy(BitConverter.GetBytes(IndexOffset), 0, bytes, i, 8); i += 8;
            Buffer.BlockCopy(BitConverter.GetBytes(IndexSize), 0, bytes, i, 4); i += 4;
            Buffer.BlockCopy(BitConverter.GetBytes(FilterOffset), 0, bytes, i, 8); i += 8;
            Buffer.BlockCopy(BitConverter.GetBytes(FilterSize), 0, bytes, i, 4); i += 4;
            var meta = Encoding.UTF8.GetBytes("minidb.footer");
            Buffer.BlockCopy(meta, 0, bytes, i, meta.Length);
            return bytes;
        }

        public static Footer Decode(byte[] data)
        {
            return new Footer
            {
                IndexOffset = BitConverter.ToInt64(data, 0),
                IndexSize = BitConverter.ToInt32(data, 8),
                FilterOffset = BitConverter.ToInt64(data, 12),
                FilterSize = BitConverter.ToInt32(data, 20)
            };
        }
    }

    internal class VersionSet
    {
        private readonly string _directory;
        private readonly MiniDBOptions _options;
        private readonly TableCache _cache;
        private readonly Logger _logger;
        private Version _current;
        private long _nextFileNumber;
        private ConcurrentDictionary<string, MemEntry> _immutable;

        public VersionSet(string directory, MiniDBOptions options, TableCache cache, Logger logger)
        {
            _directory = directory;
            _options = options;
            _cache = cache;
            _logger = logger;
            _current = new Version();
            _immutable = new ConcurrentDictionary<string, MemEntry>();
        }

        public void Load()
        {
            var files = Directory.GetFiles(Path.Combine(_directory, "sst"), "*.sst");
            foreach (var f in files)
            {
                if (long.TryParse(Path.GetFileNameWithoutExtension(f), out long num))
                {
                    if (num > _nextFileNumber) _nextFileNumber = num + 1;
                    var meta = new FileMetaData { Number = num, AllowedSeeks = 1 << 30, Smallest = new InternalKey(""), Largest = new InternalKey("") };
                    _current.Files[0].Add(meta);
                }
            }
        }

        public void LogAndApply(int level, FileMetaData f)
        {
            var v = new Version();
            for (int i = 0; i < 7; i++) v.Files[i] = new List<FileMetaData>(_current.Files[i]);
            v.Files[level].Add(f);
            _current = v;
        }

        public Version Current() => _current;

        public long NewFileNumber() => Interlocked.Increment(ref _nextFileNumber);

        public MemEntry GetImmutable(string key)
        {
            return _immutable.TryGetValue(key, out var e) ? e : null;
        }

        public void SetImmutable(ConcurrentDictionary<string, MemEntry> imm) => _immutable = imm;

        public bool NeedsCompaction() => _current.Files[0].Count >= _options.Level0CompactionTrigger;

        public async Task DoCompaction()
        {
            var files = _current.Files[0].OrderBy(f => f.Number).ToList();
            if (files.Count < _options.Level0CompactionTrigger) return;

            _logger.Log($"Compacting {files.Count} files from L0 to L1");

            var meta = new FileMetaData
            {
                Number = NewFileNumber(),
                Size = 0
            };

            var path = Path.Combine(_directory, "sst", $"{meta.Number}.sst");
            var writer = new SSTableWriter(path, _options);

            bool first = true;
            foreach (var entry in _immutable.Values.OrderBy(x => x.Key))
            {
                if (first)
                {
                    meta.Smallest = new InternalKey(entry.Key);
                    meta.Largest = new InternalKey(entry.Key);
                    first = false;
                }
                else
                {
                    if (string.Compare(entry.Key, meta.Smallest.UserKey) < 0) meta.Smallest = new InternalKey(entry.Key);
                    if (string.Compare(entry.Key, meta.Largest.UserKey) > 0) meta.Largest = new InternalKey(entry.Key);
                }
                meta.Size += writer.Add(entry.Key, entry.Type, entry.Value);
            }
            writer.Finish();

            var v = new Version();
            v.Files[0] = new List<FileMetaData>();
            for (int i = 1; i < 7; i++) v.Files[i] = new List<FileMetaData>(_current.Files[i]);

            v.Files[1].Add(meta);
            _current = v;

            foreach (var f in files)
            {
                try
                {
                    _cache.GetTable(f.Number).Dispose();
                    _cache.EvictFile(f.Number);
                    File.Delete(Path.Combine(_directory, "sst", $"{f.Number}.sst"));
                }
                catch { }
            }
            _immutable.Clear();
        }

        public async Task<byte[]> GetAsync(string key)
        {
            foreach (var f in _current.Files[0])
            {
                var val = await _cache.GetAsync(f.Number, key);
                if (val != null) return val;
            }

            for (int l = 1; l < 7; l++)
            {
                var file = _current.Files[l].FirstOrDefault(f => string.Compare(f.Smallest.UserKey, key) <= 0 && string.Compare(f.Largest.UserKey, key) >= 0);
                if (file != null)
                {
                    var val = await _cache.GetAsync(file.Number, key);
                    if (val != null) return val;
                }
            }
            return null;
        }
    }

    internal class Version
    {
        public List<List<FileMetaData>> Files { get; set; } = new List<List<FileMetaData>>
        {
            new(), new(), new(), new(), new(), new(), new()
        };
    }

    internal class FileMetaData
    {
        public long Number;
        public long Size;
        public InternalKey Smallest;
        public InternalKey Largest;
        public long AllowedSeeks;
    }

    internal struct InternalKey
    {
        public string UserKey;
        public InternalKey(string key) { UserKey = key; }
    }
}