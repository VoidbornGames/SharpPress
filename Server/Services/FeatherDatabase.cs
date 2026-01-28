using Microsoft.Data.Sqlite;
using System.Collections.Concurrent;
using System.Data;
using System.Reflection;
using System.Security;
using SharpPress.Services;

namespace SharpPress.Services
{
    /// <summary>
    /// A lightweight, high-performance SQLite wrapper with Auto-Migration.
    /// Usage is similar to JsonConvert: db.Save(obj), db.Get&lt;T&gt;(id)
    /// </summary>
    public class FeatherDatabase
    {
        private readonly string _connectionString;
        private readonly Logger _logger;

        private static readonly ConcurrentDictionary<Type, PropertyInfo[]> _propertyCache = new();

        public FeatherDatabase(Logger logger, string dbFilename = "data.db")
        {
            _logger = logger;
            var dbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, dbFilename);
            _connectionString = $"Data Source={dbPath}";

            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            _logger.Log($"💾 FeatherDatabase connected to {dbPath}");

            using var cmd = new SqliteCommand("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;", connection);
            cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Creates a table for type T if it doesn't exist.
        /// ALSO performs Auto-Migration: adds new columns if you update your C# class.
        /// </summary>
        public void CreateTable<T>() where T : new()
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var tableName = GetTableName(type);

            var sql = $"CREATE TABLE IF NOT EXISTS [{tableName}] (";

            bool hasId = false;
            foreach (var prop in props)
            {
                if (prop.Name.ToLower() == "id")
                {
                    sql += $"[{prop.Name}] INTEGER PRIMARY KEY AUTOINCREMENT, ";
                    hasId = true;
                }
                else
                {
                    var sqlType = GetSqlType(prop.PropertyType);
                    sql += $"[{prop.Name}] {sqlType}, ";
                }
            }

            sql = sql.TrimEnd(',', ' ') + ")";

            ExecuteNonQuery(sql);
            _logger.Log($"📋 Table '{tableName}' ensured.");

            EnsureTableStructure(tableName, props);
        }

        /// <summary>
        /// Compares C# properties to Database Columns and adds missing ones.
        /// </summary>
        private void EnsureTableStructure(string tableName, PropertyInfo[] props)
        {
            try
            {
                var existingColumns = GetTableColumns(tableName);

                foreach (var prop in props)
                {
                    if (prop.Name.ToLower() == "id") continue;

                    if (!existingColumns.Contains(prop.Name))
                    {
                        var sqlType = GetSqlType(prop.PropertyType);
                        var alterSql = $"ALTER TABLE [{tableName}] ADD COLUMN [{prop.Name}] {sqlType}";
                        _logger.Log($"🔄 Migrating DB: Adding column '{prop.Name}' to table '{tableName}'");
                        ExecuteNonQuery(alterSql);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Migration failed for {tableName}: {ex.Message}");
            }
        }

        /// <summary>
        /// Helper to query SQLite for the list of columns in a table.
        /// </summary>
        private HashSet<string> GetTableColumns(string tableName)
        {
            var columns = new HashSet<string>();
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = new SqliteCommand($"PRAGMA table_info({tableName})", connection);
            using var reader = cmd.ExecuteReader();

            while (reader.Read())
            {
                columns.Add(reader.GetString(1));
            }
            return columns;
        }

        /// <summary>
        /// Rebuilds the database file, reclaiming free space and defragmenting the database.
        /// This reduces the file size on disk. 
        /// WARNING: This can lock the database for a moment depending on size. Run during maintenance/low-traffic windows.
        /// </summary>
        public void VacuumDatabase()
        {
            ExecuteNonQuery("VACUUM;");
        }

        /// <summary>
        /// Retrieves a specific "page" of data. 
        /// Essential for leaderboards or logs to prevent loading the whole database into RAM.
        /// </summary>
        public List<T> GetPaged<T>(int pageNumber, int pageSize, string orderByColumn = "Id") where T : new()
        {
            var type = typeof(T);
            var tableName = GetTableName(type);
            var props = GetCachedProperties(type);
            var list = new List<T>();

            int offset = (pageNumber - 1) * pageSize;
            if (!props.Any(p => p.Name.Equals(orderByColumn, StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException($"Column '{orderByColumn}' does not exist for paging.");
            }

            var sql = $"SELECT * FROM [{tableName}] ORDER BY [{orderByColumn}] LIMIT @Limit OFFSET @Offset";

            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = new SqliteCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Limit", pageSize);
            cmd.Parameters.AddWithValue("@Offset", offset);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(MapReaderToObject<T>(reader, props));
            }
            return list;
        }

        /// <summary>
        /// Efficiently deletes multiple records based on a condition.
        /// Example: DeleteWhere<Log>("WHERE CreatedAt < @Date", new SqliteParameter("@Date", oldDate))
        /// </summary>
        public int DeleteWhere<T>(string whereClause, params SqliteParameter[] parameters) where T : new()
        {
            var tableName = GetTableName(typeof(T));

            if (string.IsNullOrWhiteSpace(whereClause) || !whereClause.TrimStart().ToUpper().StartsWith("WHERE"))
            {
                throw new ArgumentException("You must provide a WHERE clause (e.g., \"WHERE Id = 1\") to prevent accidental full table deletion.");
            }

            var sql = $"DELETE FROM [{tableName}] {whereClause}";

            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = new SqliteCommand(sql, connection);
            if (parameters != null) cmd.Parameters.AddRange(parameters);

            return cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Executes a SQL query and returns the first value of the first row.
        /// Use this for COUNT, SUM, MAX, MIN, etc.
        /// </summary>
        public object? ExecuteScalar(string sql, params SqliteParameter[] parameters)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = new SqliteCommand(sql, connection);
            if (parameters != null) cmd.Parameters.AddRange(parameters);

            return cmd.ExecuteScalar();
        }

        /// <summary>
        /// Checks if any record exists for the given type matching the SQL condition.
        /// Example: Exists<User>("WHERE Username = @Name", new SqliteParameter("@Name", "admin"))
        /// </summary>
        public bool Exists<T>(string whereClause = "", params SqliteParameter[] parameters) where T : new()
        {
            var tableName = GetTableName(typeof(T));
            var sql = $"SELECT 1 FROM [{tableName}]";

            if (!string.IsNullOrWhiteSpace(whereClause))
            {
                if (whereClause.Contains(";")) throw new ArgumentException("Invalid SQL in Exists");
                sql += $" " + whereClause;
            }

            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = new SqliteCommand(sql, connection);
            if (parameters != null) cmd.Parameters.AddRange(parameters);

            return cmd.ExecuteScalar() != null;
        }

        /// <summary>
        /// Returns the total number of rows in a table.
        /// </summary>
        public int Count<T>() where T : new()
        {
            var tableName = GetTableName(typeof(T));
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var cmd = new SqliteCommand($"SELECT COUNT(*) FROM [{tableName}]", connection);
            return Convert.ToInt32(cmd.ExecuteScalar());
        }

        /// <summary>
        /// Executes a custom SQL query and maps the results to objects.
        /// Useful for complex WHERE clauses or JOINs.
        /// Example: ExecuteQuery<User>("SELECT * FROM Users WHERE Score > @MinScore", new SqliteParameter("@MinScore", 100))
        /// </summary>
        public List<T> ExecuteQuery<T>(string sql, params SqliteParameter[] parameters) where T : new()
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var list = new List<T>();

            if (sql.ToUpper().Contains("DROP ") || sql.ToUpper().Contains("DELETE ") || sql.ToUpper().Contains("TRUNCATE "))
            {
                throw new SecurityException("ExecuteQuery is for SELECT only. Use ExecuteNonQuery for modifications.");
            }

            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = new SqliteCommand(sql, connection);
            if (parameters != null) cmd.Parameters.AddRange(parameters);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(MapReaderToObject<T>(reader, props));
            }
            return list;
        }

        /// <summary>
        /// Creates an index on a specific column to drastically speed up searches.
        /// Call this in your startup code for columns you search by frequently (e.g., Username, Email).
        /// </summary>
        public void CreateIndex<T>(string columnName, bool unique = false)
        {
            var tableName = GetTableName(typeof(T));
            var indexName = $"IDX_{tableName}_{columnName}";
            var uniqueSql = unique ? "UNIQUE" : "";

            var sql = $"CREATE {uniqueSql} INDEX IF NOT EXISTS [{indexName}] ON [{tableName}] ([{columnName}]);";

            ExecuteNonQuery(sql);
        }

        /// <summary>
        /// Saves a single object. Updates if ID > 0, Inserts if ID == 0.
        /// </summary>
        public void SaveData<T>(T obj) where T : new()
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            SaveInternal(connection, null, obj);
        }

        /// <summary>
        /// Saves a List of objects efficiently using a single Transaction.
        /// </summary>
        public void SaveMultiData<T>(List<T> items) where T : new()
        {
            if (items == null || items.Count == 0) return;

            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var transaction = connection.BeginTransaction();

            try
            {
                foreach (var item in items)
                {
                    SaveInternal(connection, transaction, item);
                }
                transaction.Commit();
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }

        /// <summary>
        /// Internal logic to perform the Insert or Update. 
        /// Can be reused by single saves or batch transactions.
        /// </summary>
        private void SaveInternal<T>(SqliteConnection connection, SqliteTransaction transaction, T obj) where T : new()
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var tableName = GetTableName(type);

            var idProp = props.FirstOrDefault(p => p.Name.ToLower() == "id");
            var idValue = idProp?.GetValue(obj);

            if (idValue != null && (int)idValue > 0)
            {
                var setClause = string.Join(", ", props
                    .Where(p => p.Name.ToLower() != "id")
                    .Select(p => $"[{p.Name}] = @{p.Name}"));

                var sql = $"UPDATE [{tableName}] SET {setClause} WHERE [{idProp.Name}] = @Id";

                using var cmd = new SqliteCommand(sql, connection);
                cmd.Transaction = transaction;
                cmd.Parameters.AddWithValue("@Id", idValue);
                foreach (var prop in props.Where(p => p.Name.ToLower() != "id"))
                {
                    cmd.Parameters.AddWithValue($"@{prop.Name}", prop.GetValue(obj) ?? DBNull.Value);
                }
                cmd.ExecuteNonQuery();
            }
            else
            {
                var columns = props.Where(p => p.Name.ToLower() != "id").Select(p => $"[{p.Name}]");
                var values = props.Where(p => p.Name.ToLower() != "id").Select(p => $"@{p.Name}");

                var sql = $"INSERT INTO [{tableName}] ({string.Join(", ", columns)}) VALUES ({string.Join(", ", values)})";

                using var cmd = new SqliteCommand(sql, connection);
                cmd.Transaction = transaction; // Bind to the transaction
                foreach (var prop in props.Where(p => p.Name.ToLower() != "id"))
                {
                    cmd.Parameters.AddWithValue($"@{prop.Name}", prop.GetValue(obj) ?? DBNull.Value);
                }
                cmd.ExecuteNonQuery();

                long lastId;
                using (var idCmd = new SqliteCommand("SELECT last_insert_rowid();", connection))
                {
                    idCmd.Transaction = transaction;
                    lastId = (long)idCmd.ExecuteScalar();
                }

                if (idProp != null && idProp.PropertyType == typeof(int))
                {
                    idProp.SetValue(obj, (int)lastId);
                }
            }
        }

        /// <summary>
        /// Retrieves a single object by ID.
        /// </summary>
        public T? GetData<T>(int id) where T : new()
        {
            var type = typeof(T);
            var tableName = GetTableName(type);
            var props = GetCachedProperties(type);
            var idProp = props.FirstOrDefault(p => p.Name.ToLower() == "id");

            if (idProp == null) throw new Exception($"Type {type.Name} does not have an ID property.");

            var sql = $"SELECT * FROM [{tableName}] WHERE [{idProp.Name}] = @Id";

            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = new SqliteCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Id", id);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return MapReaderToObject<T>(reader, props);
            }
            return default;
        }

        /// <summary>
        /// Retrieves all objects of type T.
        /// </summary>
        public List<T> GetAll<T>() where T : new()
        {
            var type = typeof(T);
            var tableName = GetTableName(type);
            var props = GetCachedProperties(type);
            var list = new List<T>();
            var sql = $"SELECT * FROM [{tableName}]";

            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = new SqliteCommand(sql, connection);
            using var reader = cmd.ExecuteReader();

            while (reader.Read())
            {
                list.Add(MapReaderToObject<T>(reader, props));
            }
            return list;
        }

        /// <summary>
        /// Safely retrieves a single record by a specific column value.
        /// </summary>
        public T? GetByColumn<T>(string columnName, object value) where T : new()
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var tableName = GetTableName(type);

            var columnProp = props.FirstOrDefault(p => p.Name.Equals(columnName, StringComparison.OrdinalIgnoreCase));
            if (columnProp == null)
            {
                throw new ArgumentException($"Column '{columnName}' does not exist in table '{tableName}'.");
            }

            var sql = $"SELECT * FROM [{tableName}] WHERE [{columnProp.Name}] = @Value LIMIT 1";

            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = new SqliteCommand(sql, connection);

            cmd.Parameters.AddWithValue("@Value", value);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return MapReaderToObject<T>(reader, props);
            }
            return default;
        }

        /// <summary>
        /// Safely retrieves a list of records by a specific column value.
        /// </summary>
        public List<T> GetListByColumn<T>(string columnName, object value) where T : new()
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var tableName = GetTableName(type);

            var columnProp = props.FirstOrDefault(p => p.Name.Equals(columnName, StringComparison.OrdinalIgnoreCase));
            if (columnProp == null)
            {
                throw new ArgumentException($"Column '{columnName}' does not exist in table '{tableName}'.");
            }

            var sql = $"SELECT * FROM [{tableName}] WHERE [{columnProp.Name}] = @Value";
            var list = new List<T>();

            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = new SqliteCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Value", value);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(MapReaderToObject<T>(reader, props));
            }
            return list;
        }

        /// <summary>
        /// Deletes an object by ID.
        /// </summary>
        public void Delete<T>(int id) where T : new()
        {
            var type = typeof(T);
            var tableName = GetTableName(type);
            var props = GetCachedProperties(type);
            var idProp = props.FirstOrDefault(p => p.Name.ToLower() == "id");

            if (idProp == null) return;

            var sql = $"DELETE FROM [{tableName}] WHERE [{idProp.Name}] = @Id";
            ExecuteNonQuery(sql, new SqliteParameter("@Id", id));
        }

        /// <summary>
        /// Executes a raw SQL command (Non-Query).
        /// </summary>
        public void ExecuteNonQuery(string sql, params SqliteParameter[] parameters)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var cmd = new SqliteCommand(sql, connection);
            if (parameters != null)
            {
                cmd.Parameters.AddRange(parameters);
            }
            cmd.ExecuteNonQuery();
            
        }

        // --- Helper Methods ---

        private T MapReaderToObject<T>(SqliteDataReader reader, PropertyInfo[] props) where T : new()
        {
            var obj = new T();
            var columnLookup = new Dictionary<string, int>(reader.FieldCount);
            for (int i = 0; i < reader.FieldCount; i++)
            {
                columnLookup[reader.GetName(i)] = i;
            }

            foreach (var prop in props)
            {
                if (!columnLookup.TryGetValue(prop.Name, out int ordinal)) continue;

                var val = reader.GetValue(ordinal);
                if (val == DBNull.Value) continue;

                Type targetType = prop.PropertyType;
                Type? underlyingType = Nullable.GetUnderlyingType(targetType);

                if (underlyingType != null)
                {
                    targetType = underlyingType;
                }

                if (targetType == typeof(Guid))
                {
                    if (val is string s)
                    {
                        prop.SetValue(obj, Guid.Parse(s));
                    }
                    else if (val is byte[] b)
                    {
                        prop.SetValue(obj, new Guid(b));
                    }
                    continue;
                }

                prop.SetValue(obj, Convert.ChangeType(val, targetType));
            }
            return obj;
        }

        private PropertyInfo[] GetCachedProperties(Type type)
        {
            return _propertyCache.GetOrAdd(type, t => t.GetProperties(BindingFlags.Public | BindingFlags.Instance));
        }

        private string GetTableName(Type type)
        {
            return type.Name;
        }

        private string GetSqlType(Type type)
        {
            if (type == typeof(int) || type == typeof(long) || type == typeof(bool)) return "INTEGER";
            if (type == typeof(double) || type == typeof(float) || type == typeof(decimal)) return "REAL";
            if (type == typeof(string) || type == typeof(DateTime)) return "TEXT";
            return "TEXT";
        }
    }
}