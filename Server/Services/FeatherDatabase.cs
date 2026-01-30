using MySqlConnector;
using SharpPress.Models;
using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Reflection;
using System.Security;

namespace SharpPress.Services
{
    public sealed class FeatherDatabase
    {
        private readonly string _connectionString;
        private readonly Logger _logger;

        private static readonly ConcurrentDictionary<Type, PropertyInfo[]> _propertyCache = new();

        public FeatherDatabase(Logger logger, MySQL_Config mySQL_Config)
        {
            _logger = logger;
            try
            {
                var serverBuilder = new MySqlConnectionStringBuilder
                {
                    Server = mySQL_Config.host,
                    Port = (uint)mySQL_Config.port,
                    UserID = mySQL_Config.database_username,
                    Password = mySQL_Config.database_password,
                    SslMode = MySqlSslMode.Preferred,
                    Pooling = false,
                    ConnectionTimeout = 5,
                    DefaultCommandTimeout = 30,
                    AllowUserVariables = false
                };

                using (var serverConnection = new MySqlConnection(serverBuilder.ConnectionString))
                {
                    serverConnection.Open();

                    using var cmd = serverConnection.CreateCommand();
                    cmd.CommandText =
                        $"CREATE DATABASE IF NOT EXISTS `{mySQL_Config.database_name}` " +
                        "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";

                    cmd.ExecuteNonQuery();
                }

                var builder = new MySqlConnectionStringBuilder
                {
                    Server = mySQL_Config.host,
                    Port = (uint)mySQL_Config.port,
                    Database = mySQL_Config.database_name,
                    UserID = mySQL_Config.database_username,
                    Password = mySQL_Config.database_password,
                    SslMode = MySqlSslMode.Preferred,
                    Pooling = true,
                    MinimumPoolSize = 0,
                    MaximumPoolSize = 100,
                    ConnectionTimeout = 5,
                    DefaultCommandTimeout = 30,
                    AllowUserVariables = false
                };

                _connectionString = builder.ConnectionString;

                using var connection = new MySqlConnection(_connectionString);
                connection.Open();

                _logger.Log($"💾 FeatherDatabase connected to MySQL {mySQL_Config.host}:{mySQL_Config.port}/{mySQL_Config.database_name}");
            }
            catch(Exception ex)
            {
                _logger.LogError($"Error connecting to MySQL: {ex.Message}");
            }
        }

        public void CreateTable<T>() where T : new()
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var tableName = GetTableName(type);

            var parts = new List<string>();

            bool hasId = false;

            foreach (var prop in props)
            {
                if (prop.Name.Equals("Id", StringComparison.OrdinalIgnoreCase))
                {
                    parts.Add($"`{prop.Name}` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY");
                    hasId = true;
                }
                else
                {
                    var sqlType = GetSqlType(prop.PropertyType);
                    parts.Add($"`{prop.Name}` {sqlType} NULL");
                }
            }

            if (!hasId)
            {
                throw new InvalidOperationException($"Type {type.Name} must contain an Id property for FeatherDatabase.");
            }

            var sql = $"CREATE TABLE IF NOT EXISTS `{tableName}` ({string.Join(", ", parts)}) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

            ExecuteNonQuery(sql);
            _logger.Log($"📋 Table '{tableName}' ensured.");

            EnsureTableStructure(tableName, props);
        }

        private void EnsureTableStructure(string tableName, PropertyInfo[] props)
        {
            try
            {
                var existingColumns = GetTableColumns(tableName);

                foreach (var prop in props)
                {
                    if (prop.Name.Equals("Id", StringComparison.OrdinalIgnoreCase)) continue;

                    if (!existingColumns.Contains(prop.Name))
                    {
                        var sqlType = GetSqlType(prop.PropertyType);
                        var alterSql = $"ALTER TABLE `{tableName}` ADD COLUMN `{prop.Name}` {sqlType} NULL";
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

        private HashSet<string> GetTableColumns(string tableName)
        {
            var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            const string sql = """
SELECT COLUMN_NAME
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = @TableName;
""";

            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var cmd = new MySqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@TableName", tableName);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                columns.Add(reader.GetString(0));
            }

            return columns;
        }

        public List<T> GetPaged<T>(int pageNumber, int pageSize, string orderByColumn = "Id") where T : new()
        {
            if (pageNumber <= 0) throw new ArgumentOutOfRangeException(nameof(pageNumber));
            if (pageSize <= 0) throw new ArgumentOutOfRangeException(nameof(pageSize));

            var type = typeof(T);
            var tableName = GetTableName(type);
            var props = GetCachedProperties(type);
            var list = new List<T>();

            int offset = (pageNumber - 1) * pageSize;

            if (!props.Any(p => p.Name.Equals(orderByColumn, StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException($"Column '{orderByColumn}' does not exist for paging.");
            }

            var sql = $"SELECT * FROM `{tableName}` ORDER BY `{orderByColumn}` LIMIT @Limit OFFSET @Offset";

            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var cmd = new MySqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Limit", pageSize);
            cmd.Parameters.AddWithValue("@Offset", offset);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(MapReaderToObject<T>(reader, props));
            }

            return list;
        }

        public int DeleteWhere<T>(string whereClause, params MySqlParameter[] parameters) where T : new()
        {
            var tableName = GetTableName(typeof(T));

            if (string.IsNullOrWhiteSpace(whereClause) || !whereClause.TrimStart().StartsWith("WHERE", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("You must provide a WHERE clause (e.g., \"WHERE Id = 1\") to prevent accidental full table deletion.");
            }

            if (whereClause.Contains(";"))
            {
                throw new ArgumentException("Invalid SQL in DeleteWhere");
            }

            var sql = $"DELETE FROM `{tableName}` {whereClause}";

            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var cmd = new MySqlCommand(sql, connection);
            if (parameters != null && parameters.Length > 0) cmd.Parameters.AddRange(parameters);

            return cmd.ExecuteNonQuery();
        }

        public object? ExecuteScalar(string sql, params MySqlParameter[] parameters)
        {
            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var cmd = new MySqlCommand(sql, connection);
            if (parameters != null && parameters.Length > 0) cmd.Parameters.AddRange(parameters);

            return cmd.ExecuteScalar();
        }

        public bool Exists<T>(string whereClause = "", params MySqlParameter[] parameters) where T : new()
        {
            var tableName = GetTableName(typeof(T));
            var sql = $"SELECT 1 FROM `{tableName}`";

            if (!string.IsNullOrWhiteSpace(whereClause))
            {
                if (whereClause.Contains(";")) throw new ArgumentException("Invalid SQL in Exists");
                sql += " " + whereClause;
            }

            sql += " LIMIT 1";

            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var cmd = new MySqlCommand(sql, connection);
            if (parameters != null && parameters.Length > 0) cmd.Parameters.AddRange(parameters);

            return cmd.ExecuteScalar() != null;
        }

        public long Count<T>() where T : new()
        {
            var tableName = GetTableName(typeof(T));

            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var cmd = new MySqlCommand($"SELECT COUNT(*) FROM `{tableName}`", connection);
            return Convert.ToInt64(cmd.ExecuteScalar());
        }

        public List<T> ExecuteQuery<T>(string sql, params MySqlParameter[] parameters) where T : new()
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var list = new List<T>();

            var upper = sql.ToUpperInvariant();
            if (upper.Contains("DROP ") || upper.Contains("DELETE ") || upper.Contains("TRUNCATE ") || upper.Contains("ALTER "))
            {
                throw new SecurityException("ExecuteQuery is for SELECT only. Use ExecuteNonQuery for modifications.");
            }

            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var cmd = new MySqlCommand(sql, connection);
            if (parameters != null && parameters.Length > 0) cmd.Parameters.AddRange(parameters);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(MapReaderToObject<T>(reader, props));
            }

            return list;
        }

        public void CreateIndex<T>(string columnName, bool unique = false)
        {
            var tableName = GetTableName(typeof(T));
            var indexName = $"IDX_{tableName}_{columnName}";
            var uniqueSql = unique ? "UNIQUE" : "";

            var sql = $"CREATE {uniqueSql} INDEX `{indexName}` ON `{tableName}` (`{columnName}`);";
            ExecuteNonQuery(sql);
        }

        public void SaveData<T>(T obj) where T : new()
        {
            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            SaveInternal(connection, null, obj);
        }

        public void SaveMultiData<T>(List<T> items) where T : new()
        {
            if (items == null || items.Count == 0) return;

            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var transaction = connection.BeginTransaction(IsolationLevel.ReadCommitted);

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

        private void SaveInternal<T>(MySqlConnection connection, MySqlTransaction? transaction, T obj) where T : new()
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var tableName = GetTableName(type);

            var idProp = props.FirstOrDefault(p => p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase));
            if (idProp == null) throw new InvalidOperationException($"Type {type.Name} must have an Id property.");

            var idValueObj = idProp.GetValue(obj);
            long idValue = 0;

            if (idValueObj != null)
            {
                idValue = Convert.ToInt64(idValueObj);
            }

            if (idValue > 0)
            {
                var setClause = string.Join(", ", props
                    .Where(p => !p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase))
                    .Select(p => $"`{p.Name}` = @{p.Name}"));

                var sql = $"UPDATE `{tableName}` SET {setClause} WHERE `{idProp.Name}` = @Id";

                using var cmd = new MySqlCommand(sql, connection);
                cmd.Transaction = transaction;

                cmd.Parameters.AddWithValue("@Id", idValue);

                foreach (var prop in props.Where(p => !p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase)))
                {
                    cmd.Parameters.AddWithValue($"@{prop.Name}", ToDbValue(prop.GetValue(obj)));
                }

                cmd.ExecuteNonQuery();
            }
            else
            {
                var insertProps = props.Where(p => !p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase)).ToArray();

                var columns = insertProps.Select(p => $"`{p.Name}`");
                var values = insertProps.Select(p => $"@{p.Name}");

                var sql = $"INSERT INTO `{tableName}` ({string.Join(", ", columns)}) VALUES ({string.Join(", ", values)})";

                using var cmd = new MySqlCommand(sql, connection);
                cmd.Transaction = transaction;

                foreach (var prop in insertProps)
                {
                    cmd.Parameters.AddWithValue($"@{prop.Name}", ToDbValue(prop.GetValue(obj)));
                }

                cmd.ExecuteNonQuery();

                long lastId = cmd.LastInsertedId;

                if (idProp.PropertyType == typeof(int))
                {
                    idProp.SetValue(obj, (int)lastId);
                }
                else if (idProp.PropertyType == typeof(long))
                {
                    idProp.SetValue(obj, lastId);
                }
            }
        }

        public T? GetData<T>(long id) where T : new()
        {
            var type = typeof(T);
            var tableName = GetTableName(type);
            var props = GetCachedProperties(type);
            var idProp = props.FirstOrDefault(p => p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase));

            if (idProp == null) throw new Exception($"Type {type.Name} does not have an Id property.");

            var sql = $"SELECT * FROM `{tableName}` WHERE `{idProp.Name}` = @Id LIMIT 1";

            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var cmd = new MySqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Id", id);

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return MapReaderToObject<T>(reader, props);
            }

            return default;
        }

        public List<T> GetAll<T>() where T : new()
        {
            var type = typeof(T);
            var tableName = GetTableName(type);
            var props = GetCachedProperties(type);
            var list = new List<T>();

            var sql = $"SELECT * FROM `{tableName}`";

            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var cmd = new MySqlCommand(sql, connection);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(MapReaderToObject<T>(reader, props));
            }

            return list;
        }

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

            var sql = $"SELECT * FROM `{tableName}` WHERE `{columnProp.Name}` = @Value LIMIT 1";

            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var cmd = new MySqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Value", ToDbValue(value));

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return MapReaderToObject<T>(reader, props);
            }

            return default;
        }

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

            var sql = $"SELECT * FROM `{tableName}` WHERE `{columnProp.Name}` = @Value";

            var list = new List<T>();

            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var cmd = new MySqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Value", ToDbValue(value));

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(MapReaderToObject<T>(reader, props));
            }

            return list;
        }

        public void Delete<T>(long id) where T : new()
        {
            var type = typeof(T);
            var tableName = GetTableName(type);
            var props = GetCachedProperties(type);
            var idProp = props.FirstOrDefault(p => p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase));

            if (idProp == null) return;

            var sql = $"DELETE FROM `{tableName}` WHERE `{idProp.Name}` = @Id";
            ExecuteNonQuery(sql, new MySqlParameter("@Id", id));
        }

        public void ExecuteNonQuery(string sql, params MySqlParameter[] parameters)
        {
            using var connection = new MySqlConnection(_connectionString);
            connection.Open();

            using var cmd = new MySqlCommand(sql, connection);
            if (parameters != null && parameters.Length > 0)
            {
                cmd.Parameters.AddRange(parameters);
            }

            cmd.ExecuteNonQuery();
        }

        private T MapReaderToObject<T>(MySqlDataReader reader, PropertyInfo[] props) where T : new()
        {
            var obj = new T();

            var columnLookup = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
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
                if (underlyingType != null) targetType = underlyingType;

                if (targetType == typeof(Guid))
                {
                    if (val is string s)
                    {
                        prop.SetValue(obj, Guid.Parse(s));
                    }
                    else if (val is byte[] b && b.Length == 16)
                    {
                        prop.SetValue(obj, new Guid(b));
                    }
                    continue;
                }

                if (targetType == typeof(bool))
                {
                    prop.SetValue(obj, Convert.ToInt32(val) != 0);
                    continue;
                }

                prop.SetValue(obj, Convert.ChangeType(val, targetType));
            }

            return obj;
        }

        private static object ToDbValue(object? value)
        {
            if (value == null) return DBNull.Value;

            if (value is DateTime dt)
            {
                return dt.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(dt, DateTimeKind.Utc) : dt.ToUniversalTime();
            }

            if (value is Guid g)
            {
                return g.ToString("D");
            }

            return value;
        }

        private PropertyInfo[] GetCachedProperties(Type type)
        {
            return _propertyCache.GetOrAdd(type, t => t.GetProperties(BindingFlags.Public | BindingFlags.Instance));
        }

        private static string GetTableName(Type type)
        {
            return type.Name;
        }

        private static string GetSqlType(Type type)
        {
            Type? underlying = Nullable.GetUnderlyingType(type);
            if (underlying != null) type = underlying;

            if (type == typeof(int)) return "INT";
            if (type == typeof(long)) return "BIGINT";
            if (type == typeof(bool)) return "TINYINT(1)";
            if (type == typeof(float) || type == typeof(double)) return "DOUBLE";
            if (type == typeof(decimal)) return "DECIMAL(18,6)";
            if (type == typeof(DateTime)) return "DATETIME(6)";
            if (type == typeof(Guid)) return "CHAR(36)";
            if (type == typeof(string)) return "LONGTEXT";
            if (type == typeof(byte[])) return "LONGBLOB";
            if (type == typeof(DateTimeOffset)) return "DATETIMEOFFSET(6)";
            if (type == typeof(TimeSpan)) return "TIME(6)";
            if (type == typeof(short)) return "SMALLINT";
            if (type == typeof(byte)) return "TINYINT UNSIGNED";

            return "LONGTEXT";
        }
    }
}
