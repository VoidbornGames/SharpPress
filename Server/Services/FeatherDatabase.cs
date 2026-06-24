using MySqlConnector;
using Newtonsoft.Json;
using SharpPress.Models;
using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Linq.Expressions;
using System.Reflection;
using System.Security;
using System.Collections;

namespace SharpPress.Services
{
    public sealed class FeatherDatabase : IAsyncDisposable
    {
        private readonly FeatherDatabaseOptions _options;
        private readonly string _connectionString;
        private readonly ILogger<FeatherDatabase> _logger;
        private readonly CancellationToken _globalCancellationToken;
        private static readonly ConcurrentDictionary<Type, PropertyInfo[]> _propertyCache = new();

        private const int MaxRetryAttempts = 3;
        private static readonly TimeSpan[] RetryDelays = {
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromMilliseconds(250),
            TimeSpan.FromMilliseconds(500)
        };

        public FeatherDatabase(ILogger<FeatherDatabase> logger, MySQL_Config mySQL_Config, CancellationToken globalCancellationToken = default)
        {
            _logger = logger;
            _globalCancellationToken = globalCancellationToken;
            _options = new FeatherDatabaseOptions
            {
                AutoAddColumns = true,
                AutoCreateTable = true,
                AutoModifyColumns = true,
                AutoDeleteOrphanedColumns = false
            };

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
                    ConnectionTimeout = 10,
                    DefaultCommandTimeout = 30,
                    AllowUserVariables = false
                };

                _connectionString = builder.ConnectionString;

                using var connection = new MySqlConnection(_connectionString);
                connection.Open();

                _logger.LogInformation("FeatherDatabase connected to MySQL {Host}:{Port}/{Database}",
                    mySQL_Config.host, mySQL_Config.port, mySQL_Config.database_name);
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "Failed to initialise FeatherDatabase");
                throw;
            }
        }

        public IQueryable<T> Query<T>() where T : new()
        {
            return new FeatherQueryable<T>(this);
        }

        public async Task<List<T>> GetPagedByLinq<T>(
            int pageNumber,
            int pageSize,
            Expression<Func<T, bool>> predicate,
            Expression<Func<T, object>> orderBy,
            bool descending = true) where T : new()
        {
            if (pageNumber <= 0) throw new ArgumentOutOfRangeException(nameof(pageNumber));
            if (pageSize <= 0) throw new ArgumentOutOfRangeException(nameof(pageSize));

            var (whereClause, whereParams) = ExpressionToSql(predicate);
            var orderByProperty = GetPropertyName(orderBy);
            var tableName = GetTableName(typeof(T));
            var sql = $@"
                SELECT * FROM `{tableName}`
                WHERE {whereClause}
                ORDER BY `{orderByProperty}` {(descending ? "DESC" : "ASC")}
                LIMIT @Limit OFFSET @Offset";

            var parameters = new List<MySqlParameter>(whereParams)
            {
                new("@Limit", pageSize),
                new("@Offset", (pageNumber - 1) * pageSize)
            };

            return await ExecuteQuery<T>(sql, parameters.ToArray()).ConfigureAwait(false);
        }

        public IQueryable<T> WhereLinq<T>(Expression<Func<T, bool>> predicate) where T : new()
        {
            return new FeatherQueryable<T>(this).Where(predicate);
        }

        public async Task CreateTable<T>() where T : new()
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
                    parts.Add($"`{prop.Name}` {GetSqlType(prop)} NULL");
                }
            }

            if (!hasId)
                throw new InvalidOperationException($"Type {type.Name} must have an Id property for FeatherDatabase.");

            var sql = $"CREATE TABLE IF NOT EXISTS `{tableName}` ({string.Join(", ", parts)}) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

            await ExecuteNonQuery(sql).ConfigureAwait(false);
            _logger.LogInformation("Table '{TableName}' ensured", tableName);

            if (_options.AutoAddColumns || _options.AutoModifyColumns || _options.AutoDeleteOrphanedColumns)
            {
                await EnsureTableStructure(tableName, props).ConfigureAwait(false);
            }
        }

        public async Task SaveData<T>(T obj) where T : new()
        {
            await using var connection = new MySqlConnection(_connectionString);
            await connection.OpenAsync(_globalCancellationToken).ConfigureAwait(false);
            await SaveInternal(connection, null, obj).ConfigureAwait(false);
        }

        public async Task SaveMultiData<T>(List<T> items) where T : new()
        {
            if (items == null || items.Count == 0) return;

            await ExecuteInTransactionAsync(async (connection, transaction) =>
            {
                foreach (var item in items)
                    await SaveInternal(connection, transaction, item).ConfigureAwait(false);
            }).ConfigureAwait(false);
        }

        public async Task<UpdateDataResult> UpdateData<T>(T obj, params Expression<Func<T, object>>[] fieldsToUpdate) where T : new()
        {
            await using var connection = new MySqlConnection(_connectionString);
            await connection.OpenAsync(_globalCancellationToken).ConfigureAwait(false);
            return await UpdateDataInternal(connection, null, obj, fieldsToUpdate).ConfigureAwait(false);
        }

        public async Task<List<UpdateDataResult>> UpdateMultiData<T>(List<T> items, params Expression<Func<T, object>>[] fieldsToUpdate) where T : new()
        {
            if (items == null || items.Count == 0)
                return new List<UpdateDataResult>();

            var results = new List<UpdateDataResult>();

            await ExecuteInTransactionAsync(async (connection, transaction) =>
            {
                foreach (var item in items)
                {
                    var result = await UpdateDataInternal(connection, transaction, item, fieldsToUpdate)
                        .ConfigureAwait(false);
                    results.Add(result);
                }
            }).ConfigureAwait(false);

            return results;
        }

        public async Task<T?> GetData<T>(long id) where T : new()
        {
            var type = typeof(T);
            var tableName = GetTableName(type);
            var props = GetCachedProperties(type);
            var idProp = props.FirstOrDefault(p => p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase))
                         ?? throw new Exception($"Type {type.Name} does not have an Id property.");

            var sql = $"SELECT * FROM `{tableName}` WHERE `{idProp.Name}` = @Id LIMIT 1";

            await using var connection = new MySqlConnection(_connectionString);
            await connection.OpenAsync(_globalCancellationToken).ConfigureAwait(false);
            await using var cmd = new MySqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Id", id);

            await using var reader = await cmd.ExecuteReaderAsync(_globalCancellationToken).ConfigureAwait(false);
            if (await reader.ReadAsync(_globalCancellationToken).ConfigureAwait(false))
                return await MapReaderToObject<T>(reader, props).ConfigureAwait(false);

            return default;
        }

        public async Task<List<T>> GetAll<T>() where T : new()
        {
            var type = typeof(T);
            var tableName = GetTableName(type);
            var sql = $"SELECT * FROM `{tableName}`";

            return await ExecuteQuery<T>(sql).ConfigureAwait(false);
        }

        public async Task Delete<T>(long id) where T : new()
        {
            var type = typeof(T);
            var tableName = GetTableName(type);
            var idProp = GetCachedProperties(type).FirstOrDefault(p => p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase));
            if (idProp == null) return;

            var sql = $"DELETE FROM `{tableName}` WHERE `{idProp.Name}` = @Id";
            await ExecuteNonQuery(sql, new MySqlParameter("@Id", id)).ConfigureAwait(false);
        }

        [Obsolete("Use DeleteByLinq instead for safe parameterised deletion.")]
        internal async Task<int> DeleteWhere<T>(string whereClause, params MySqlParameter[] parameters) where T : new()
        {
            var tableName = GetTableName(typeof(T));

            if (string.IsNullOrWhiteSpace(whereClause) || !whereClause.TrimStart().StartsWith("WHERE", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("You must provide a WHERE clause (e.g., \"WHERE Id = 1\") to prevent accidental full table deletion.");

            if (whereClause.Contains(";"))
                throw new ArgumentException("Invalid SQL in DeleteWhere");

            var sql = $"DELETE FROM `{tableName}` {whereClause}";
            return await ExecuteNonQuery(sql, parameters).ConfigureAwait(false);
        }

        public async Task<int> DeleteByLinq<T>(Expression<Func<T, bool>> predicate) where T : new()
        {
            var (whereClause, parameters) = ExpressionToSql(predicate);
            var sql = $"DELETE FROM `{GetTableName(typeof(T))}` WHERE {whereClause}";
            return await ExecuteNonQuery(sql, parameters.ToArray()).ConfigureAwait(false);
        }

        public string GetConnectionString() => _connectionString;

        public async Task<int> ExecuteNonQueryWithCount(string sql, params MySqlParameter[] parameters)
        {
            using var connection = new MySqlConnection(_connectionString);
            await connection.OpenAsync();
            using var cmd = new MySqlCommand(sql, connection);
            if (parameters != null && parameters.Length > 0)
                cmd.Parameters.AddRange(parameters);
            return await cmd.ExecuteNonQueryAsync();
        }

        public async Task<List<T>> ExecuteQuery<T>(string sql, params MySqlParameter[] parameters) where T : new()
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var list = new List<T>();

            var upper = sql.ToUpperInvariant();
            if (upper.Contains("DROP ") || upper.Contains("DELETE ") || upper.Contains("TRUNCATE ") || upper.Contains("ALTER "))
                throw new SecurityException("ExecuteQuery is for SELECT only. Use ExecuteNonQuery for modifications.");

            await using var connection = new MySqlConnection(_connectionString);
            await connection.OpenAsync(_globalCancellationToken).ConfigureAwait(false);
            await using var cmd = new MySqlCommand(sql, connection);
            if (parameters != null && parameters.Length > 0)
                cmd.Parameters.AddRange(parameters);

            await using var reader = await cmd.ExecuteReaderAsync(_globalCancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(_globalCancellationToken).ConfigureAwait(false))
            {
                list.Add(await MapReaderToObject<T>(reader, props).ConfigureAwait(false));
            }

            return list;
        }

        public async Task<int> ExecuteNonQuery(string sql, params MySqlParameter[] parameters)
        {
            await using var connection = new MySqlConnection(_connectionString);
            await connection.OpenAsync(_globalCancellationToken).ConfigureAwait(false);
            await using var cmd = new MySqlCommand(sql, connection);
            if (parameters != null && parameters.Length > 0)
                cmd.Parameters.AddRange(parameters);
            return await cmd.ExecuteNonQueryAsync(_globalCancellationToken).ConfigureAwait(false);
        }

        public async Task<object?> ExecuteScalar(string sql, params MySqlParameter[] parameters)
        {
            await using var connection = new MySqlConnection(_connectionString);
            await connection.OpenAsync(_globalCancellationToken).ConfigureAwait(false);
            await using var cmd = new MySqlCommand(sql, connection);
            if (parameters != null && parameters.Length > 0)
                cmd.Parameters.AddRange(parameters);
            return await cmd.ExecuteScalarAsync(_globalCancellationToken).ConfigureAwait(false);
        }

        public async Task<bool> Exists<T>(string whereClause = "", params MySqlParameter[] parameters) where T : new()
        {
            var tableName = GetTableName(typeof(T));
            var sql = $"SELECT 1 FROM `{tableName}`";

            if (!string.IsNullOrWhiteSpace(whereClause))
            {
                if (whereClause.Contains(";")) throw new ArgumentException("Invalid SQL in Exists");
                sql += " " + whereClause;
            }

            sql += " LIMIT 1";

            await using var connection = new MySqlConnection(_connectionString);
            await connection.OpenAsync(_globalCancellationToken).ConfigureAwait(false);
            await using var cmd = new MySqlCommand(sql, connection);
            if (parameters != null && parameters.Length > 0) cmd.Parameters.AddRange(parameters);
            return await cmd.ExecuteScalarAsync(_globalCancellationToken).ConfigureAwait(false) != null;
        }

        public async Task<long> Count<T>() where T : new()
        {
            var tableName = GetTableName(typeof(T));
            var sql = $"SELECT COUNT(*) FROM `{tableName}`";
            var result = await ExecuteScalar(sql).ConfigureAwait(false);
            return Convert.ToInt64(result);
        }

        public async Task<List<T>> GetPaged<T>(int pageNumber, int pageSize, string orderByColumn = "Id") where T : new()
        {
            if (pageNumber <= 0) throw new ArgumentOutOfRangeException(nameof(pageNumber));
            if (pageSize <= 0) throw new ArgumentOutOfRangeException(nameof(pageSize));

            var type = typeof(T);
            var tableName = GetTableName(type);
            var props = GetCachedProperties(type);
            var list = new List<T>();

            int offset = (pageNumber - 1) * pageSize;

            if (!props.Any(p => p.Name.Equals(orderByColumn, StringComparison.OrdinalIgnoreCase)))
                throw new ArgumentException($"Column '{orderByColumn}' does not exist for paging.");

            var sql = $"SELECT * FROM `{tableName}` ORDER BY `{orderByColumn}` LIMIT @Limit OFFSET @Offset";

            await using var connection = new MySqlConnection(_connectionString);
            await connection.OpenAsync(_globalCancellationToken).ConfigureAwait(false);
            await using var cmd = new MySqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Limit", pageSize);
            cmd.Parameters.AddWithValue("@Offset", offset);

            await using var reader = await cmd.ExecuteReaderAsync(_globalCancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(_globalCancellationToken).ConfigureAwait(false))
            {
                list.Add(await MapReaderToObject<T>(reader, props).ConfigureAwait(false));
            }

            return list;
        }

        public async Task<T?> GetByColumn<T>(string columnName, object value) where T : new()
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var tableName = GetTableName(type);

            var columnProp = props.FirstOrDefault(p => p.Name.Equals(columnName, StringComparison.OrdinalIgnoreCase));
            if (columnProp == null)
                throw new ArgumentException($"Column '{columnName}' does not exist in table '{tableName}'.");

            var sql = $"SELECT * FROM `{tableName}` WHERE `{columnProp.Name}` = @Value LIMIT 1";

            await using var connection = new MySqlConnection(_connectionString);
            await connection.OpenAsync(_globalCancellationToken).ConfigureAwait(false);
            await using var cmd = new MySqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Value", ToDbValue(value));

            await using var reader = await cmd.ExecuteReaderAsync(_globalCancellationToken).ConfigureAwait(false);
            if (await reader.ReadAsync(_globalCancellationToken).ConfigureAwait(false))
                return await MapReaderToObject<T>(reader, props).ConfigureAwait(false);

            return default;
        }

        public async Task<List<T>> GetListByColumn<T>(string columnName, object value) where T : new()
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var tableName = GetTableName(type);

            var columnProp = props.FirstOrDefault(p => p.Name.Equals(columnName, StringComparison.OrdinalIgnoreCase));
            if (columnProp == null)
                throw new ArgumentException($"Column '{columnName}' does not exist in table '{tableName}'.");

            var sql = $"SELECT * FROM `{tableName}` WHERE `{columnProp.Name}` = @Value";

            var list = new List<T>();
            await using var connection = new MySqlConnection(_connectionString);
            await connection.OpenAsync(_globalCancellationToken).ConfigureAwait(false);
            await using var cmd = new MySqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@Value", ToDbValue(value));

            await using var reader = await cmd.ExecuteReaderAsync(_globalCancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(_globalCancellationToken).ConfigureAwait(false))
            {
                list.Add(await MapReaderToObject<T>(reader, props).ConfigureAwait(false));
            }

            return list;
        }

        public async Task CreateIndex<T>(string columnName, bool unique = false)
        {
            var tableName = GetTableName(typeof(T));
            var indexName = $"IDX_{tableName}_{columnName}";
            var uniqueSql = unique ? "UNIQUE" : "";
            var sql = $"CREATE {uniqueSql} INDEX `{indexName}` ON `{tableName}` (`{columnName}`);";

            try
            {
                await ExecuteNonQuery(sql).ConfigureAwait(false);
                _logger.LogInformation("Index '{IndexName}' created on table '{TableName}'", indexName, tableName);
            }
            catch (MySqlException ex) when (ex.Number == 1061)
            {
                _logger.LogDebug("Index '{IndexName}' already exists on table '{TableName}'", indexName, tableName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating index {IndexName}", indexName);
                throw;
            }
        }

        public async Task<long> CountByLinq<T>(Expression<Func<T, bool>> predicate) where T : new()
        {
            var (whereClause, parameters) = ExpressionToSql(predicate);
            var tableName = GetTableName(typeof(T));
            var sql = $"SELECT COUNT(*) FROM `{tableName}` WHERE {whereClause}";
            var result = await ExecuteScalar(sql, parameters.ToArray()).ConfigureAwait(false);
            return Convert.ToInt64(result);
        }

        public async Task<T?> GetByLinq<T>(Expression<Func<T, bool>> predicate) where T : new()
        {
            var (whereClause, parameters) = ExpressionToSql(predicate);
            var sql = $"SELECT * FROM `{GetTableName(typeof(T))}` WHERE {whereClause} LIMIT 1";
            var list = await ExecuteQuery<T>(sql, parameters.ToArray()).ConfigureAwait(false);
            return list.FirstOrDefault();
        }

        public async Task<List<T>> GetListByLinq<T>(Expression<Func<T, bool>> predicate) where T : new()
        {
            var (whereClause, parameters) = ExpressionToSql(predicate);
            var sql = $"SELECT * FROM `{GetTableName(typeof(T))}` WHERE {whereClause}";
            return await ExecuteQuery<T>(sql, parameters.ToArray()).ConfigureAwait(false);
        }

        private async Task EnsureTableStructure(string tableName, PropertyInfo[] props)
        {
            try
            {
                var existingColumns = await GetTableColumnsWithTypes(tableName).ConfigureAwait(false);
                var modelColumnNames = props.Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

                foreach (var prop in props)
                {
                    if (prop.Name.Equals("Id", StringComparison.OrdinalIgnoreCase)) continue;

                    var desiredType = GetSqlType(prop);
                    if (!existingColumns.TryGetValue(prop.Name, out var currentType))
                    {
                        if (_options.AutoAddColumns)
                        {
                            var alterSql = $"ALTER TABLE `{tableName}` ADD COLUMN `{prop.Name}` {desiredType} NULL";
                            _logger.LogInformation("Adding column '{Column}' to table '{Table}'", prop.Name, tableName);
                            await ExecuteNonQuery(alterSql).ConfigureAwait(false);
                        }
                        else
                        {
                            _logger.LogWarning("Column '{Column}' missing in table '{Table}' but AutoAddColumns is disabled", prop.Name, tableName);
                        }
                    }
                    else if (!IsTypeCompatible(currentType, desiredType))
                    {
                        if (_options.AutoModifyColumns)
                        {
                            var alterSql = $"ALTER TABLE `{tableName}` MODIFY COLUMN `{prop.Name}` {desiredType} NULL";
                            _logger.LogInformation("Changing column '{Column}' from {Current} to {Desired}", prop.Name, currentType, desiredType);
                            await ExecuteNonQuery(alterSql).ConfigureAwait(false);
                        }
                        else
                        {
                            _logger.LogWarning("Column '{Column}' type mismatch (DB: {Current}, Model: {Desired}) but AutoModifyColumns is disabled", prop.Name, currentType, desiredType);
                        }
                    }
                }

                if (_options.AutoDeleteOrphanedColumns)
                {
                    foreach (var dbColumn in existingColumns.Keys)
                    {
                        if (dbColumn.Equals("Id", StringComparison.OrdinalIgnoreCase)) continue;
                        if (!modelColumnNames.Contains(dbColumn))
                        {
                            var dropSql = $"ALTER TABLE `{tableName}` DROP COLUMN `{dbColumn}`";
                            _logger.LogWarning("Deleting orphaned column '{Column}' from table '{Table}'", dbColumn, tableName);
                            await ExecuteNonQuery(dropSql).ConfigureAwait(false);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Migration failed for {TableName}", tableName);
                throw new MigrationException($"Failed to migrate table {tableName}", ex);
            }
        }

        private async Task<Dictionary<string, string>> GetTableColumnsWithTypes(string tableName)
        {
            const string sql = @"
                SELECT COLUMN_NAME, COLUMN_TYPE
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = @TableName;";

            await using var connection = new MySqlConnection(_connectionString);
            await connection.OpenAsync(_globalCancellationToken).ConfigureAwait(false);
            await using var cmd = new MySqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@TableName", tableName);
            await using var reader = await cmd.ExecuteReaderAsync(_globalCancellationToken).ConfigureAwait(false);

            var columns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            while (await reader.ReadAsync(_globalCancellationToken).ConfigureAwait(false))
                columns[reader.GetString(0)] = reader.GetString(1);
            return columns;
        }

        private async Task SaveInternal<T>(MySqlConnection connection, MySqlTransaction? transaction, T obj)
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var tableName = GetTableName(type);

            var idProp = props.FirstOrDefault(p => p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase))
                         ?? throw new InvalidOperationException($"Type {type.Name} must have an Id property.");

            var idValueObj = idProp.GetValue(obj);
            long idValue = idValueObj != null ? Convert.ToInt64(idValueObj) : 0;

            if (idValue > 0)
            {
                var setClause = string.Join(", ", props
                    .Where(p => !p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase))
                    .Select(p => $"`{p.Name}` = @{p.Name}"));

                var sql = $"UPDATE `{tableName}` SET {setClause} WHERE `{idProp.Name}` = @Id";

                await using var cmd = new MySqlCommand(sql, connection, transaction);
                cmd.Parameters.AddWithValue("@Id", idValue);
                foreach (var prop in props.Where(p => !p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase)))
                    cmd.Parameters.AddWithValue($"@{prop.Name}", ToDbValue(prop.GetValue(obj)));

                await cmd.ExecuteNonQueryAsync(_globalCancellationToken).ConfigureAwait(false);
            }
            else
            {
                var insertProps = props.Where(p => !p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase)).ToArray();
                var columns = string.Join(", ", insertProps.Select(p => $"`{p.Name}`"));
                var values = string.Join(", ", insertProps.Select(p => $"@{p.Name}"));

                var sql = $"INSERT INTO `{tableName}` ({columns}) VALUES ({values}); SELECT LAST_INSERT_ID();";

                await using var cmd = new MySqlCommand(sql, connection, transaction);
                foreach (var prop in insertProps)
                    cmd.Parameters.AddWithValue($"@{prop.Name}", ToDbValue(prop.GetValue(obj)));

                var lastId = Convert.ToInt64(await cmd.ExecuteScalarAsync(_globalCancellationToken).ConfigureAwait(false));
                if (idProp.PropertyType == typeof(int))
                    idProp.SetValue(obj, (int)lastId);
                else if (idProp.PropertyType == typeof(long))
                    idProp.SetValue(obj, lastId);
            }
        }

        private async Task<UpdateDataResult> UpdateDataInternal<T>(MySqlConnection connection, MySqlTransaction? transaction, T obj, Expression<Func<T, object>>[] fieldsToUpdate) where T : new()
        {
            var type = typeof(T);
            var props = GetCachedProperties(type);
            var tableName = GetTableName(type);

            var idProp = props.FirstOrDefault(p => p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase))
                         ?? throw new InvalidOperationException($"Type {type.Name} must have an Id property.");

            var idValueObj = idProp.GetValue(obj);
            long idValue = idValueObj != null ? Convert.ToInt64(idValueObj) : 0;

            if (idValue <= 0)
                throw new InvalidOperationException(
                    "Cannot update a record with Id <= 0. Use SaveData for new records.");

            var versionProp = props.FirstOrDefault(p =>
                p.Name.Equals("Version", StringComparison.OrdinalIgnoreCase) &&
                (p.PropertyType == typeof(int) || p.PropertyType == typeof(long) ||
                 p.PropertyType == typeof(int?) || p.PropertyType == typeof(long?)));

            var updatedAtProp = props.FirstOrDefault(p =>
                p.Name.Equals("UpdatedAt", StringComparison.OrdinalIgnoreCase) &&
                (p.PropertyType == typeof(DateTime) || p.PropertyType == typeof(DateTime?)));

            var updateProps = new List<PropertyInfo>();

            if (fieldsToUpdate is { Length: > 0 })
            {
                foreach (var expr in fieldsToUpdate)
                {
                    var name = GetPropertyName(expr);
                    if (name.Equals("Id", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("Version", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var prop = props.FirstOrDefault(p =>
                                   p.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                               ?? throw new ArgumentException(
                                   $"Property '{name}' not found on type {type.Name}.");

                    if (!updateProps.Contains(prop))
                        updateProps.Add(prop);
                }
            }
            else
            {
                updateProps = props
                    .Where(p => !p.Name.Equals("Id", StringComparison.OrdinalIgnoreCase) &&
                                !p.Name.Equals("Version", StringComparison.OrdinalIgnoreCase))
                    .ToList();
            }

            if (updateProps.Count == 0)
                throw new ArgumentException("No valid fields to update.", nameof(fieldsToUpdate));

            var setClauses = new List<string>();
            var parameters = new List<MySqlParameter> { new("@Id", idValue) };

            foreach (var prop in updateProps)
            {
                setClauses.Add($"`{prop.Name}` = @upd_{prop.Name}");
                parameters.Add(new MySqlParameter($"@upd_{prop.Name}", ToDbValue(prop.GetValue(obj))));
            }

            if (updatedAtProp != null && !updateProps.Contains(updatedAtProp))
            {
                var now = DateTime.UtcNow;
                setClauses.Add($"`{updatedAtProp.Name}` = @upd__autoUpdatedAt");
                parameters.Add(new MySqlParameter("@upd__autoUpdatedAt", now));
                updatedAtProp.SetValue(obj, now);
            }

            if (versionProp != null)
            {
                setClauses.Add($"`{versionProp.Name}` = `{versionProp.Name}` + 1");
            }

            var whereClause = $"`{idProp.Name}` = @Id";
            if (versionProp != null)
            {
                var currentVersion = Convert.ToInt64(versionProp.GetValue(obj));
                whereClause += $" AND `{versionProp.Name}` = @CurrentVersion";
                parameters.Add(new MySqlParameter("@CurrentVersion", currentVersion));
            }

            var sql = $"UPDATE `{tableName}` SET {string.Join(", ", setClauses)} WHERE {whereClause}";

            await using var cmd = new MySqlCommand(sql, connection, transaction);
            if (parameters.Count > 0)
                cmd.Parameters.AddRange(parameters.ToArray());

            int rowsAffected = await cmd.ExecuteNonQueryAsync(_globalCancellationToken).ConfigureAwait(false);

            if (versionProp != null && rowsAffected > 0)
            {
                var currentVersion = Convert.ToInt64(versionProp.GetValue(obj));
                var nextVersion = currentVersion + 1;

                if (versionProp.PropertyType == typeof(int))
                    versionProp.SetValue(obj, (int)nextVersion);
                else if (versionProp.PropertyType == typeof(long))
                    versionProp.SetValue(obj, nextVersion);
                else if (versionProp.PropertyType == typeof(int?))
                    versionProp.SetValue(obj, (int?)nextVersion);
                else
                    versionProp.SetValue(obj, (long?)nextVersion);
            }

            bool concurrencyConflict = versionProp != null && rowsAffected == 0;

            return new UpdateDataResult
            {
                Success = rowsAffected > 0,
                RowsAffected = rowsAffected,
                ConcurrencyConflict = concurrencyConflict,
                Message = concurrencyConflict
                    ? "Optimistic concurrency conflict: the record was modified by another process."
                    : rowsAffected > 0 ? "Update successful." : "No rows matched the update criteria."
            };
        }

        private async Task ExecuteInTransactionAsync(Func<MySqlConnection, MySqlTransaction, Task> action)
        {
            for (int attempt = 0; attempt < MaxRetryAttempts; attempt++)
            {
                await using var connection = new MySqlConnection(_connectionString);
                await connection.OpenAsync(_globalCancellationToken).ConfigureAwait(false);
                await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, _globalCancellationToken).ConfigureAwait(false);

                try
                {
                    await action(connection, transaction).ConfigureAwait(false);
                    await transaction.CommitAsync(_globalCancellationToken).ConfigureAwait(false);
                    return;
                }
                catch (MySqlException ex) when (ex.Number == 1213 && attempt < MaxRetryAttempts - 1)
                {
                    _logger.LogWarning(ex, "Deadlock detected, retry attempt {Attempt}", attempt + 1);
                    await transaction.RollbackAsync(_globalCancellationToken).ConfigureAwait(false);
                    await Task.Delay(RetryDelays[attempt], _globalCancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    await transaction.RollbackAsync(_globalCancellationToken).ConfigureAwait(false);
                    throw;
                }
            }
        }

        private async Task<T> MapReaderToObject<T>(MySqlDataReader reader, PropertyInfo[] props) where T : new()
        {
            var obj = new T();
            var columnLookup = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < reader.FieldCount; i++)
                columnLookup[reader.GetName(i)] = i;

            foreach (var prop in props)
            {
                if (!prop.CanWrite || prop.SetMethod == null) continue;
                if (!columnLookup.TryGetValue(prop.Name, out int ordinal)) continue;

                var val = reader.GetValue(ordinal);
                if (val == DBNull.Value) continue;

                Type targetType = prop.PropertyType;
                Type? underlyingType = Nullable.GetUnderlyingType(targetType);
                if (underlyingType != null) targetType = underlyingType;

                try
                {
                    if (targetType.IsEnum)
                    {
                        object enumValue = val switch
                        {
                            int i => Enum.ToObject(targetType, i),
                            long l => Enum.ToObject(targetType, (int)l),
                            string s => int.TryParse(s, out int parsed)
                                ? Enum.ToObject(targetType, parsed)
                                : Enum.Parse(targetType, s, true),
                            _ => Convert.ChangeType(val, targetType)
                        };
                        prop.SetValue(obj, enumValue);
                    }
                    else if (targetType == typeof(Guid))
                    {
                        prop.SetValue(obj, val is string s ? Guid.Parse(s) : new Guid((byte[])val));
                    }
                    else if (targetType == typeof(bool))
                    {
                        prop.SetValue(obj, Convert.ToInt32(val) != 0);
                    }
                    else if (val is string json && !IsSimpleType(targetType))
                    {
                        var deserialized = JsonConvert.DeserializeObject(json, targetType);
                        prop.SetValue(obj, deserialized);
                    }
                    else
                    {
                        prop.SetValue(obj, Convert.ChangeType(val, targetType));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to map column '{Column}' to property {Property}", prop.Name, prop.Name);

                    if (underlyingType == null && targetType.IsValueType)
                        prop.SetValue(obj, Activator.CreateInstance(targetType));
                }
            }

            return obj;
        }

        private static PropertyInfo[] GetCachedProperties(Type type)
            => _propertyCache.GetOrAdd(type, t => t.GetProperties(BindingFlags.Public | BindingFlags.Instance));

        private static string GetTableName(Type type) => type.Name;

        private static string GetSqlType(PropertyInfo prop)
        {
            var type = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType;

            return type switch
            {
                _ when type == typeof(int) => "INT",
                _ when type == typeof(long) => "BIGINT",
                _ when type == typeof(bool) => "TINYINT(1)",
                _ when type == typeof(float) || type == typeof(double) => "DOUBLE",
                _ when type == typeof(decimal) => "DECIMAL(18,6)",
                _ when type == typeof(DateTime) => "DATETIME(6)",
                _ when type == typeof(Guid) => "CHAR(36)",
                _ when type == typeof(byte[]) => "LONGBLOB",
                _ when type == typeof(DateTimeOffset) => "DATETIMEOFFSET(6)",
                _ when type == typeof(TimeSpan) => "TIME(6)",
                _ when type == typeof(short) => "SMALLINT",
                _ when type == typeof(byte) => "TINYINT UNSIGNED",
                _ when type.IsEnum => "INT",
                _ when type == typeof(string) => GetStringColumnType(prop),
                _ => "LONGTEXT"
            };
        }

        private static string GetStringColumnType(PropertyInfo prop)
        {
            var stringLengthAttr = prop.GetCustomAttribute<StringLengthAttribute>();
            if (stringLengthAttr != null)
                return $"VARCHAR({stringLengthAttr.MaximumLength})";
            return "LONGTEXT";
        }

        internal static bool IsSimpleType(Type type)
        {
            return type.IsPrimitive
                || type == typeof(string)
                || type == typeof(decimal)
                || type == typeof(DateTime)
                || type == typeof(DateTimeOffset)
                || type == typeof(TimeSpan)
                || type == typeof(Guid)
                || type == typeof(byte[]);
        }

        private static object ToDbValue(object? value)
        {
            if (value == null) return DBNull.Value;

            var type = value.GetType();
            if (type.IsEnum)
                return Convert.ChangeType(value, Enum.GetUnderlyingType(type));

            if (value is Guid g)
                return g == Guid.Empty ? DBNull.Value : g.ToString("D");

            if (value is DateTime dt)
                return dt.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(dt, DateTimeKind.Utc) : dt.ToUniversalTime();

            if (value is Array or System.Collections.IEnumerable && type != typeof(string))
                return JsonConvert.SerializeObject(value);

            if (!IsSimpleType(type))
                return JsonConvert.SerializeObject(value);

            return value;
        }

        private static bool IsTypeCompatible(string currentType, string desiredType)
        {
            currentType = currentType.ToLowerInvariant().Trim();
            desiredType = desiredType.ToLowerInvariant().Trim();

            if (currentType.StartsWith("longtext") && desiredType.StartsWith("varchar"))
                return false;

            if (currentType.StartsWith("varchar") && desiredType.StartsWith("varchar"))
            {
                var currentLen = ExtractLength(currentType);
                var desiredLen = ExtractLength(desiredType);
                return currentLen >= desiredLen;
            }

            return currentType == desiredType;
        }

        private static int ExtractLength(string type)
        {
            var match = System.Text.RegularExpressions.Regex.Match(type, @"\((\d+)\)");
            return match.Success ? int.Parse(match.Groups[1].Value) : 0;
        }

        private static string GetPropertyName<T>(Expression<Func<T, object>> expression)
        {
            return expression.Body switch
            {
                MemberExpression m => m.Member.Name,
                UnaryExpression u when u.Operand is MemberExpression m => m.Member.Name,
                _ => throw new ArgumentException("Invalid order by expression")
            };
        }

        private (string whereClause, List<MySqlParameter> parameters) ExpressionToSql<T>(Expression<Func<T, bool>> predicate)
        {
            var visitor = new WhereClauseVisitor();
            var whereClause = visitor.Visit(predicate.Body);
            return (whereClause, visitor.Parameters);
        }

        private class WhereClauseVisitor : ExpressionVisitor
        {
            public List<MySqlParameter> Parameters { get; } = new();
            private int _counter;

            public string Visit(Expression expr) => expr switch
            {
                BinaryExpression b => VisitBinary(b),
                MemberExpression m => VisitMember(m),
                ConstantExpression c => VisitConstant(c),
                MethodCallExpression m => VisitMethodCall(m),
                UnaryExpression u => VisitUnary(u),
                _ => throw new NotSupportedException($"Expression type {expr.GetType()} not supported")
            };

            private string VisitUnary(UnaryExpression node)
            {
                if (node.NodeType == ExpressionType.Convert)
                    return Visit(node.Operand);
                if (node.NodeType == ExpressionType.Not)
                    return $"NOT ({Visit(node.Operand)})";
                throw new NotSupportedException($"Unary operator {node.NodeType} not supported");
            }

            private string VisitBinary(BinaryExpression node)
            {
                var left = Visit(node.Left);
                var right = Visit(node.Right);

                var op = node.NodeType switch
                {
                    ExpressionType.Equal => "=",
                    ExpressionType.NotEqual => "!=",
                    ExpressionType.GreaterThan => ">",
                    ExpressionType.GreaterThanOrEqual => ">=",
                    ExpressionType.LessThan => "<",
                    ExpressionType.LessThanOrEqual => "<=",
                    ExpressionType.AndAlso => "AND",
                    ExpressionType.OrElse => "OR",
                    _ => throw new NotSupportedException($"Operator {node.NodeType} not supported")
                };

                if (node.NodeType is ExpressionType.AndAlso or ExpressionType.OrElse)
                    return $"({left} {op} {right})";

                if (right.StartsWith("@"))
                    return $"{left} {op} {right}";

                var value = GetValueFromExpression(node.Right);
                return $"{left} {op} {AddParameter(value)}";
            }

            private string VisitMember(MemberExpression node)
            {
                if (node.Expression?.NodeType == ExpressionType.Parameter)
                    return $"`{node.Member.Name}`";

                var value = GetValueFromExpression(node);
                return AddParameter(value);
            }

            private string VisitConstant(ConstantExpression node)
            {
                return AddParameter(node.Value);
            }

            private string VisitMethodCall(MethodCallExpression node)
            {
                if (node.Method.DeclaringType == typeof(string))
                {
                    var column = Visit(node.Object!);
                    var argValue = GetValueFromExpression(node.Arguments[0])?.ToString() ?? "";

                    var pattern = node.Method.Name switch
                    {
                        "Contains" => $"%{argValue}%",
                        "StartsWith" => $"{argValue}%",
                        "EndsWith" => $"%{argValue}",
                        _ => throw new NotSupportedException($"String method {node.Method.Name} not supported")
                    };

                    return $"{column} LIKE {AddParameter(pattern)}";
                }

                if (node.Method.Name == "get_HasValue" && node.Object?.Type.IsGenericType == true &&
                    node.Object.Type.GetGenericTypeDefinition() == typeof(Nullable<>))
                {
                    return $"{Visit(node.Object)} IS NOT NULL";
                }

                if (node.Method.Name == "Contains")
                {
                    bool isEnumerableContains = node.Method.DeclaringType == typeof(Enumerable);

                    bool isGenericContains = node.Method.DeclaringType?.IsGenericType == true &&
                        (node.Method.DeclaringType.GetGenericTypeDefinition() == typeof(List<>) ||
                         node.Method.DeclaringType.GetGenericTypeDefinition() == typeof(HashSet<>));

                    if (isEnumerableContains || isGenericContains)
                    {
                        MemberExpression? memberExpr = null;
                        Expression collectionExpr = null!;

                        if (isEnumerableContains)
                        {
                            collectionExpr = node.Arguments[0];
                            memberExpr = node.Arguments[1] as MemberExpression;
                        }
                        else
                        {
                            collectionExpr = node.Object!;
                            memberExpr = node.Arguments[0] as MemberExpression;
                        }

                        if (memberExpr == null)
                            throw new NotSupportedException("Contains must compare against a database column (e.g., list.Contains(x.Id)).");

                        var column = Visit(memberExpr);

                        var collectionValue = GetValueFromExpression(collectionExpr) as System.Collections.IEnumerable;
                        if (collectionValue == null)
                            throw new NotSupportedException("Collection value could not be evaluated.");

                        var values = collectionValue.Cast<object>().ToList();

                        if (values.Count == 0) return "1 = 0";

                        var paramNames = new List<string>();
                        foreach (var val in values)
                        {
                            paramNames.Add(AddParameter(val));
                        }
                        return $"{column} IN ({string.Join(", ", paramNames)})";
                    }
                }

                throw new NotSupportedException($"Method {node.Method.Name} not supported");
            }

            private object? GetValueFromExpression(Expression expr)
            {
                if (expr is MemberExpression memberExpr)
                {
                    var objectMember = Expression.Convert(memberExpr, typeof(object));
                    var getterLambda = Expression.Lambda<Func<object>>(objectMember);
                    return getterLambda.Compile()();
                }

                var lambda = Expression.Lambda(expr);
                return lambda.Compile().DynamicInvoke();
            }

            private string AddParameter(object? value)
            {
                if (value != null && value.GetType().IsEnum)
                {
                    value = Convert.ChangeType(value, Enum.GetUnderlyingType(value.GetType()));
                }
                var paramName = $"@p{_counter++}";
                Parameters.Add(new MySqlParameter(paramName, value ?? DBNull.Value));
                return paramName;
            }
        }

        public class MigrationException : Exception
        {
            public MigrationException(string message, Exception inner) : base(message, inner) { }
        }

        public class UpdateDataResult
        {
            public bool Success { get; init; }
            public int RowsAffected { get; init; }
            public bool ConcurrencyConflict { get; init; }
            public string Message { get; init; } = "";

            public void EnsureSuccess()
            {
                if (!Success)
                    throw ConcurrencyConflict
                        ? new OptimisticConcurrencyException(Message)
                        : new InvalidOperationException(Message);
            }
        }

        public class OptimisticConcurrencyException : Exception
        {
            public OptimisticConcurrencyException(string message) : base(message) { }
            public OptimisticConcurrencyException(string message, Exception inner) : base(message, inner) { }
        }

        public async ValueTask DisposeAsync()
        {
            await Task.CompletedTask;
        }
    }

    public class FeatherDatabaseOptions
    {
        public bool AutoCreateTable { get; set; } = true;
        public bool AutoAddColumns { get; set; } = true;
        public bool AutoModifyColumns { get; set; } = false;
        public bool AutoDeleteOrphanedColumns { get; set; } = false;
    }

    public class FeatherQueryable<T> : IQueryable<T>, IAsyncEnumerable<T>, IOrderedQueryable<T>
    {
        internal readonly FeatherQueryProvider _provider;
        internal readonly Expression _expression;

        public FeatherQueryable(FeatherDatabase database)
        {
            _provider = new FeatherQueryProvider(database);
            _expression = Expression.Constant(this);
        }

        internal FeatherQueryable(FeatherQueryProvider provider, Expression expression)
        {
            _provider = provider ?? throw new ArgumentNullException(nameof(provider));
            _expression = expression ?? throw new ArgumentNullException(nameof(expression));
        }

        public Type ElementType => typeof(T);
        public Expression Expression => _expression;
        public IQueryProvider Provider => _provider;

        public IEnumerator<T> GetEnumerator()
            => ExecuteAsync().GetAwaiter().GetResult().GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator()
            => GetEnumerator();

        public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
            => new AsyncEnumerator(ExecuteAsync(cancellationToken).GetAwaiter().GetResult().GetEnumerator());

        private Task<List<T>> ExecuteAsync(CancellationToken cancellationToken = default)
            => _provider.ExecuteAsync<List<T>>(_expression, cancellationToken);

        private class AsyncEnumerator : IAsyncEnumerator<T>
        {
            private readonly IEnumerator<T> _inner;

            public AsyncEnumerator(IEnumerator<T> inner) => _inner = inner;
            public T Current => _inner.Current;

            public ValueTask<bool> MoveNextAsync() => new(_inner.MoveNext());
            public ValueTask DisposeAsync()
            {
                _inner.Dispose();
                return ValueTask.CompletedTask;
            }
        }
    }

    public enum ExecutionType
    {
        List,
        FirstOrDefault,
        SingleOrDefault,
        Count,
        Any
    }

    public class SqlTranslationResult
    {
        public string Sql { get; set; } = "";
        public List<MySqlParameter> Parameters { get; set; } = new();
        public ExecutionType ExecutionType { get; set; } = ExecutionType.List;
        public bool IsProjection { get; set; }
        public Type? ProjectedType { get; set; }
        public List<MemberInfo>? ProjectedMembers { get; set; }
    }

    public class FeatherQueryProvider : IQueryProvider
    {
        private readonly FeatherDatabase _database;
        private static readonly ConcurrentDictionary<Type, PropertyInfo[]> _propertyCache = new();

        public FeatherQueryProvider(FeatherDatabase database)
        {
            _database = database ?? throw new ArgumentNullException(nameof(database));
        }

        public IQueryable CreateQuery(Expression expression)
        {
            var elementType = GetElementType(expression.Type);
            var queryableType = typeof(FeatherQueryable<>).MakeGenericType(elementType);
            return (IQueryable)queryableType
                .GetConstructor(new[] { typeof(FeatherQueryProvider), typeof(Expression) })!
                .Invoke(new object[] { this, expression });
        }

        public IQueryable<TElement> CreateQuery<TElement>(Expression expression)
        {
            return new FeatherQueryable<TElement>(this, expression);
        }

        public object? Execute(Expression expression)
            => ExecuteAsync(expression).GetAwaiter().GetResult();

        public TResult Execute<TResult>(Expression expression)
            => (TResult)ExecuteAsync(expression).GetAwaiter().GetResult()!;

        public Task<object?> ExecuteAsync(Expression expression, CancellationToken cancellationToken = default)
            => ExecuteCoreAsync(expression, cancellationToken);

        public async Task<TResult> ExecuteAsync<TResult>(Expression expression, CancellationToken cancellationToken = default)
        {
            var result = await ExecuteCoreAsync(expression, cancellationToken);

            if (result is System.Collections.IList sourceList && typeof(TResult) != sourceList.GetType())
            {
                if (typeof(TResult).IsGenericType && typeof(TResult).GetGenericTypeDefinition() == typeof(List<>))
                {
                    var elementType = typeof(TResult).GetGenericArguments()[0];
                    var typedList = (System.Collections.IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(elementType))!;
                    foreach (var item in sourceList)
                    {
                        typedList.Add(item);
                    }
                    return (TResult)(object)typedList;
                }
            }

            return (TResult)result!;
        }

        private async Task<object?> ExecuteCoreAsync(Expression expression, CancellationToken cancellationToken)
        {
            var sourceType = FindSourceType(expression);
            var translator = new SqlExpressionTranslator(sourceType);
            var translation = translator.Translate(expression);

            await using var connection = new MySqlConnection(_database.GetConnectionString());
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var cmd = new MySqlCommand(translation.Sql, connection);

            foreach (var param in translation.Parameters)
                cmd.Parameters.Add(param);

            await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

            if ((translation.IsProjection && translation.ProjectedType != null) ||
                translation.ExecutionType == ExecutionType.Count ||
                translation.ExecutionType == ExecutionType.Any)
            {
                return await ReadProjectionAsync(reader, translation, cancellationToken).ConfigureAwait(false);
            }

            var props = GetCachedProperties(sourceType);
            var list = new List<object>();

            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                list.Add(MapToObject(reader, props, sourceType));
            }

            return translation.ExecutionType switch
            {
                ExecutionType.List => list,
                ExecutionType.FirstOrDefault => list.FirstOrDefault(),
                ExecutionType.SingleOrDefault => list.SingleOrDefault(),
                ExecutionType.Count => list.Count,
                ExecutionType.Any => list.Count > 0,
                _ => list
            };
        }

        private async Task<object?> ReadProjectionAsync(MySqlDataReader reader, SqlTranslationResult translation, CancellationToken cancellationToken)
        {
            var projectedType = translation.ProjectedType!;

            if (translation.ExecutionType == ExecutionType.Count)
            {
                if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                    return Convert.ToInt64(reader.GetValue(0));
                return 0L;
            }

            if (translation.ExecutionType == ExecutionType.Any)
            {
                return await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            }

            if (translation.ExecutionType == ExecutionType.FirstOrDefault)
            {
                if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    if (translation.ProjectedMembers != null && translation.ProjectedMembers.Count > 1)
                        return ConstructMultiMemberObject(reader, translation.ProjectedMembers, projectedType);
                    return ConvertScalarValue(reader.GetValue(0), projectedType);
                }
                return GetDefault(projectedType);
            }

            if (translation.ExecutionType == ExecutionType.SingleOrDefault)
            {
                var result = new List<object>();
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    if (translation.ProjectedMembers != null && translation.ProjectedMembers.Count > 1)
                        result.Add(ConstructMultiMemberObject(reader, translation.ProjectedMembers, projectedType)!);
                    else
                        result.Add(ConvertScalarValue(reader.GetValue(0), projectedType)!);
                }
                return result.Count == 0 ? GetDefault(projectedType) : result.Count == 1 ? result[0] : throw new InvalidOperationException("Sequence contains more than one element");
            }

            var listType = typeof(List<>).MakeGenericType(projectedType);
            var list = (System.Collections.IList)Activator.CreateInstance(listType)!;

            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (translation.ProjectedMembers != null && translation.ProjectedMembers.Count > 1)
                    list.Add(ConstructMultiMemberObject(reader, translation.ProjectedMembers, projectedType)!);
                else
                    list.Add(ConvertScalarValue(reader.GetValue(0), projectedType)!);
            }

            return list;
        }

        private static object? ConstructMultiMemberObject(MySqlDataReader reader, List<MemberInfo> members, Type targetType)
        {
            var values = new object[members.Count];
            var types = new Type[members.Count];

            for (int i = 0; i < members.Count; i++)
            {
                var memberType = members[i] is PropertyInfo pi ? pi.PropertyType : ((FieldInfo)members[i]).FieldType;
                types[i] = memberType;
                var val = reader.GetValue(i);
                values[i] = ConvertScalarValue(val, memberType) ?? GetDefault(memberType)!;
            }

            var constructor = targetType.GetConstructor(types);
            if (constructor != null)
                return constructor.Invoke(values);

            return Activator.CreateInstance(targetType, values);
        }

        private static object? ConvertScalarValue(object? value, Type targetType)
        {
            if (value == null || value == DBNull.Value)
                return GetDefault(targetType);

            var underlying = Nullable.GetUnderlyingType(targetType) ?? targetType;

            if (underlying == typeof(Guid))
                return value is string s ? Guid.Parse(s) : new Guid((byte[])value);

            if (underlying == typeof(bool))
                return Convert.ToInt32(value) != 0;

            if (underlying.IsEnum)
                return Enum.ToObject(underlying, Convert.ToInt32(value));

            return Convert.ChangeType(value, underlying);
        }

        private static object? GetDefault(Type type)
        {
            return type.IsValueType ? Activator.CreateInstance(type) : null;
        }

        private static Type FindSourceType(Expression expression)
        {
            var finder = new SourceTypeFinder();
            finder.Visit(expression);
            return finder.SourceType ?? throw new InvalidOperationException("Could not determine source type");
        }

        private class SourceTypeFinder : ExpressionVisitor
        {
            public Type? SourceType { get; private set; }

            protected override Expression VisitConstant(ConstantExpression node)
            {
                if (node.Value != null)
                {
                    var type = node.Value.GetType();
                    if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(FeatherQueryable<>))
                    {
                        SourceType ??= type.GetGenericArguments()[0];
                    }
                }
                return base.VisitConstant(node);
            }
        }

        private static PropertyInfo[] GetCachedProperties(Type type)
            => _propertyCache.GetOrAdd(type, t => t.GetProperties(BindingFlags.Public | BindingFlags.Instance));

        private static object MapToObject(MySqlDataReader reader, PropertyInfo[] props, Type type)
        {
            var obj = Activator.CreateInstance(type)!;
            var columnLookup = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < reader.FieldCount; i++)
                columnLookup[reader.GetName(i)] = i;

            foreach (var prop in props)
            {
                if (!prop.CanWrite || prop.SetMethod == null) continue;
                if (!columnLookup.TryGetValue(prop.Name, out int ordinal)) continue;

                var val = reader.GetValue(ordinal);
                if (val == DBNull.Value) continue;

                Type targetType = prop.PropertyType;
                Type? underlyingType = Nullable.GetUnderlyingType(targetType);
                if (underlyingType != null) targetType = underlyingType;

                try
                {
                    if (targetType.IsEnum)
                    {
                        object enumValue = val switch
                        {
                            int i => Enum.ToObject(targetType, i),
                            long l => Enum.ToObject(targetType, (int)l),
                            string s => int.TryParse(s, out int parsed)
                                ? Enum.ToObject(targetType, parsed)
                                : Enum.Parse(targetType, s, true),
                            _ => Convert.ChangeType(val, targetType)
                        };
                        prop.SetValue(obj, enumValue);
                    }
                    else if (targetType == typeof(Guid))
                    {
                        prop.SetValue(obj, val is string s ? Guid.Parse(s) : new Guid((byte[])val));
                    }
                    else if (targetType == typeof(bool))
                    {
                        prop.SetValue(obj, Convert.ToInt32(val) != 0);
                    }
                    else if (val is string json && !FeatherDatabase.IsSimpleType(targetType))
                    {
                        var deserialized = JsonConvert.DeserializeObject(json, targetType);
                        prop.SetValue(obj, deserialized);
                    }
                    else
                    {
                        prop.SetValue(obj, Convert.ChangeType(val, targetType));
                    }
                }
                catch
                {
                    if (underlyingType == null && targetType.IsValueType)
                        prop.SetValue(obj, Activator.CreateInstance(targetType));
                }
            }

            return obj;
        }

        private static Type GetElementType(Type type)
        {
            if (type.IsGenericType)
            {
                var genericDef = type.GetGenericTypeDefinition();
                if (genericDef == typeof(IQueryable<>) ||
                    genericDef == typeof(IEnumerable<>) ||
                    genericDef == typeof(IOrderedQueryable<>))
                    return type.GetGenericArguments()[0];
            }
            return typeof(object);
        }
    }

    public class SqlExpressionTranslator
    {
        private readonly string _tableName;
        private readonly List<MySqlParameter> _parameters = new();
        private int _paramCounter;

        private static readonly HashSet<string> _supportedMethods = new()
        {
            "Where", "OrderBy", "OrderByDescending", "ThenBy", "ThenByDescending",
            "Skip", "Take", "Select", "FirstOrDefault", "SingleOrDefault",
            "Count", "LongCount", "Any", "ToList"
        };

        public SqlExpressionTranslator(Type sourceType)
        {
            _tableName = sourceType.Name;
        }

        public SqlTranslationResult Translate(Expression expression)
        {
            var context = new QueryContext
            {
                TableName = _tableName,
                SelectClause = "*",
                WhereClause = "",
                OrderByClause = "",
                Limit = -1,
                Offset = -1,
                ExecutionType = ExecutionType.List
            };

            VisitExpression(expression, context);
            var sql = BuildSql(context, _parameters);

            return new SqlTranslationResult
            {
                Sql = sql,
                Parameters = _parameters,
                ExecutionType = context.ExecutionType,
                IsProjection = context.IsProjection,
                ProjectedType = context.ProjectedType,
                ProjectedMembers = context.ProjectedMembers
            };
        }

        private void VisitExpression(Expression expression, QueryContext context)
        {
            switch (expression)
            {
                case ConstantExpression constant when constant.Value is IQueryable:
                    break;
                case MethodCallExpression methodCall:
                    VisitMethodCall(methodCall, context);
                    break;
                case UnaryExpression unary when unary.NodeType == ExpressionType.Quote:
                    VisitExpression(unary.Operand, context);
                    break;
                case LambdaExpression lambda:
                    VisitExpression(lambda.Body, context);
                    break;
                default:
                    throw new NotSupportedException($"Expression type '{expression.GetType().Name}' is not supported");
            }
        }

        private void VisitMethodCall(MethodCallExpression methodCall, QueryContext context)
        {
            var methodName = methodCall.Method.Name;

            if (!_supportedMethods.Contains(methodName))
                throw new NotSupportedException($"Method '{methodName}' is not supported by FeatherDatabase LINQ provider");

            foreach (var arg in methodCall.Arguments)
            {
                if (IsQueryableType(arg.Type))
                {
                    VisitExpression(arg, context);
                }
            }

            switch (methodName)
            {
                case "Where":
                    ProcessWhere(methodCall, context);
                    break;
                case "OrderBy":
                    ProcessOrderBy(methodCall, context, "ASC", false);
                    break;
                case "OrderByDescending":
                    ProcessOrderBy(methodCall, context, "DESC", false);
                    break;
                case "ThenBy":
                    ProcessOrderBy(methodCall, context, "ASC", true);
                    break;
                case "ThenByDescending":
                    ProcessOrderBy(methodCall, context, "DESC", true);
                    break;
                case "Skip":
                    ProcessSkip(methodCall, context);
                    break;
                case "Take":
                    ProcessTake(methodCall, context);
                    break;
                case "FirstOrDefault":
                    context.ExecutionType = ExecutionType.FirstOrDefault;
                    context.Limit = 1;
                    break;
                case "SingleOrDefault":
                    context.ExecutionType = ExecutionType.SingleOrDefault;
                    context.Limit = 2;
                    break;
                case "Count":
                case "LongCount":
                    context.ExecutionType = ExecutionType.Count;
                    context.SelectClause = "COUNT(*)";
                    break;
                case "Any":
                    context.ExecutionType = ExecutionType.Any;
                    context.SelectClause = "1";
                    break;
                case "ToList":
                    break;
                case "Select":
                    ProcessSelect(methodCall, context);
                    break;
            }
        }

        private void ProcessWhere(MethodCallExpression methodCall, QueryContext context)
        {
            var predicate = GetLambdaFromMethodCall(methodCall);
            if (predicate == null) return;

            var whereSql = TranslatePredicate(predicate.Body);
            context.WhereClause = string.IsNullOrEmpty(context.WhereClause)
                ? whereSql
                : $"{context.WhereClause} AND {whereSql}";
        }

        private void ProcessOrderBy(MethodCallExpression methodCall, QueryContext context, string direction, bool isThenBy)
        {
            var keySelector = GetLambdaFromMethodCall(methodCall);
            if (keySelector == null) return;

            var columnName = GetColumnName(keySelector.Body);
            var orderPart = $"`{columnName}` {direction}";

            if (isThenBy)
            {
                context.OrderByClause = string.IsNullOrEmpty(context.OrderByClause)
                    ? orderPart
                    : $"{context.OrderByClause}, {orderPart}";
            }
            else
            {
                context.OrderByClause = orderPart;
            }
        }

        private void ProcessSkip(MethodCallExpression methodCall, QueryContext context)
        {
            var value = GetConstantValue<int>(methodCall.Arguments.Last());
            context.Offset = value;
        }

        private void ProcessTake(MethodCallExpression methodCall, QueryContext context)
        {
            var value = GetConstantValue<int>(methodCall.Arguments.Last());
            context.Limit = value;
        }

        private void ProcessSelect(MethodCallExpression methodCall, QueryContext context)
        {
            var selector = GetLambdaFromMethodCall(methodCall);
            if (selector == null) return;

            var body = selector.Body;

            if (body is UnaryExpression { NodeType: ExpressionType.Convert } unary)
                body = unary.Operand;

            if (body is MemberExpression member && member.Expression?.NodeType == ExpressionType.Parameter)
            {
                context.SelectClause = $"`{member.Member.Name}`";
                context.IsProjection = true;
                context.ProjectedType = selector.ReturnType;
                context.ProjectedMembers = new List<MemberInfo> { member.Member };
            }
            else if (body is NewExpression newExpr && newExpr.Members != null && newExpr.Members.Count > 0)
            {
                var columns = string.Join(", ", newExpr.Members.Select(m => $"`{m.Name}`"));
                context.SelectClause = columns;
                context.IsProjection = true;
                context.ProjectedType = newExpr.Type;
                context.ProjectedMembers = newExpr.Members.ToList();
            }
            else if (body is MemberInitExpression memberInit && memberInit.Bindings.Count > 0)
            {
                var columns = string.Join(", ", memberInit.Bindings.Select(b => $"`{b.Member.Name}`"));
                context.SelectClause = columns;
                context.IsProjection = true;
                context.ProjectedType = memberInit.Type;
                context.ProjectedMembers = memberInit.Bindings.Select(b => b.Member).ToList();
            }
            else
            {
                throw new NotSupportedException("Only simple property projections are supported in Select (e.g., u => u.Id or u => new { u.Id, u.Name })");
            }
        }

        private string TranslatePredicate(Expression predicate)
        {
            return predicate switch
            {
                BinaryExpression binary => TranslateBinary(binary),
                UnaryExpression unary when unary.NodeType == ExpressionType.Not =>
                    $"NOT ({TranslatePredicate(unary.Operand)})",
                UnaryExpression unary when unary.NodeType == ExpressionType.Convert =>
                    TranslatePredicate(unary.Operand),
                MethodCallExpression methodCall => TranslateMethodCall(methodCall),
                MemberExpression member => $"{TranslateOperand(member)} = {AddParameter(1)}",
                _ => throw new NotSupportedException($"Predicate type '{predicate.GetType().Name}' is not supported")
            };
        }

        private string TranslateBinary(BinaryExpression binary)
        {
            if (binary.NodeType == ExpressionType.Equal && IsNullConstant(binary.Right))
                return $"{TranslateOperand(binary.Left)} IS NULL";

            if (binary.NodeType == ExpressionType.NotEqual && IsNullConstant(binary.Right))
                return $"{TranslateOperand(binary.Left)} IS NOT NULL";

            if (binary.NodeType == ExpressionType.Equal && IsNullConstant(binary.Left))
                return $"{TranslateOperand(binary.Right)} IS NULL";

            if (binary.NodeType == ExpressionType.NotEqual && IsNullConstant(binary.Left))
                return $"{TranslateOperand(binary.Right)} IS NOT NULL";

            var op = binary.NodeType switch
            {
                ExpressionType.Equal => "=",
                ExpressionType.NotEqual => "!=",
                ExpressionType.GreaterThan => ">",
                ExpressionType.GreaterThanOrEqual => ">=",
                ExpressionType.LessThan => "<",
                ExpressionType.LessThanOrEqual => "<=",
                ExpressionType.AndAlso => "AND",
                ExpressionType.OrElse => "OR",
                ExpressionType.Add => "+",
                ExpressionType.Subtract => "-",
                ExpressionType.Multiply => "*",
                ExpressionType.Divide => "/",
                _ => throw new NotSupportedException($"Binary operator '{binary.NodeType}' is not supported")
            };

            if (binary.NodeType is ExpressionType.AndAlso or ExpressionType.OrElse)
            {
                var left = TranslatePredicate(binary.Left);
                var right = TranslatePredicate(binary.Right);
                return $"({left} {op} {right})";
            }

            var leftSql = TranslateOperand(binary.Left);
            var rightSql = TranslateOperand(binary.Right, binary.Right.Type);

            return $"{leftSql} {op} {rightSql}";
        }

        private string TranslateOperand(Expression expression, Type? expectedType = null)
        {
            return expression switch
            {
                MemberExpression member when member.Expression?.NodeType == ExpressionType.Parameter =>
                    $"`{member.Member.Name}`",
                MemberExpression member => AddParameter(GetValue(member)),
                ConstantExpression constant => AddParameter(constant.Value),
                UnaryExpression unary when unary.NodeType == ExpressionType.Convert =>
                    TranslateOperand(unary.Operand, unary.Type),
                _ => AddParameter(GetValue(expression))
            };
        }

        private string TranslateMethodCall(MethodCallExpression methodCall)
        {
            if (methodCall.Method.DeclaringType == typeof(string))
            {
                var column = TranslateOperand(methodCall.Object!);
                var value = GetValue(methodCall.Arguments[0])?.ToString() ?? "";

                var pattern = methodCall.Method.Name switch
                {
                    "Contains" => $"%{EscapeLikePattern(value)}%",
                    "StartsWith" => $"{EscapeLikePattern(value)}%",
                    "EndsWith" => $"%{EscapeLikePattern(value)}",
                    _ => throw new NotSupportedException($"String method '{methodCall.Method.Name}' is not supported")
                };

                return $"{column} LIKE {AddParameter(pattern)}";
            }

            if (methodCall.Method.Name == "get_HasValue")
            {
                return $"{TranslateOperand(methodCall.Object!)} IS NOT NULL";
            }

            if (methodCall.Method.Name == "get_Value")
            {
                return TranslateOperand(methodCall.Object!);
            }

            if (methodCall.Method.Name == "Contains")
            {
                return TranslateContains(methodCall);
            }

            if (methodCall.Method.Name == "Equals" && methodCall.Arguments.Count == 1)
            {
                var left = TranslateOperand(methodCall.Object!);
                var right = TranslateOperand(methodCall.Arguments[0], methodCall.Arguments[0].Type);
                return $"{left} = {right}";
            }

            if (methodCall.Method.Name == "ToString")
            {
                return $"CAST({TranslateOperand(methodCall.Object!)} AS CHAR)";
            }

            throw new NotSupportedException($"Method '{methodCall.Method.Name}' is not supported in WHERE clause");
        }

        private string TranslateContains(MethodCallExpression methodCall)
        {
            Expression? columnExpr = null;
            Expression? collectionExpr = null;

            if (methodCall.Method.DeclaringType == typeof(Enumerable))
            {
                collectionExpr = methodCall.Arguments[0];
                columnExpr = methodCall.Arguments[1];
            }
            else if (methodCall.Object != null)
            {
                collectionExpr = methodCall.Object;
                columnExpr = methodCall.Arguments[0];
            }

            if (columnExpr == null || collectionExpr == null)
                throw new NotSupportedException("Contains expression could not be parsed");

            var columnSql = TranslateOperand(columnExpr);
            var collection = GetValue(collectionExpr) as System.Collections.IEnumerable;

            if (collection == null)
                throw new NotSupportedException("Collection value could not be evaluated for Contains");

            var values = new List<object?>();
            foreach (var item in collection)
            {
                values.Add(item);
            }

            if (values.Count == 0)
                return "1 = 0";

            var paramNames = values.Select(v => AddParameter(v)).ToList();
            return $"{columnSql} IN ({string.Join(", ", paramNames)})";
        }

        private string GetColumnName(Expression expression)
        {
            return expression switch
            {
                MemberExpression member when member.Expression?.NodeType == ExpressionType.Parameter =>
                    member.Member.Name,
                UnaryExpression unary when unary.Operand is MemberExpression member =>
                    member.Member.Name,
                _ => throw new ArgumentException("Invalid order by expression")
            };
        }

        private LambdaExpression? GetLambdaFromMethodCall(MethodCallExpression methodCall)
        {
            foreach (var arg in methodCall.Arguments.Reverse())
            {
                if (arg is LambdaExpression lambda)
                    return lambda;
                if (arg is UnaryExpression { NodeType: ExpressionType.Quote } unary && unary.Operand is LambdaExpression quotedLambda)
                    return quotedLambda;
            }
            return null;
        }

        private T GetConstantValue<T>(Expression expression)
        {
            return expression switch
            {
                ConstantExpression constant => (T)constant.Value!,
                UnaryExpression { NodeType: ExpressionType.Convert } unary =>
                    (T)GetValue(unary.Operand)!,
                _ => (T)GetValue(expression)!
            };
        }

        private object? GetValue(Expression expression)
        {
            switch (expression)
            {
                case ConstantExpression constant:
                    return constant.Value;
                case MemberExpression member:
                    if (member.Expression is ConstantExpression container)
                    {
                        return member.Member switch
                        {
                            FieldInfo field => field.GetValue(container.Value),
                            PropertyInfo prop => prop.GetValue(container.Value),
                            _ => null
                        };
                    }
                    if (member.Expression != null)
                    {
                        var parentValue = GetValue(member.Expression);
                        return member.Member switch
                        {
                            FieldInfo field => field.GetValue(parentValue),
                            PropertyInfo prop => prop.GetValue(parentValue),
                            _ => null
                        };
                    }
                    return null;
                case UnaryExpression { NodeType: ExpressionType.Convert } unary:
                    var innerValue = GetValue(unary.Operand);
                    if (innerValue != null && unary.Type != innerValue.GetType())
                        return Convert.ChangeType(innerValue, unary.Type);
                    return innerValue;
                case NewArrayExpression newArray:
                    return newArray.Expressions.Select(GetValue).ToArray();
                default:
                    try
                    {
                        var lambda = Expression.Lambda(expression);
                        var compiled = lambda.Compile();
                        return compiled.DynamicInvoke();
                    }
                    catch
                    {
                        return null;
                    }
            }
        }

        private string AddParameter(object? value)
        {
            var paramName = $"@p{_paramCounter++}";
            _parameters.Add(new MySqlParameter(paramName, value ?? DBNull.Value));
            return paramName;
        }

        private static bool IsNullConstant(Expression expression)
        {
            return expression is ConstantExpression constant && constant.Value == null;
        }

        private static string EscapeLikePattern(string value)
        {
            return value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
        }

        private static string BuildSql(QueryContext context, List<MySqlParameter> parameters)
        {
            var sql = $"SELECT {context.SelectClause} FROM `{context.TableName}`";

            if (!string.IsNullOrEmpty(context.WhereClause))
                sql += $" WHERE {context.WhereClause}";

            if (!string.IsNullOrEmpty(context.OrderByClause))
                sql += $" ORDER BY {context.OrderByClause}";

            if (context.Limit > 0)
            {
                sql += " LIMIT @__Limit";
                parameters.Add(new MySqlParameter("@__Limit", context.Limit));
                if (context.Offset > 0)
                {
                    sql += " OFFSET @__Offset";
                    parameters.Add(new MySqlParameter("@__Offset", context.Offset));
                }
            }
            else if (context.Offset > 0)
            {
                sql += " LIMIT 18446744073709551615 OFFSET @__Offset";
                parameters.Add(new MySqlParameter("@__Offset", context.Offset));
            }

            return sql;
        }

        private static bool IsQueryableType(Type type)
        {
            if (!type.IsGenericType) return false;
            var genericDef = type.GetGenericTypeDefinition();
            return genericDef == typeof(IQueryable<>) ||
                   genericDef == typeof(IOrderedQueryable<>) ||
                   genericDef == typeof(FeatherQueryable<>);
        }

        private class QueryContext
        {
            public string TableName { get; set; } = "";
            public string SelectClause { get; set; } = "*";
            public string WhereClause { get; set; } = "";
            public string OrderByClause { get; set; } = "";
            public int Limit { get; set; } = -1;
            public int Offset { get; set; } = -1;
            public ExecutionType ExecutionType { get; set; } = ExecutionType.List;
            public bool IsProjection { get; set; }
            public Type? ProjectedType { get; set; }
            public List<MemberInfo>? ProjectedMembers { get; set; }
        }
    }

    public static class FeatherAsyncExtensions
    {
        public static async Task<List<T>> ToListAsync<T>(this IQueryable<T> query)
        {
            return query switch
            {
                FeatherQueryable<T> featherQuery => await featherQuery._provider
                    .ExecuteAsync<List<T>>(featherQuery._expression),
                _ => query.ToList()
            };
        }

        public static async Task<T?> FirstOrDefaultAsync<T>(this IQueryable<T> query)
        {
            return query switch
            {
                FeatherQueryable<T> featherQuery => await featherQuery._provider.ExecuteAsync<T?>(
                    Expression.Call(typeof(Queryable), "FirstOrDefault", new[] { typeof(T) }, featherQuery._expression)),
                _ => query.FirstOrDefault()
            };
        }

        public static async Task<T?> SingleOrDefaultAsync<T>(this IQueryable<T> query)
        {
            return query switch
            {
                FeatherQueryable<T> featherQuery => await featherQuery._provider.ExecuteAsync<T?>(
                    Expression.Call(typeof(Queryable), "SingleOrDefault", new[] { typeof(T) }, featherQuery._expression)),
                _ => query.SingleOrDefault()
            };
        }

        public static async Task<long> CountAsync<T>(this IQueryable<T> query)
        {
            return query switch
            {
                FeatherQueryable<T> featherQuery => await featherQuery._provider.ExecuteAsync<long>(
                    Expression.Call(typeof(Queryable), "LongCount", new[] { typeof(T) }, featherQuery._expression)),
                _ => query.LongCount()
            };
        }

        public static async Task<bool> AnyAsync<T>(this IQueryable<T> query)
        {
            return query switch
            {
                FeatherQueryable<T> featherQuery => await featherQuery._provider.ExecuteAsync<bool>(
                    Expression.Call(typeof(Queryable), "Any", new[] { typeof(T) }, featherQuery._expression)),
                _ => query.Any()
            };
        }

        public static IQueryable<T> WhereIf<T>(
            this IQueryable<T> query,
            bool condition,
            Expression<Func<T, bool>> predicate)
        {
            return condition ? query.Where(predicate) : query;
        }

        public static IOrderedQueryable<T> OrderByIf<T, TKey>(
            this IQueryable<T> query,
            bool condition,
            Expression<Func<T, TKey>> keySelector)
        {
            return condition ? query.OrderBy(keySelector) : (IOrderedQueryable<T>)query;
        }

        public static IOrderedQueryable<T> OrderByDescendingIf<T, TKey>(
            this IQueryable<T> query,
            bool condition,
            Expression<Func<T, TKey>> keySelector)
        {
            return condition ? query.OrderByDescending(keySelector) : (IOrderedQueryable<T>)query;
        }
    }

    public class FeatherAsyncQuery<T> where T : new()
    {
        private readonly Task<List<T>> _baseTask;
        private readonly List<Func<IEnumerable<T>, IEnumerable<T>>> _operations = new();

        public FeatherAsyncQuery(Task<List<T>> task)
        {
            _baseTask = task;
        }

        private FeatherAsyncQuery(Task<List<T>> task, List<Func<IEnumerable<T>, IEnumerable<T>>> operations)
        {
            _baseTask = task;
            _operations = operations;
        }

        private FeatherAsyncQuery<T> AddOperation(Func<IEnumerable<T>, IEnumerable<T>> operation)
        {
            var newOps = new List<Func<IEnumerable<T>, IEnumerable<T>>>(_operations) { operation };
            return new FeatherAsyncQuery<T>(_baseTask, newOps);
        }

        public FeatherAsyncQuery<T> Where(Expression<Func<T, bool>> predicate)
            => AddOperation(query => query.Where(predicate.Compile()));

        public FeatherAsyncQuery<T> OrderBy<TKey>(Expression<Func<T, TKey>> keySelector)
            => AddOperation(query => query.OrderBy(keySelector.Compile()));

        public FeatherAsyncQuery<T> OrderByDescending<TKey>(Expression<Func<T, TKey>> keySelector)
            => AddOperation(query => query.OrderByDescending(keySelector.Compile()));

        public FeatherAsyncQuery<T> ThenBy<TKey>(Expression<Func<T, TKey>> keySelector)
            => AddOperation(query => ((IOrderedEnumerable<T>)query).ThenBy(keySelector.Compile()));

        public FeatherAsyncQuery<T> ThenByDescending<TKey>(Expression<Func<T, TKey>> keySelector)
            => AddOperation(query => ((IOrderedEnumerable<T>)query).ThenByDescending(keySelector.Compile()));

        public FeatherAsyncQuery<T> Skip(int count)
            => AddOperation(query => query.Skip(count));

        public async Task<List<T>> Take(int count)
        {
            var result = await _baseTask.ConfigureAwait(false);
            IEnumerable<T> current = result;
            foreach (var op in _operations) current = op(current);
            return current.Take(count).ToList();
        }

        public async Task<List<TOut>> Select<TOut>(Expression<Func<T, TOut>> selector)
        {
            var result = await _baseTask.ConfigureAwait(false);
            IEnumerable<T> current = result;
            foreach (var op in _operations) current = op(current);
            return current.Select(selector.Compile()).ToList();
        }

        public async Task<List<T>> ToListAsync()
        {
            var result = await _baseTask.ConfigureAwait(false);
            IEnumerable<T> current = result;
            foreach (var op in _operations) current = op(current);
            return current.ToList();
        }

        public async Task<T?> FirstOrDefaultAsync()
        {
            var result = await _baseTask.ConfigureAwait(false);
            IEnumerable<T> current = result;
            foreach (var op in _operations) current = op(current);
            return current.FirstOrDefault();
        }
    }

    public static class FeatherAsyncBridgeExtensions
    {
        public static FeatherAsyncQuery<T> Where<T>(this Task<List<T>> task, Expression<Func<T, bool>> predicate) where T : new()
            => new FeatherAsyncQuery<T>(task).Where(predicate);

        public static FeatherAsyncQuery<T> OrderBy<T, TKey>(this Task<List<T>> task, Expression<Func<T, TKey>> keySelector) where T : new()
            => new FeatherAsyncQuery<T>(task).OrderBy(keySelector);

        public static FeatherAsyncQuery<T> OrderByDescending<T, TKey>(this Task<List<T>> task, Expression<Func<T, TKey>> keySelector) where T : new()
            => new FeatherAsyncQuery<T>(task).OrderByDescending(keySelector);

        public static FeatherAsyncQuery<T> ThenBy<T, TKey>(this FeatherAsyncQuery<T> query, Expression<Func<T, TKey>> keySelector) where T : new()
            => query.ThenBy(keySelector);

        public static FeatherAsyncQuery<T> ThenByDescending<T, TKey>(this FeatherAsyncQuery<T> query, Expression<Func<T, TKey>> keySelector) where T : new()
            => query.ThenByDescending(keySelector);

        public static FeatherAsyncQuery<T> Skip<T>(this Task<List<T>> task, int count) where T : new()
            => new FeatherAsyncQuery<T>(task).Skip(count);

        public static FeatherAsyncQuery<T> Skip<T>(this FeatherAsyncQuery<T> query, int count) where T : new()
            => query.Skip(count);

        public static Task<List<T>> Take<T>(this Task<List<T>> task, int count) where T : new()
            => new FeatherAsyncQuery<T>(task).Take(count);

        public static Task<List<T>> Take<T>(this FeatherAsyncQuery<T> query, int count) where T : new()
            => query.Take(count);

        public static Task<List<TOut>> Select<T, TOut>(this Task<List<T>> task, Expression<Func<T, TOut>> selector) where T : new()
            => new FeatherAsyncQuery<T>(task).Select(selector);

        public static Task<List<TOut>> Select<T, TOut>(this FeatherAsyncQuery<T> query, Expression<Func<T, TOut>> selector) where T : new()
            => query.Select(selector);

        public static async Task<TOut?> Select<TIn, TOut>(this Task<TIn?> task, Expression<Func<TIn, TOut>> selector) where TIn : new()
        {
            var result = await task.ConfigureAwait(false);
            if (result == null) return default;
            return selector.Compile()(result);
        }
    }
}