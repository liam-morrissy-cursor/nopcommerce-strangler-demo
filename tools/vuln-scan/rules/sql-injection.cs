// Semgrep rule test fixture (run: semgrep --test tools/vuln-scan/rules). Not compiled.
public class SearchController : BasePublicController
{
    public IActionResult Find(string name, int id)
    {
        // ruleid: sql-from-request-input, sql-string-concatenation
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);

        var q = $"SELECT * FROM Users WHERE Name = '{name}'";
        // ruleid: sql-from-request-input
        _db.ExecuteAsync(q);

        // ruleid: sql-string-concatenation
        cmd.CommandText = $"DELETE FROM T WHERE Id = {id}";

        // ruleid: sql-from-request-input, sql-string-concatenation
        _dataProvider.QueryAsync<Foo>(string.Format("SELECT * FROM X WHERE a='{0}'", Request.Query["a"]));

        // ok: sql-from-request-input, sql-string-concatenation
        _db.ExecuteAsync("SELECT 1");

        // ok: sql-string-concatenation
        _db.ExecuteAsync($"SELECT 1");

        // ok: sql-from-request-input, sql-string-concatenation
        var safe = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
        safe.Parameters.AddWithValue("@name", name);

        // ok: sql-from-request-input
        _logger.Information("Searching for " + name);

        return View();
    }
}

public class TaskController : BasePublicController
{
    public async Task<IActionResult> RunTask(string taskType)
    {
        var task = await _scheduleTaskService.GetTaskByTypeAsync(taskType);
        // ok: sql-from-request-input
        await _taskRunner.ExecuteAsync(task);
        return NoContent();
    }
}
