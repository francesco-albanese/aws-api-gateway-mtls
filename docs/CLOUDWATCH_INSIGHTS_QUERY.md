# Useful Cloudwatch Insights Queries

This is a collection of useful queries I ran in Cloudwatch insights against my 2 lambdas and api gateway access logs to find out about latency, cold start and throttle count when conducting performance tests:

1. Throttle count:

```bash
fields @timestamp, @message
| filter @message like /Rate Exceeded|TooManyRequestsException|throttle/
| stats count() as throttle_count
```

2. error count:

```bash
fields @timestamp, @message
| filter @message like /503|429|timeout/
| stats count() as c by @message
| stats sum(c) as total
```

3. cold start:

```bash
fields @timestamp, @duration, @initDuration
| filter @type = "REPORT"
| stats count(@initDuration) as cold_starts,
avg(@initDuration) as avg_cold_start_ms,
max(@duration) as max_duration_ms
```

4. Latency:

```bash
    fields @timestamp, @duration
    | filter @type = "REPORT"
    | stats avg(@duration) as avg_ms,
            pct(@duration, 90) as p90,
            pct(@duration, 99) as p99,
            pct(@duration, 50) as p50,
            max(@duration) as max_ms
    | sort @timestamp desc
```

5. Integration error:

```bash
fields @timestamp, @message
| filter @message like /integrationError/
| filter @message not like /"-"/
```
