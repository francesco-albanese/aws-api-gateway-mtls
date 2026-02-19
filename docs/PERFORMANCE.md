# Performance stats

I wanted to stress test the system to see how API Gateway and the lambdas perform under a small load.
Before running the test I ran `aws lambda get-account-settings | jq '.AccountLimit.ConcurrentExecutions'` to find out how many concurrent executions are enabled on my account by default, the result was 10.

## Concurrent Load test 256MB memory

Ran this bash command to send 10 concurrent requests:

```bash
for i in {1..10}; do make curl-health-verbose & done; wait
```

then ran these [queries in Cloudwatch](./CLOUDWATCH_INSIGHTS_QUERY.md)

Findings:

- One lambda got throttled once
  ![throttled](throttled-10-concurrent.png)

- cold start of authorizer lambda
  ![cold start authorizer](cold-start-authorizer-10-concurrent.png)

- cold start of health lambda
  ![cold start health](cold-start-health-10-concurrent.png)

- latency of authorizer
  ![latency authorizer](latency-authorizer-10-concurrent.png)

- latency of health
  ![latency health](latency-health-10-concurrent.png)

The cold start of 1.5s average seems to be too high for a python lambda, the OTEL instrumentation is clearly adding a significant overhead. 256MB of memory might not be enough, I'll bump it up to 512MB and repeat the same test.

## Concurrent load 512MB memory