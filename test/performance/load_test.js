import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const errorRate = new Rate('errors');
const iocCreationTime = new Trend('ioc_creation_time');
const enrichmentTime = new Trend('enrichment_time');
const requestCounter = new Counter('total_requests');

const BASE_URL = __ENV.API_GATEWAY_URL || 'http://localhost:8080';
const AUTH_TOKEN = __ENV.API_TOKEN || '';
const REQUEST_TIMEOUT = __ENV.REQUEST_TIMEOUT || '20s';

export const options = {
    stages: [
        { duration: '1m', target: 10 },   // Ramp up to 10 users
        { duration: '3m', target: 10 },   // Stay at 10 users for 3 minutes
        { duration: '1m', target: 50 },   // Ramp up to 50 users
        { duration: '5m', target: 50 },   // Stay at 50 users for 5 minutes
        { duration: '1m', target: 100 },  // Ramp up to 100 users
        { duration: '5m', target: 100 },  // Stay at 100 users for 5 minutes
        { duration: '2m', target: 0 },    // Ramp down to 0 users
    ],
    thresholds: {
        'http_req_duration': ['p(95)<2000', 'p(99)<5000'], // 95% of requests should be below 2s, 99% below 5s
        'http_req_failed': ['rate<0.05'],  // Less than 5% of requests should fail
        'errors': ['rate<0.1'],            // Less than 10% error rate
    },
};

// Test data generators
function generateRandomIP() {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

function generateRandomDomain() {
    const domains = ['malicious', 'suspicious', 'phishing', 'botnet', 'c2'];
    const tlds = ['com', 'net', 'org', 'io', 'xyz'];
    return `${domains[Math.floor(Math.random() * domains.length)]}-${Math.floor(Math.random() * 10000)}.${tlds[Math.floor(Math.random() * tlds.length)]}`;
}

function parseJsonBody(response) {
    try {
        return JSON.parse(response.body);
    } catch (e) {
        return null;
    }
}

export function setup() {
    console.log('Starting load test setup...');

    if (!AUTH_TOKEN) {
        throw new Error('API_TOKEN is required because /api/v1 routes are protected by JWT auth');
    }

    const healthCheck = http.get(`${BASE_URL}/health`);
    if (healthCheck.status !== 200) {
        throw new Error(`API Gateway is not healthy (status: ${healthCheck.status})`);
    }

    // Pre-flight auth check: verify the token actually works before starting the test
    const authCheck = http.get(`${BASE_URL}/api/v1/iocs/stats`, {
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
        timeout: '10s',
    });
    if (authCheck.status === 401) {
        throw new Error(
            `JWT authentication failed (401). The JWT_SECRET used to generate the token ` +
            `does not match the one configured in the API Gateway. ` +
            `Check that test/Makefile JWT_SECRET matches docker-compose.yaml JWT_SECRET. ` +
            `Response: ${authCheck.body}`
        );
    }
    console.log(`Auth pre-flight check passed (status: ${authCheck.status})`);

    console.log('API Gateway is ready');
    return { baseUrl: BASE_URL };
}

export default function (data) {
    requestCounter.add(1);

    const commonHeaders = {
        'Content-Type': 'application/json',
    };
    if (AUTH_TOKEN) {
        commonHeaders.Authorization = `Bearer ${AUTH_TOKEN}`;
    }

    // Ensure each iteration executes exactly one scenario with configured traffic split.
    const scenario = Math.random();

    // Test Scenario 1: IoC Batch Ingestion (40% of traffic)
    if (scenario < 0.4) {
        group('IoC Batch Ingestion', function () {
            const payload = JSON.stringify({
                iocs: [
                    {
                        type: 'ip',
                        value: generateRandomIP(),
                        description: `Load test IP - VU ${__VU} - Iteration ${__ITER}`,
                        severity: ['low', 'medium', 'high', 'info'][Math.floor(Math.random() * 4)],
                        source: 'load-test',
                        created_by: `test-${__VU}`,
                        metadata: { md: `VU ${__VU} - Iteration ${__ITER}` },
                        tags: ['load-test', 'automated'],
                    },
                    {
                        type: 'domain',
                        value: generateRandomDomain(),
                        description: `Load test domain - VU ${__VU} - Iteration ${__ITER}`,
                        severity: ['low', 'medium', 'high', 'info'][Math.floor(Math.random() * 4)],
                        source: 'load-test',
                        created_by: `test-${__VU}`,
                        metadata: { md: `VU ${__VU} - Iteration ${__ITER}` },
                        tags: ['load-test', 'automated'],
                    },
                ],
                auto_enrich: false,
            });

            const params = {
                headers: commonHeaders,
                timeout: REQUEST_TIMEOUT,
                tags: { name: 'BatchUpsertIoCs' },
            };

            const response = http.post(`${data.baseUrl}/api/v1/iocs/batch`, payload, params);

            const success = check(response, {
                'batch upsert status is 200': (r) => r.status === 200,
                'batch upsert returns IDs': (r) => {
                    const body = parseJsonBody(r);
                    return !!(body && body.success && body.data && Array.isArray(body.data.upserted_ids) && body.data.upserted_ids.length > 0);
                },
            });

            iocCreationTime.add(response.timings.duration);
            errorRate.add(!success);
        });
    }

    // Test Scenario 2: IoC Retrieval (30% of traffic)
    else if (scenario < 0.7) {
        group('IoC Retrieval', function () {
            const params = {
                headers: AUTH_TOKEN ? { Authorization: `Bearer ${AUTH_TOKEN}` } : {},
                timeout: REQUEST_TIMEOUT,
                tags: { name: 'GetIoCStatistics' },
            };
            const response = http.get(`${data.baseUrl}/api/v1/iocs/stats`, params);

            const success = check(response, {
                'statistics status is 200': (r) => r.status === 200,
                'statistics contains data': (r) => {
                    const body = parseJsonBody(r);
                    return !!(body && body.success && body.data);
                },
            });

            errorRate.add(!success);
        });
    }

    // Test Scenario 3: IoC Search (20% of traffic)
    else if (scenario < 0.9) {
        group('IoC Search', function () {
            const severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
            const severity = severities[Math.floor(Math.random() * severities.length)];

            const params = {
                headers: AUTH_TOKEN ? { Authorization: `Bearer ${AUTH_TOKEN}` } : {},
                timeout: REQUEST_TIMEOUT,
                tags: { name: 'FindIoCs' },
            };
            const payload = JSON.stringify({
                pagination: { page: 1, page_size: 20 },
                filter: { severity: severity.toLowerCase() },
            });
            const postParams = {
                ...params,
                headers: {
                    ...params.headers,
                    'Content-Type': 'application/json',
                },
            };
            const response = http.post(`${data.baseUrl}/api/v1/iocs/find`, payload, postParams);

            const success = check(response, {
                'search status is 200': (r) => r.status === 200,
                'search returns IoCs array': (r) => {
                    const body = parseJsonBody(r);
                    return !!(body && body.success && body.data && Array.isArray(body.data.iocs));
                },
            });

            errorRate.add(!success);
        });
    }

    // Test Scenario 4: Threat Operations (10% of traffic)
    else {
        group('Threat Operations', function () {
            // Create threat
            const threatPayload = JSON.stringify({
                threats: [
                    {
                        name: `LOAD-TEST-THREAT-${__VU}-${__ITER}`,
                        description: `Load test threat`,
                        category: ['malware', 'phishing', 'spam'][Math.floor(Math.random() * 3)],
                        severity: ['high', 'low'][Math.floor(Math.random() * 2)],
                        tags: ['load-test'],
                    },
                ],
            });

            const params = {
                headers: commonHeaders,
                timeout: REQUEST_TIMEOUT,
                tags: { name: 'BatchUpsertThreats' },
            };

            const response = http.post(`${data.baseUrl}/api/v1/threats/batch`, threatPayload, params);

            const success = check(response, {
                'threat upsert status is 200': (r) => r.status === 200,
            });

            errorRate.add(!success);
        });
    }

    // Small delay between iterations to simulate real user behavior
    sleep(Math.random() * 2 + 1);
}

// Teardown function - runs once after test
export function teardown(data) {
    console.log('Load test completed');
}

// Handle summary for custom reporting
export function handleSummary(data) {
    return {
        'stdout': textSummary(data, { indent: ' ', enableColors: true }),
        './performance/load_test_results.json': JSON.stringify(data),
    };
}

function metricValue(data, metricName, valueKey, fallback = 0) {
    const metric = data.metrics && data.metrics[metricName];
    if (!metric || !metric.values) {
        return fallback;
    }
    const value = metric.values[valueKey];
    return Number.isFinite(value) ? value : fallback;
}

function metricFixed(data, metricName, valueKey, digits = 2, fallback = 0) {
    return metricValue(data, metricName, valueKey, fallback).toFixed(digits);
}

function textSummary(data, opts) {
    const indent = opts.indent || '';

    let summary = '\n' + indent + 'Load Test Summary\n\n';

    // Request stats
    summary += indent + '  Requests:\n';
    summary += indent + `    Total: ${metricValue(data, 'http_reqs', 'count', 0)}\n`;
    summary += indent + `    Rate: ${metricFixed(data, 'http_reqs', 'rate')} req/s\n`;
    summary += indent + `    Failed: ${(metricValue(data, 'http_req_failed', 'rate', 0) * 100).toFixed(2)}%\n\n`;

    // Response time stats
    summary += indent + '  Response Times:\n';
    summary += indent + `    Average: ${metricFixed(data, 'http_req_duration', 'avg')}ms\n`;
    summary += indent + `    Median: ${metricFixed(data, 'http_req_duration', 'med')}ms\n`;
    summary += indent + `    P95: ${metricFixed(data, 'http_req_duration', 'p(95)')}ms\n`;
    summary += indent + `    P99: ${metricFixed(data, 'http_req_duration', 'p(99)')}ms\n`;
    summary += indent + `    Max: ${metricFixed(data, 'http_req_duration', 'max')}ms\n\n`;

    // VU stats
    summary += indent + '  Virtual Users:\n';
    summary += indent + `    Max: ${metricValue(data, 'vus_max', 'max', 0)}\n\n`;

    // Custom metrics
    if (data.metrics && data.metrics.errors) {
        summary += indent + '  Error Rate:\n';
        summary += indent + `    ${(metricValue(data, 'errors', 'rate', 0) * 100).toFixed(2)}%\n\n`;
    }

    // Thresholds
    summary += indent + '  Thresholds:\n';
    for (const [name, threshold] of Object.entries(data.thresholds || {})) {
        const passed = threshold.ok ? '[O]' : '[X]';
        summary += indent + `    ${passed} ${name}\n`;
    }

    return summary;
}
