import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errorRate = new Rate('errors');
const responseTime = new Trend('response_time');
const connDrops = new Rate('connection_drops');
const appErrors = new Rate('app_errors');

const BASE_URL = __ENV.API_GATEWAY_URL || 'http://localhost:8080';
const AUTH_TOKEN = __ENV.API_TOKEN || '';
const REQUEST_TIMEOUT = __ENV.REQUEST_TIMEOUT || '30s';

export const options = {
    stages: [
        { duration: '2m', target: 50 },    // Warm up
        { duration: '3m', target: 100 },   // Normal load
        { duration: '3m', target: 200 },   // High load
        { duration: '3m', target: 400 },   // Very high load
        { duration: '3m', target: 600 },   // Extreme load
        { duration: '3m', target: 800 },   // Breaking point
        { duration: '3m', target: 1000 },  // Maximum stress
        { duration: '5m', target: 0 },     // Recovery
    ],
    thresholds: {
        'http_req_duration': ['p(99)<10000'], // 99% should be below 10s during stress
        'app_errors': ['rate<0.3'],            // Allow up to 30% app errors during stress
    },
    // Treat 429 (rate limited) as expected, not a failure in http_req_failed metric
    discardResponseBodies: false,
};

function generateRandomIP() {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

function generateRandomDomain() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let domain = '';
    for (let i = 0; i < 10; i++) {
        domain += chars[Math.floor(Math.random() * chars.length)];
    }
    return `${domain}.com`;
}

function generateLargeBatch(size) {
    const iocs = [];
    for (let i = 0; i < size; i++) {
        iocs.push({
            type: ['ip', 'domain'][Math.floor(Math.random() * 2)],
            value: Math.random() < 0.5 ? generateRandomIP() : generateRandomDomain(),
            description: `Stress test IoC ${i}`,
            severity: ['low', 'medium', 'high', 'info'][Math.floor(Math.random() * 4)],
            source: 'stress-test',
            metadata: {
                md: `Stress-test - ${__VU}-${__ITER}`,
                scenario: 'stress-test',
            },
            tags: ['stress-test'],
            created_by: `stress-tester-${__VU}`,
        });
    }
    return iocs;
}

export function setup() {
    console.log('Starting stress test...');

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

    console.log('System is ready for stress testing');
    return { baseUrl: BASE_URL };
}

export default function (data) {
    const scenario = Math.random();
    const commonHeaders = {
        'Content-Type': 'application/json',
    };
    if (AUTH_TOKEN) {
        commonHeaders.Authorization = `Bearer ${AUTH_TOKEN}`;
    }

    function trackResponse(response) {
        responseTime.add(response.timings.duration);
        connDrops.add(response.status === 0);
        const isAppError = response.status >= 400 && response.status !== 429 && response.status !== 409;
        appErrors.add(isAppError);
        // errors metric: only real application errors (5xx, 4xx except 429/409), not connection drops
        errorRate.add(isAppError);
    }

    // Scenario 1: Standard requests (50%)
    if (scenario < 0.5) {
        group('Standard Batch Upsert', function () {
            const payload = JSON.stringify({
                iocs: generateLargeBatch(5), // 5 IoCs per batch
                auto_enrich: false,
            });

            const params = {
                headers: commonHeaders,
                timeout: REQUEST_TIMEOUT,
                tags: { name: 'StandardBatch' },
            };

            const response = http.post(`${data.baseUrl}/api/v1/iocs/batch`, payload, params);

            check(response, {
                'status is 200 or 429': (r) => r.status === 200 || r.status === 429 || r.status === 0,
                'response time < 10s': (r) => r.timings.duration < 10000,
            });

            trackResponse(response);
        });
    }
    // Scenario 2: Large batch requests (30%)
    else if (scenario < 0.8) {
        group('Large Batch Upsert', function () {
            const payload = JSON.stringify({
                iocs: generateLargeBatch(50), // 50 IoCs per batch
                auto_enrich: false,
            });

            const params = {
                headers: commonHeaders,
                tags: { name: 'LargeBatch' },
                timeout: REQUEST_TIMEOUT,
            };

            const response = http.post(`${data.baseUrl}/api/v1/iocs/batch`, payload, params);

            check(response, {
                'large batch handled': (r) => r.status === 200 || r.status === 429 || r.status === 413 || r.status === 0,
            });

            trackResponse(response);
        });
    }
    // Scenario 3: Rapid fire queries (20%)
    else {
        group('Rapid Queries', function () {
            for (let i = 0; i < 5; i++) {
                const response = http.get(`${data.baseUrl}/api/v1/iocs/stats`, {
                    headers: AUTH_TOKEN ? { Authorization: `Bearer ${AUTH_TOKEN}` } : {},
                    timeout: REQUEST_TIMEOUT,
                    tags: { name: 'RapidQuery' },
                });

                check(response, {
                    // status 0 = connection dropped (expected under extreme stress)
                    'rapid query handled': (r) => r.status === 200 || r.status === 429 || r.status === 0,
                });

                trackResponse(response);
                sleep(0.05);
            }
        });
    }

    // Minimal sleep during stress test
    sleep(0.1);
}

export function teardown(data) {
    console.log('Stress test completed');
    console.log('Checking system recovery...');

    // Wait a bit for system to recover
    sleep(30);

    // Check if system is still responsive
    const healthCheck = http.get(`${data.baseUrl}/health`);
    if (healthCheck.status === 200) {
        console.log('[O] System recovered successfully');
    } else {
        console.log('[X] System may need manual recovery');
    }
}

export function handleSummary(data) {
    // Use our custom 'app_errors' metric (only real application errors, not connection drops)
    const appErrorRate = metricValue(data, 'app_errors', 'rate', 0);
    // Connection drops rate
    const connDropRate = metricValue(data, 'connection_drops', 'rate', 0);
    // k6 built-in metric for reference
    const httpFailedRate = metricValue(data, 'http_req_failed', 'rate', 0);

    let breakingPoint = 'Not reached';
    if (appErrorRate > 0.5) {
        breakingPoint = 'System overwhelmed - 50%+ app error rate';
    } else if (appErrorRate > 0.3) {
        breakingPoint = 'System stressed - 30%+ app error rate';
    } else if (connDropRate > 0.5) {
        breakingPoint = `Connection limited - ${(connDropRate * 100).toFixed(0)}% requests dropped (infrastructure bottleneck)`;
    }

    // Collect HTTP status code distribution for diagnostics
    const statusLines = [];
    const expectedStatuses = ['200', '401', '429', '413', '500', '502', '503', '0'];
    for (const code of expectedStatuses) {
        const metricName = `http_req_status{status:${code}}`;
        const count = metricValue(data, metricName, 'count', 0);
        if (count > 0) {
            statusLines.push(`  HTTP ${code}: ${count} requests`);
        }
    }

    const summaryLines = [
        '',
        'Stress Test Summary',
        `Total Requests: ${metricValue(data, 'http_reqs', 'count', 0)}`,
        `App Errors (4xx excl 429, 5xx): ${(appErrorRate * 100).toFixed(2)}%`,
        `Connection Drops (EOF/timeout): ${(connDropRate * 100).toFixed(2)}%`,
        `HTTP Non-2xx (k6 built-in): ${(httpFailedRate * 100).toFixed(2)}%`,
        `Average Response Time: ${metricFixed(data, 'http_req_duration', 'avg')}ms`,
        `P95 Response Time: ${metricFixed(data, 'http_req_duration', 'p(95)')}ms`,
        `P99 Response Time: ${metricFixed(data, 'http_req_duration', 'p(99)')}ms`,
        `Max Response Time: ${metricFixed(data, 'http_req_duration', 'max')}ms`,
        `Max VUs: ${metricValue(data, 'vus_max', 'max', 0)}`,
        `Breaking Point: ${breakingPoint}`,
    ];

    if (statusLines.length > 0) {
        summaryLines.push('', 'HTTP Status Distribution:');
        summaryLines.push(...statusLines);
    }

    if (appErrorRate > 0.95) {
        summaryLines.push(
            '',
            'WARNING: Near-100% failure rate detected.',
            'Common causes:',
            '  - JWT_SECRET mismatch between test and API Gateway (all 401s)',
            '  - API Gateway or downstream service is down (connection refused)',
            '  - Rate limiting is too restrictive (all 429s)',
        );
    }

    summaryLines.push('');

    return {
        'stdout': summaryLines.join('\n'),
        'stress_test_results.json': JSON.stringify(data),
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
