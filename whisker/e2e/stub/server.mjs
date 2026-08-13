/**
 * A programmable stand-in for whisker-backend, used by the Playwright suite.
 *
 * It deliberately knows nothing about flow logs beyond their wire framing:
 * tests push the exact payloads they want through the control API below, so
 * fixtures live with the tests rather than in here. That keeps this file stable
 * while the app (and its fixtures) change.
 *
 * Plain .mjs with no dependencies so it runs under any Node the repo pins.
 *
 * App-facing routes, mirroring whisker-backend:
 *   GET  {base}/flows?watch=true    server-sent event stream of flows
 *   GET  {base}/flows               JSON array of flows
 *   GET  {base}/flows-filter-hints  paged filter hint options
 *
 * Control API, for tests only:
 *   GET  /__stub__/health           readiness probe
 *   POST /__stub__/reset            clear all state and drop open streams
 *   PUT  /__stub__/backlog          flows delivered as soon as a stream opens
 *   POST /__stub__/emit             push flows to currently open streams
 *   PUT  /__stub__/hints            filter hint options, keyed by hint type
 *   PUT  /__stub__/failures         force error statuses on app-facing routes
 *   GET  /__stub__/requests         every app request, in order
 *   GET  /__stub__/streams          open/opened/closed stream counts
 */

import http from 'node:http';

const PORT = Number(process.env.E2E_STUB_PORT ?? 8081);
const BASE_PATH = process.env.E2E_STUB_BASE_PATH ?? '/whisker-backend';

// The app is served from a different origin (the rsbuild dev server), so the
// stub has to opt in to cross-origin reads for both fetch and EventSource.
const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept',
};

const initialState = () => ({
    backlog: [],
    hints: {},
    failures: { flows: null, hints: null },
    requests: [],
    streams: new Set(),
    streamsOpened: 0,
    streamsClosed: 0,
});

let state = initialState();

const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://localhost:${PORT}`);

    if (req.method === 'OPTIONS') {
        res.writeHead(204, CORS_HEADERS);
        res.end();
        return;
    }

    if (url.pathname.startsWith('/__stub__/')) {
        handleControl(req, res, url);
        return;
    }

    recordRequest(req, url);

    if (url.pathname === `${BASE_PATH}/flows`) {
        if (state.failures.flows) {
            respondJson(res, state.failures.flows, { error: 'forced failure' });
            return;
        }

        // `watch=true` is what makes this a stream rather than a list.
        if (url.searchParams.get('watch') === 'true') {
            openStream(req, res);
        } else {
            respondJson(res, 200, state.backlog);
        }
        return;
    }

    if (url.pathname === `${BASE_PATH}/flows-filter-hints`) {
        respondFilterHints(res, url);
        return;
    }

    respondJson(res, 404, { error: `no stub route for ${url.pathname}` });
});

/**
 * Records what the app asked for. Tests assert against this to pin the
 * frontend -> backend contract (e.g. that a deep-linked URL produces the
 * expected `filters` blob) without reaching into the app's internals.
 */
const recordRequest = (req, url) => {
    state.requests.push({
        method: req.method,
        pathname: url.pathname,
        query: Object.fromEntries(url.searchParams.entries()),
        search: url.search,
    });
};

const openStream = (req, res) => {
    res.writeHead(200, {
        // Matches lib/httpmachinery's eventStreamResponseWriter.
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
        ...CORS_HEADERS,
    });
    // Flush the head so EventSource fires onopen before any data arrives.
    res.flushHeaders();

    state.streams.add(res);
    state.streamsOpened += 1;

    for (const flow of state.backlog) {
        writeEvent(res, flow);
    }

    req.on('close', () => {
        if (state.streams.delete(res)) {
            state.streamsClosed += 1;
        }
    });
};

const writeEvent = (res, flow) => {
    res.write(`data: ${JSON.stringify(flow)}\n\n`);
};

const respondFilterHints = (res, url) => {
    if (state.failures.hints) {
        respondJson(res, state.failures.hints, { error: 'forced failure' });
        return;
    }

    const type = url.searchParams.get('type');
    const page = Number(url.searchParams.get('page') ?? 0);
    const pageSize = Number(url.searchParams.get('pageSize') ?? 20);
    const values = state.hints[type] ?? [];
    const start = page * pageSize;

    respondJson(res, 200, {
        items: values
            .slice(start, start + pageSize)
            .map((value) => ({ value })),
        total: {
            totalResults: values.length,
            totalPages: Math.max(1, Math.ceil(values.length / pageSize)),
        },
    });
};

const handleControl = async (req, res, url) => {
    const route = url.pathname.replace('/__stub__/', '');

    if (route === 'health') {
        respondJson(res, 200, { ok: true });
        return;
    }

    if (route === 'requests') {
        respondJson(res, 200, { requests: state.requests });
        return;
    }

    if (route === 'streams') {
        respondJson(res, 200, {
            open: state.streams.size,
            opened: state.streamsOpened,
            closed: state.streamsClosed,
        });
        return;
    }

    const body = await readJsonBody(req);

    switch (route) {
        case 'reset': {
            for (const stream of state.streams) {
                stream.end();
            }
            state = initialState();
            respondJson(res, 200, { ok: true });
            return;
        }
        case 'backlog': {
            state.backlog = body.flows ?? [];
            respondJson(res, 200, { ok: true, count: state.backlog.length });
            return;
        }
        case 'emit': {
            const flows = body.flows ?? [];
            for (const stream of state.streams) {
                for (const flow of flows) {
                    writeEvent(stream, flow);
                }
            }
            respondJson(res, 200, {
                ok: true,
                streams: state.streams.size,
                count: flows.length,
            });
            return;
        }
        case 'hints': {
            state.hints = body.hints ?? {};
            respondJson(res, 200, { ok: true });
            return;
        }
        case 'failures': {
            state.failures = {
                flows: body.flows ?? null,
                hints: body.hints ?? null,
            };
            respondJson(res, 200, { ok: true });
            return;
        }
        default: {
            respondJson(res, 404, { error: `unknown control route ${route}` });
        }
    }
};

const readJsonBody = (req) =>
    new Promise((resolve) => {
        let raw = '';
        req.on('data', (chunk) => {
            raw += chunk;
        });
        req.on('end', () => {
            try {
                resolve(raw ? JSON.parse(raw) : {});
            } catch {
                resolve({});
            }
        });
    });

const respondJson = (res, status, payload) => {
    res.writeHead(status, {
        'Content-Type': 'application/json',
        ...CORS_HEADERS,
    });
    res.end(JSON.stringify(payload));
};

server.listen(PORT, () => {
    console.info(
        `whisker-backend stub listening on http://localhost:${PORT}${BASE_PATH}`,
    );
});
