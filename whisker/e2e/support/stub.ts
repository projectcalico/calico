import { StubFlowLog } from '../fixtures/flows';

/**
 * Typed client for the stub whisker-backend's control API (e2e/stub/server.mjs).
 *
 * `requests()` and `streamRequests()` are the interesting part: they let a test
 * assert what the frontend actually asked the backend for. That contract is the
 * thing a refactor is most likely to break silently, and it is invisible to
 * component tests that mock the api layer out.
 */

export const STUB_URL = process.env.E2E_STUB_URL ?? 'http://localhost:8081';

export type RecordedRequest = {
    method: string;
    pathname: string;
    query: Record<string, string>;
    search: string;
};

/** A flows stream request with its `filters` blob parsed back into an object. */
export type StreamRequest = {
    startTimeGte: string | undefined;
    filters: Record<string, unknown>;
};

export type StreamCounts = {
    open: number;
    opened: number;
    closed: number;
};

export class StubBackend {
    constructor(private readonly baseUrl: string = STUB_URL) {}

    /** Clears recorded requests and queued data, and drops open streams. */
    async reset(): Promise<void> {
        await this.control('POST', 'reset');
    }

    /** Flows delivered to a stream the moment it opens. */
    async setBacklog(flows: StubFlowLog[]): Promise<void> {
        await this.control('PUT', 'backlog', { flows });
    }

    /** Pushes flows to streams that are already open. */
    async emit(flows: StubFlowLog[]): Promise<void> {
        await this.control('POST', 'emit', { flows });
    }

    /**
     * Filter hint options keyed by the hint type the UI requests, e.g.
     * `{ SourceNamespace: ['default', 'kube-system'] }`. See FilterHintTypes.
     */
    async setHints(hints: Record<string, string[]>): Promise<void> {
        await this.control('PUT', 'hints', { hints });
    }

    /** Forces error statuses on the app-facing routes. */
    async fail(statuses: { flows?: number; hints?: number }): Promise<void> {
        await this.control('PUT', 'failures', statuses);
    }

    async requests(): Promise<RecordedRequest[]> {
        const { requests } = await this.control<{
            requests: RecordedRequest[];
        }>('GET', 'requests');

        return requests;
    }

    /** Every flows stream request, oldest first, with `filters` parsed. */
    async streamRequests(): Promise<StreamRequest[]> {
        const requests = await this.requests();

        return requests
            .filter(
                (request) =>
                    request.pathname.endsWith('/flows') &&
                    request.query.watch === 'true',
            )
            .map((request) => ({
                startTimeGte: request.query.startTimeGte,
                filters: request.query.filters
                    ? JSON.parse(request.query.filters)
                    : {},
            }));
    }

    /** The filters blob from the most recent stream request. */
    async lastStreamFilters(): Promise<Record<string, unknown>> {
        const streams = await this.streamRequests();

        return streams.at(-1)?.filters ?? {};
    }

    /** Filter hint requests, in order, as `[hintType, searchFilters]` pairs. */
    async hintRequests(): Promise<
        Array<{ type: string; filters: Record<string, unknown> }>
    > {
        const requests = await this.requests();

        return requests
            .filter((request) =>
                request.pathname.endsWith('/flows-filter-hints'),
            )
            .map((request) => ({
                type: request.query.type,
                filters: request.query.filters
                    ? JSON.parse(request.query.filters)
                    : {},
            }));
    }

    async streams(): Promise<StreamCounts> {
        return this.control<StreamCounts>('GET', 'streams');
    }

    private async control<T = unknown>(
        method: string,
        route: string,
        body?: unknown,
    ): Promise<T> {
        const response = await fetch(`${this.baseUrl}/__stub__/${route}`, {
            method,
            headers: body ? { 'Content-Type': 'application/json' } : undefined,
            body: body ? JSON.stringify(body) : undefined,
        });

        if (!response.ok) {
            throw new Error(
                `stub control ${method} ${route} failed: ${response.status}`,
            );
        }

        return response.json() as Promise<T>;
    }
}
