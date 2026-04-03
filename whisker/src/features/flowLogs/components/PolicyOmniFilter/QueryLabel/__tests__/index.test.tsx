import { render, screen } from '@/test-utils/helper';
import QueryLabel, { arePropsEqual } from '..';
import { QuerySelect } from '../../QueryList';

const kind = { label: 'NetworkPolicy', value: 'NetworkPolicy' };
const tier = { label: 'default', value: 'default' };
const namespace = { label: 'kube-system', value: 'kube-system' };
const name = { label: 'allow-dns', value: 'allow-dns' };

describe('arePropsEqual', () => {
    it.each([
        ['both queries are empty', {}, {}],
        [
            'all field values match',
            { kind, tier, namespace, name },
            { kind, tier, namespace, name },
        ],
        [
            'labels differ but values match',
            { kind: { label: 'NP', value: 'NetworkPolicy' } },
            { kind: { label: 'NetPol', value: 'NetworkPolicy' } },
        ],
        [
            'both fields are null or undefined',
            { kind: null },
            { kind: undefined },
        ],
    ])('returns true when %s', (_desc, prev, next) => {
        expect(arePropsEqual({ query: prev }, { query: next })).toBe(true);
    });

    it.each([
        [
            'kind',
            { kind },
            {
                kind: {
                    label: 'GlobalNetworkPolicy',
                    value: 'GlobalNetworkPolicy',
                },
            },
        ],
        ['tier', { tier }, { tier: { label: 'security', value: 'security' } }],
        [
            'namespace',
            { namespace },
            { namespace: { label: 'default', value: 'default' } },
        ],
        ['name', { name }, { name: { label: 'deny-all', value: 'deny-all' } }],
    ])('returns false when %s value differs', (_field, prev, next) => {
        expect(arePropsEqual({ query: prev }, { query: next })).toBe(false);
    });

    it('returns false when one field is set and the other is undefined', () => {
        expect(arePropsEqual({ query: { kind } }, { query: {} })).toBe(false);
    });
});

describe('<QueryLabel />', () => {
    it('renders placeholder when query is empty', () => {
        render(<QueryLabel query={{}} />);

        expect(screen.getByText('Add a query...')).toBeInTheDocument();
    });

    it('renders a badge for a single field', () => {
        render(<QueryLabel query={{ kind }} />);

        expect(screen.getByText('kind = NetworkPolicy')).toBeInTheDocument();
        expect(screen.queryByText('&')).not.toBeInTheDocument();
    });

    it('renders badges with "&" separator for multiple fields', () => {
        const query: QuerySelect = { kind, tier };
        render(<QueryLabel query={query} />);

        expect(screen.getByText('kind = NetworkPolicy')).toBeInTheDocument();
        expect(screen.getByText('tier = default')).toBeInTheDocument();
        expect(screen.getByText('&')).toBeInTheDocument();
    });

    it('renders all four fields with separators between them', () => {
        const query: QuerySelect = { kind, tier, namespace, name };
        render(<QueryLabel query={query} />);

        expect(screen.getByText('kind = NetworkPolicy')).toBeInTheDocument();
        expect(screen.getByText('tier = default')).toBeInTheDocument();
        expect(screen.getByText('namespace = kube-system')).toBeInTheDocument();
        expect(screen.getByText('name = allow-dns')).toBeInTheDocument();
        expect(screen.getAllByText('&')).toHaveLength(3);
    });

    it('skips null fields', () => {
        const query: QuerySelect = { kind, tier: null };
        render(<QueryLabel query={query} />);

        expect(screen.getByText('kind = NetworkPolicy')).toBeInTheDocument();
        expect(screen.queryByText(/tier/)).not.toBeInTheDocument();
        expect(screen.queryByText('&')).not.toBeInTheDocument();
    });
});
