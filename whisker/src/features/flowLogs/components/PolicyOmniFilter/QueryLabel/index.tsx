import React from 'react';
import { Badge, Text } from '@chakra-ui/react';
import { QuerySelect } from '../QueryList';

type QueryLabelProps = {
    query: QuerySelect;
    showEmptyMessage?: boolean;
};

const QueryLabel: React.FC<QueryLabelProps> = ({
    query,
    showEmptyMessage = true,
}) => {
    const label = [
        query.kind && `(kind = ${query.kind.label})`,
        query.tier && `(tier = ${query.tier.label})`,
        query.namespace && `(namespace = ${query.namespace.label})`,
        query.name && `(name = ${query.name.label})`,
    ]
        .filter(Boolean)
        .join(' and ');

    const labels = [
        query.kind && `kind = ${query.kind.label}`,
        query.tier && `tier = ${query.tier.label}`,
        query.namespace && `namespace = ${query.namespace.label}`,
        query.name && `name = ${query.name.label}`,
    ].filter(Boolean);

    if (label.length > 0) {
        return (
            <div className='flex gap-1 mr-4 flex-wrap'>
                {labels.map((label, index) => (
                    <div className='flex gap-1' key={label}>
                        <Badge
                            key={label}
                            fontWeight='medium'
                            textTransform='none'
                            fontSize='sm'
                            variant='solid'
                        >
                            {label}
                        </Badge>

                        {index !== labels.length - 1 && (
                            <Text fontWeight='normal'>&</Text>
                        )}
                    </div>
                ))}
            </div>
        );
    }

    return (
        <span
            className={`text-left flex-1 text-tigera-token-fg-subtle text-sm min-h-[20px] transition-opacity duration-200 ${showEmptyMessage ? 'opacity-100' : 'opacity-0'}`}
        >
            No filters applied
        </span>
    );
};

export const arePropsEqual = (prev: QueryLabelProps, next: QueryLabelProps) =>
    prev.showEmptyMessage === next.showEmptyMessage &&
    prev.query.kind?.value === next.query.kind?.value &&
    prev.query.tier?.value === next.query.tier?.value &&
    prev.query.namespace?.value === next.query.namespace?.value &&
    prev.query.name?.value === next.query.name?.value;

export default React.memo(QueryLabel, arePropsEqual);
