import * as React from 'react';
import type { SystemStyleObject, HTMLChakraProps } from '@chakra-ui/react';
import { Box, Button, Flex, useStyleConfig } from '@chakra-ui/react';
import { dividerStyles } from './styles';
import OmniFilter, { OmniFilterProps } from '../OmniFilter';
import { OperatorType } from '../OmniFilter/types';

interface OmniFilterListProps extends HTMLChakraProps<'div'> {
    sx?: SystemStyleObject;
    defaultFilterIds: Array<string>;
    visibleFilterIds: Array<string>;
    onResetVisible: () => void;
    onChangeVisible: (labels: Array<string>) => void;
    children: React.ReactNode;
    labelReset?: string;
    labelResetAria?: string;
    labelMore?: string;
}

type FiltersList = Array<{ filterId: string; filterLabel: string }>;

const areArraysEqual = (arr1: Array<any>, arr2: Array<any>) =>
    arr1.length === arr2.length && arr1.every((id) => arr2.includes(id));

const OmniFilterList: React.FC<
    React.PropsWithChildren<OmniFilterListProps>
> = ({
    children,
    defaultFilterIds,
    visibleFilterIds,
    onResetVisible,
    onChangeVisible,
    labelResetAria = 'Reset filter changes to default',
    labelReset = 'Reset',
    labelMore = 'More +',
    ...rest
}) => {
    const listStyles = useStyleConfig('OmniFilterList', rest);
    const [filters, setFilters] = React.useState<FiltersList>([]);
    const [isDirty, setDirty] = React.useState<boolean>(false);

    React.useEffect(() => {
        const childFilters: FiltersList = [];
        let hasChangedContent = false;

        React.Children.forEach(children, (child) => {
            if (React.isValidElement<OmniFilterProps>(child)) {
                const {
                    filterLabel,
                    filterId,
                    selectedFilters,
                    selectedOperator,
                } = child.props;

                childFilters.push({
                    filterLabel,
                    filterId,
                });

                if (
                    !hasChangedContent &&
                    selectedFilters &&
                    selectedFilters.length > 0
                ) {
                    hasChangedContent = true;
                }

                if (
                    !hasChangedContent &&
                    selectedOperator &&
                    selectedOperator !== OperatorType.Equals
                ) {
                    hasChangedContent = true;
                }

                setFilters(childFilters);
                setDirty(
                    hasChangedContent ||
                        !areArraysEqual(defaultFilterIds, visibleFilterIds),
                );
            }
        });
    }, [children]);

    const moreFilters = filters
        .filter((filter) => !defaultFilterIds.includes(filter.filterId))
        .map(({ filterId, filterLabel }) => ({
            label: filterLabel,
            value: filterId,
        }));

    return (
        <Flex __css={listStyles} {...rest}>
            {React.Children.map(children as any, (child: React.ReactElement) =>
                visibleFilterIds.includes(child.props.filterId)
                    ? React.cloneElement(child, child.props)
                    : null,
            )}

            {moreFilters.length > 0 && (
                <OmniFilter
                    filterId='omniMoreFilter'
                    filterLabel={labelMore}
                    showSearch={false}
                    showButtonIcon={false}
                    showOperatorSelect={false}
                    showSelectedOnButton={false}
                    selectedFilters={moreFilters.filter(({ value }) =>
                        visibleFilterIds.includes(value),
                    )}
                    onClear={() => onChangeVisible([...defaultFilterIds])}
                    filters={moreFilters}
                    onChange={(change) =>
                        onChangeVisible([
                            ...defaultFilterIds,
                            ...change.filters.map((filter) => filter.value),
                        ])
                    }
                />
            )}

            {isDirty && <Box sx={dividerStyles} />}

            {isDirty && (
                <Button
                    data-testid='omnifilterlist-reset'
                    aria-label={labelResetAria}
                    variant='ghost'
                    onClick={() => onResetVisible()}
                >
                    {labelReset}
                </Button>
            )}
        </Flex>
    );
};

export default OmniFilterList;
