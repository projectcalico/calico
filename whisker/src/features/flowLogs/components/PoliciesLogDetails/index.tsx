import React from 'react';
import {
    Table,
    Tbody,
    Tr,
    Td,
    Heading,
    Th,
    Tooltip,
    Icon,
    Flex,
    Box,
    Popover,
    PopoverTrigger,
    PopoverContent,
    PopoverBody,
    Portal,
} from '@chakra-ui/react';
import { InfoOutlineIcon } from '@chakra-ui/icons';
import {
    headingStyles,
    infoIconStyles,
    tableStyles,
    triggerButtonStyles,
    triggerTableStyles,
} from './styles';
import { Policy, PoliciesLogEntries } from '@/types/api';
import { TriggeredIcon } from '@/icons';
import PolicyActionIndicator from '@/components/common/PolicyActionIndicator';
import { FlowLogAction } from '@/types/render';

type PoliciesLogDetails = {
    tableCellData: PoliciesLogEntries;
};

const END_OF_TIER_POLICY_KIND = 'EndOfTier';
const PROFILE_POLICY_KIND = 'Profile';

const POLICY_ENTRIES = [
    {
        key: 'enforced',
        title: 'Enforced Policies',
        description: 'Policies that were enforced for this flow.',
    },
    {
        key: 'pending',
        title: 'Pending Policies',
        description:
            'Policies that would be enforced if a new connection was initiated now, and staged policies were enforced.',
    },
];

const transformPolicyLog = (tableCellData: PoliciesLogEntries) =>
    POLICY_ENTRIES.reduce((acc: PoliciesLogEntries, { key }) => {
        acc[key] = tableCellData[key].map((policy: Policy) =>
            policy.kind === PROFILE_POLICY_KIND
                ? {
                      ...policy,
                      kind: END_OF_TIER_POLICY_KIND,
                      tier: 'default',
                      name: '',
                      policy_index: null,
                      rule_index: null,
                  }
                : policy.kind === END_OF_TIER_POLICY_KIND
                  ? {
                        ...policy,
                        policy_index: null,
                        rule_index: null,
                    }
                  : policy,
        );

        return acc;
    }, {} as PoliciesLogEntries);

const PoliciesLogDetails: React.FC<PoliciesLogDetails> = ({
    tableCellData,
}) => {
    const policyLogData = React.useMemo(
        () => transformPolicyLog(tableCellData),
        [tableCellData],
    );

    return (
        <Box w='fit-content'>
            {POLICY_ENTRIES.map(({ key, title, description }, index) => {
                return (
                    <Box key={key} mb={2}>
                        <Heading
                            as='h3'
                            {...headingStyles}
                            mt={index === 0 ? 2 : 4}
                        >
                            <span>{title}</span>

                            <Tooltip
                                label={description}
                                hasArrow
                                placement='top'
                            >
                                <Icon
                                    as={InfoOutlineIcon}
                                    sx={infoIconStyles}
                                />
                            </Tooltip>
                        </Heading>

                        <Table
                            variant='inline'
                            data-testid='enforced-policies-table'
                            sx={tableStyles}
                        >
                            <Tbody>
                                <Tr>
                                    <Th>Kind</Th>
                                    <Th>Namespace</Th>
                                    <Th>Policy Name</Th>
                                    <Th>Tier</Th>
                                    <Th>Action</Th>
                                    <Th>Policy Index</Th>
                                    <Th>Rule Index</Th>
                                    <Th>Triggered By</Th>
                                </Tr>
                                {policyLogData[key].map((policy: Policy) => {
                                    return (
                                        <Tr
                                            key={`${policy.kind}:${policy.name}:${policy.namespace}`}
                                        >
                                            <Td>{policy.kind}</Td>
                                            <Td>{policy.namespace}</Td>
                                            <Td>{policy.name}</Td>
                                            <Td>{policy.tier}</Td>
                                            <Td>
                                                <PolicyActionIndicator
                                                    action={
                                                        policy.action as FlowLogAction
                                                    }
                                                />
                                            </Td>
                                            <Td>{policy.policy_index ?? ''}</Td>
                                            <Td>{policy.rule_index ?? ''}</Td>
                                            <Td>
                                                {policy.trigger ? (
                                                    <Popover>
                                                        <PopoverTrigger>
                                                            <Flex
                                                                sx={
                                                                    triggerButtonStyles
                                                                }
                                                            >
                                                                <TriggeredIcon />

                                                                <span>
                                                                    {`${policy.trigger.namespace ? policy.trigger.namespace + '/' : ''}${policy.trigger.name}`}
                                                                </span>
                                                            </Flex>
                                                        </PopoverTrigger>
                                                        <Portal>
                                                            <PopoverContent fontFamily='monospace'>
                                                                <PopoverBody>
                                                                    <Table
                                                                        sx={
                                                                            triggerTableStyles
                                                                        }
                                                                    >
                                                                        <tbody>
                                                                            <tr>
                                                                                <td>
                                                                                    Kind
                                                                                </td>
                                                                                <td>
                                                                                    {
                                                                                        policy
                                                                                            .trigger
                                                                                            .kind
                                                                                    }
                                                                                </td>
                                                                            </tr>
                                                                            {policy
                                                                                .trigger
                                                                                .namespace && (
                                                                                <tr>
                                                                                    <td>
                                                                                        Namespace
                                                                                    </td>
                                                                                    <td>
                                                                                        {
                                                                                            policy
                                                                                                .trigger
                                                                                                .namespace
                                                                                        }
                                                                                    </td>
                                                                                </tr>
                                                                            )}
                                                                            <tr>
                                                                                <td>
                                                                                    Policy
                                                                                    Name
                                                                                </td>
                                                                                <td>
                                                                                    {
                                                                                        policy
                                                                                            .trigger
                                                                                            .name
                                                                                    }
                                                                                </td>
                                                                            </tr>
                                                                        </tbody>
                                                                    </Table>
                                                                </PopoverBody>
                                                            </PopoverContent>
                                                        </Portal>
                                                    </Popover>
                                                ) : (
                                                    <span>-</span>
                                                )}
                                            </Td>
                                        </Tr>
                                    );
                                })}
                            </Tbody>
                        </Table>
                    </Box>
                );
            })}
        </Box>
    );
};

export default PoliciesLogDetails;
