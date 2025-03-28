import * as React from 'react';
import { Button, Menu, MenuButton, MenuList } from '@chakra-ui/react';
import type { SystemStyleObject } from '@chakra-ui/react';
import { ChevronDownIcon } from '@chakra-ui/icons';

interface ActionMenuProps {
    sx?: SystemStyleObject;
    buttonAriaLabel: string;
    buttonValue: string;
    children: React.ReactNode;
}

const ActionMenu: React.FC<React.PropsWithChildren<ActionMenuProps>> = ({
    sx,
    buttonAriaLabel,
    buttonValue,
    children,
}) => {
    return (
        <Menu isLazy={true}>
            <MenuButton
                as={Button}
                minWidth='90px'
                variant='ghost'
                data-testid='action-menu-button'
                onClick={(e) => e.stopPropagation()}
                aria-label={buttonAriaLabel}
                rightIcon={<ChevronDownIcon w={5} h={5} />}
                sx={sx}
            >
                {buttonValue}
            </MenuButton>
            <MenuList>{children}</MenuList>
        </Menu>
    );
};

export default ActionMenu;
