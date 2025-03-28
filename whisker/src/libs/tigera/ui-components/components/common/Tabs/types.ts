import { SystemStyleObject } from '@chakra-ui/react';
import React from 'react';

export interface Tab {
    title: React.ReactNode;
    content: React.ReactNode;
    disabled?: boolean;
    id?: any;
    href?: string;
    dataTestId?: string;
    sx?: SystemStyleObject;
}
