import { Alert, AlertDescription, CloseButton } from '@chakra-ui/react';
import AppHeader from '../AppHeader';
import { Outlet } from 'react-router-dom';
import { Link } from '@/libs/tigera/ui-components/components/common';
import ArrowRightIcon from '@/icons/ArrowRightIcon';
import { alertDescriptionStyles, linkStyles } from './styles';

const AppLayout: React.FC = () => (
    <>
        <Alert status='info' padding='2px'>
            <AlertDescription sx={alertDescriptionStyles}>
                Popup message informing user about feature or event.{' '}
                <Link
                    isExternal
                    href='https://tigera.io'
                    variant='underlined'
                    sx={linkStyles}
                >
                    Link
                    <ArrowRightIcon ml={1} />
                </Link>
            </AlertDescription>
            <CloseButton ml='auto' />
        </Alert>
        <AppHeader />
        <Outlet />
    </>
);

export default AppLayout;
