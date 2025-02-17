import ArrowRightIcon from '@/icons/ArrowRightIcon';
import { Link } from '@/libs/tigera/ui-components/components/common';
import {
    Alert,
    AlertDescription,
    CloseButton,
    Grid,
    GridItem,
} from '@chakra-ui/react';
import { Outlet } from 'react-router-dom';
import AppHeader from '../AppHeader';
import { alertDescriptionStyles, gridStyles, linkStyles } from './styles';

const AppLayout: React.FC = () => (
    <Grid sx={gridStyles}>
        <GridItem gridArea='alert'>
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
        </GridItem>
        <GridItem gridArea='header'>
            <AppHeader />
        </GridItem>
        <GridItem id='main' gridArea='main' overflowY='auto' height='100%'>
            <Outlet />
        </GridItem>
    </Grid>
);

export default AppLayout;
