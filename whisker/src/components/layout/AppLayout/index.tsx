import { Grid, GridItem } from '@chakra-ui/react';
import { Outlet } from 'react-router-dom';
import AppHeader from '../AppHeader';
import { gridStyles } from './styles';

const AppLayout: React.FC = () => (
    <Grid sx={gridStyles}>
        <GridItem gridArea='header'>
            <AppHeader />
        </GridItem>
        <GridItem id='main' gridArea='main' overflowY='auto' height='100%'>
            <Outlet />
        </GridItem>
    </Grid>
);

export default AppLayout;
