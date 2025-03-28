import { render } from '@/test-utils/helper';
import NoResults from '../index';
import { Table } from '@chakra-ui/react';

describe('<NoResults/>', () => {
    it('it renders', () => {
        const { asFragment } = render(
            <Table>
                <NoResults colSpan={2} message='Some Cell Value' />
            </Table>,
        );
        expect(asFragment()).toMatchSnapshot();
    });
});
