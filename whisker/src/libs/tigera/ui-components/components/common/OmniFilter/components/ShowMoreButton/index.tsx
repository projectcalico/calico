import { Box, Button } from '@chakra-ui/react';

type ShowMoreButtonProps = {
    isLoadingMore: boolean;
    onRequestMore?: () => void;
};

const ShowMoreButton: React.FC<
    React.PropsWithChildren<ShowMoreButtonProps>
> = ({ isLoadingMore, onRequestMore, children }) => {
    return (
        <Box>
            <Button
                mb={3}
                mt={1}
                variant='ghost'
                fontWeight='semibold'
                size='sm'
                data-testid='show-more-button'
                isLoading={isLoadingMore}
                isDisabled={isLoadingMore}
                onClick={onRequestMore}
            >
                {children}
            </Button>
        </Box>
    );
};

export default ShowMoreButton;
