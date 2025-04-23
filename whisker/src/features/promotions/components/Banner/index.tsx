import { ArrowRightIcon } from '@/icons';
import { Alert, AlertDescription, CloseButton, Link } from '@chakra-ui/react';
import React from 'react';
import { alertDescriptionStyles, linkStyles } from './styles';

const testId = 'promotions-banner';

type BannerProps = {
    link: string;
    description: string;
    clusterId?: string;
    onClose: () => void;
};

const Banner: React.FC<BannerProps> = ({
    description,
    link,
    onClose,
    clusterId,
}) => (
    <Alert status='info' padding={1} data-testid={testId}>
        <AlertDescription sx={alertDescriptionStyles}>
            {description}{' '}
            <Link
                isExternal
                href={`${link}?utm_source=whisker&utm_medium=promo-banner-link&utm_campaign=oss-ui&whisker_id=${clusterId}`}
                variant='underlined'
                sx={linkStyles}
                data-testid={`${testId}-link`}
            >
                {link}
                <ArrowRightIcon ml={1} />
            </Link>
        </AlertDescription>
        <CloseButton
            ml='auto'
            onClick={onClose}
            data-testid={`${testId}-close-button`}
        />
    </Alert>
);

export default Banner;
