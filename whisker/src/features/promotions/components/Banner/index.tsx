import { ArrowRightIcon } from '@/icons';
import { Alert, AlertDescription, CloseButton, Link } from '@chakra-ui/react';
import React from 'react';
import { alertDescriptionStyles, linkStyles } from './styles';

type BannerProps = {
    description: string;
    link: string;
    onClose: () => void;
};

const Banner: React.FC<BannerProps> = ({ description, link, onClose }) => (
    <Alert status='info' padding='2px'>
        <AlertDescription sx={alertDescriptionStyles}>
            {description}{' '}
            <Link isExternal href={link} variant='underlined' sx={linkStyles}>
                {link}
                <ArrowRightIcon ml={1} />
            </Link>
        </AlertDescription>
        <CloseButton
            ml='auto'
            onClick={onClose}
            data-testid='promotions-banner-close-button'
        />
    </Alert>
);

export default Banner;
