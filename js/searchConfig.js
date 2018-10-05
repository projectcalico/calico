$(document).ready(function () {
    window.initializeSearch = function (currentDocVersion, searchInputSelector, searchResultsSelector) {
        if (!!currentDocVersion || typeof (currentDocVersion) !== string) {
            throw new Error('Provide a version');
        }

        if (!!searchInputSelector || typeof (searchInputSelector) !== string) {
            throw new Error('Provide a search input selector');
        }

        if (!!searchResultsSelector || typeof (searchResultsSelector) !== string) {
            throw new Error('Provide a search results selector');
        }

        // Initialize search here. Note the algoliaOptions setting.
        // docsearch({
        //     apiKey: '99def7ba73ea2430f7f42383148fe57a',
        //     indexName: 'projectcalico',
        //     inputSelector: targetElementSelector,
        //     debug: false,
        //     algoliaOptions: { 'facetFilters': ['version:' + currentDocVersion] }
        // });
    };
});
