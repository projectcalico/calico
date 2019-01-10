(function () {
    window.initializeSearch = function (currentDocVersion, searchInputSelector, searchContentSelector,
        searchResultsSelector, searchPaginationSelector) {
        if (!currentDocVersion || typeof (currentDocVersion) !== 'string') {
            throw new Error('Provide a version');
        }

        if (!searchInputSelector || typeof searchInputSelector !== 'string') {
            throw new Error('Provide a search input selector');
        }

        if (!searchContentSelector || typeof searchContentSelector !== 'string') {
            throw new Error('Provide a search content selector');
        }

        if (!searchResultsSelector || typeof searchResultsSelector !== 'string') {
            throw new Error('Provide a search results selector');
        }

        if (!searchPaginationSelector || typeof searchPaginationSelector !== 'string') {
            throw new Error('Provide a search pagination selector');
        }

        $(document).ready(function () {
            initializeInstantSearch(currentDocVersion, searchInputSelector, searchResultsSelector,
                searchPaginationSelector);
            initializePopover(searchContentSelector, searchInputSelector);
            hidePopoversOnClickOutside();
        });
    };

    function initializeInstantSearch(currentDocVersion, inputSelector, resultsSelector, paginationSelector) {
        var search = instantsearch({
            appId: 'BH4D9OD16A',
            apiKey: '99def7ba73ea2430f7f42383148fe57a',
            indexName: 'projectcalico',
            routing: false,
            searchParameters: {
                hitsPerPage: 10,
                facetsRefinements: {
                    version: [currentDocVersion]
                },
                facets: ['version']
            }
        });
        search.addWidget(instantsearch.widgets.searchBox({
            container: inputSelector,
            placeholder: 'Search in the documentation',
            autofocus: false,
            poweredBy: true
        }));
        search.addWidget(instantsearch.widgets.hits({
            container: resultsSelector,
            templates: {
                empty: 'No results',
                allItems: $('#search-results-template').html()
            },
            transformData: {
                allItems: searchResults => {
                    searchResults.hits.sort(function (a, b) {
                        var hitATopCategory = a.hierarchy.lvl0;
                        var hitBTopCategory = b.hierarchy.lvl0;

                        return hitATopCategory < hitBTopCategory
                            ? -1
                            : hitATopCategory > hitBTopCategory;
                    });

                    var visitedTopCategories = {};

                    searchResults.hits.forEach(function (hit) {
                        var hitTopCategory = hit.hierarchy.lvl0;

                        if (hitTopCategory && visitedTopCategories[hitTopCategory]) {
                            hit.shouldDisplayTopCategory = false;
                        } else {
                            hit.shouldDisplayTopCategory = true;
                            visitedTopCategories[hitTopCategory] = true;
                        }
                    });

                    return searchResults;
                }
            }
        }));
        search.addWidget(instantsearch.widgets.pagination({
            container: paginationSelector,
            maxPages: 20,
            scrollTo: false
        }));
        search.start();
    }

    function initializePopover(searchContentSelector, searchInputSelector) {
        var content = $(searchContentSelector).children();
        $(searchInputSelector).popover({
            html: true,
            content: function () {
                return content;
            }
        });
    }

    function hidePopoversOnClickOutside() {
        $('body').on('click', function (e) {
            $('[data-toggle="popover"]').each(function () {
                if (!$(this).is(e.target)
                    && $(this).has(e.target).length === 0
                    && $('.popover').has(e.target).length === 0) {
                    $(this).popover('hide');
                }
            });
        });
    }
})();
