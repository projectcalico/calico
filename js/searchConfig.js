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

    var searchResultTemplate = '\
            <div class="search-result ais-result">\
                {{#hierarchy.lvl0}}\
                <h3 class="search-result__category ais-lvl0">\
                    <a href="{{url}}" >\
                        {{{_highlightResult.hierarchy.lvl0.value}}}\
                    </a>\
                </h3>\
                {{/hierarchy.lvl0}}\
                {{#hierarchy.lvl1}}\
                <h4 class="search-result__subcategory ais-lvl1">\
                    <a href="{{url}}">\
                        {{{_highlightResult.hierarchy.lvl1.value}}}\
                    </a>\
                </h4>\
                {{/hierarchy.lvl1}}\
                {{#hierarchy.lvl2}}\
                <h5 class="search-result__subsubcategory ais-lvl2">\
                    <a href="{{url}}">\
                        {{{_highlightResult.hierarchy.lvl2.value}}}\
                    </a>\
                </h5>\
                {{/hierarchy.lvl2}}\
                {{#content}}\
                <div class="search-result__content ais-content">\
                    <a href="{{url}}" >\
                        {{{_snippetResult.content.value}}}\
                    </a>\
                </div>\
                {{/content}}\
            </div>\
        ';

    function initializeInstantSearch(currentDocVersion, inputSelector, resultsSelector, paginationSelector) {
        // TODO: appId, apiKey
        var search = instantsearch({
            appId: 'BH4D9OD16A',
            apiKey: '99def7ba73ea2430f7f42383148fe57a',
            indexName: 'projectcalico',
            routing: false,
            // https://community.algolia.com/instantsearch.js/v2/instantsearch.html#struct-InstantSearchOptions-searchClient
            searchParameters: {
                hitsPerPage: 5,
                // facetsRefinements: {
                //     version: currentDocVersion
                // }
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
                item: searchResultTemplate
            },
            hitsPerPage: 6
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
