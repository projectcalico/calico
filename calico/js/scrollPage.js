(function () {
    const tocs = document.querySelectorAll('.toc');
    tocs.forEach(toc => {
        const links = getLinks(toc);

        links.emptyLinks.forEach(l => l.link.hidden = true);

        const highlightNearestLink = highlightNearestLinkHandlerFactory(links.availableLinks);
        highlightNearestLink();
        window.addEventListener("scroll", highlightNearestLink);
    });

    function getLinks(toc) {
        const links = Array
            .from(toc.getElementsByTagName("a"))
            .map(link => ({ link, id: link.href.split("#")[1] }));

        return links.reduce((links, link) => {
            if (link.id) {
                links.availableLinks.push(link);
            } else {
                links.emptyLinks.push(link);
            }

            return links;
        }, { emptyLinks: [], availableLinks: [] });
    }

    function highlightNearestLinkHandlerFactory(availableLinks) {
        let highlightedLink = undefined;

        return function highlightNearestLink() {
            const nearestLink = findNearestLink(availableLinks, highlightedLink);
            if (highlightedLink) {
                highlightedLink.link.className = '';
            }
            if (nearestLink) {
                nearestLink.link.className = 'current';
            }
            highlightedLink = nearestLink;
        }
    }

    function findNearestLink(availableLinks, previousNearestLink) {
        let nearestLink = previousNearestLink;
        let currentNearestPos = undefined;

        for (const link of availableLinks) {
            const id = link.id;
            const heading = document.getElementById(id);

            if (!heading) {
                continue;
            }

            const headingRect = heading.getBoundingClientRect();
            const yPosition = headingRect.top;

            if (yPosition === 0) {
                nearestLink = link;
                break;
            }

            const diff = yPosition * yPosition;
            if (!currentNearestPos || diff <= currentNearestPos) {
                currentNearestPos = diff;
                nearestLink = link;
            }
        }

        return nearestLink;
    }
})();
