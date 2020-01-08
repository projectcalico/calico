
(function () {
    const tocs = document.querySelectorAll('.toc');
    tocs.forEach(toc => {
        let globalLink = undefined;

        function handleScroll() {
            const links = Array.from(toc.getElementsByTagName("a"));
            const ids = links.map(l => {
                const href = l.href.split("#");
                const id = href[1];

                return id;
            })

            let nearestId = globalLink ? globalLink.href.split("#")[1] : '';
            let currentNearestPos = undefined;

            for (const id of ids) {
                const heading = document.getElementById(id);
                const headingRect = heading.getBoundingClientRect();
                const yPosition = headingRect.top;

                if (yPosition === 0) {
                    nearestId = id;
                    break;
                }


                const diff = yPosition * yPosition;
                if (!currentNearestPos || diff <= currentNearestPos) {
                    currentNearestPos = diff;
                    nearestId = id;
                }
            };

            const link = links.find(l => l.href.split("#")[1] === nearestId);

            if (globalLink) {
                globalLink.className = '';
            }
            globalLink = link;

            link.className = 'current';
        }

        handleScroll();
        window.addEventListener("scroll", handleScroll);
    });
})()