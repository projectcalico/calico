
(function() {
    let globalLink = undefined;

    function scrollPage() {    
        const toc = document.getElementById("right-toc");
        const links = Array.from(toc.getElementsByTagName("a"));
        const ids = links.map(l => {
            const href = l.href.split("#");
            const id = href[1];

            return id;
        })
    
        let nearestId = globalLink ? globalLink.href.split("#")[1] : '';
        let currentNearestPos = undefined;

        for(let i of ids) {
            const heading = document.getElementById(i);
            const headingRect = heading.getBoundingClientRect();
            const yPosition = headingRect.y;

            if (yPosition === 0) {
                nearestId = i;
                break;
            }
    

            const diff = yPosition * yPosition;
            if (!currentNearestPos || diff <= currentNearestPos) {
                currentNearestPos = diff;
                nearestId = i;
            }
        };
    
        var link = links.find(l => l.href.split("#")[1] === nearestId);
    
        if (globalLink) {
            globalLink.className = '';
        }
        globalLink = link;

        link.className = 'current';
    }
    
    scrollPage();
    window.addEventListener("scroll", scrollPage);
})()