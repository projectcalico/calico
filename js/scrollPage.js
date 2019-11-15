
(function() {
    let globalLink = undefined;
    
    document.body.addEventListener("scroll", function () {        
        const calculationPoint = window.pageYOffset;
    
        const toc = document.getElementById("right-toc");
        const links = Array.from(toc.getElementsByTagName("a"));
        const ids = links.map(l => {
            const href = l.href.split("#");
            const id = href[1];

            return id;
        })
    
        let nearestId = '';
        let currentNearestPos = Number.MAX_SAFE_INTEGER;
        
        for(let i of ids) {
            const heading = document.getElementById(i);
            const headingRect = heading.getBoundingClientRect();
            const yPosition = headingRect.y;
    
            if (yPosition === calculationPoint) {
                nearestId = i;
                currentNearestPos = 0;
    
                break;
            }
    
            const diff = yPosition < calculationPoint
                ? Number.MAX_SAFE_INTEGER
                : yPosition - calculationPoint;
    
            if (currentNearestPos > diff) {
                currentNearestPos = yPosition;
                nearestId = i;
            }
        };
    
        var link = links.find(l => l.href.split("#")[1] === nearestId);
    
        if (globalLink) {
            globalLink.className = '';
        }
        globalLink = link;

        link.className = 'current';
    });
})()