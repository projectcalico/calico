
(function() {
    let globalLink = undefined;

    function scrollPage() {    
        const viewHeight = window.innerHeight;
        const calculationPoint = viewHeight * 0.3;
    
        const firstHeadings = Array.from(document.getElementsByTagName("h1"));
        const secondHeadings = Array.from(document.getElementsByTagName("h2"));
        const thirdHeadings = Array.from(document.getElementsByTagName("h3"));
        const forthHeadings = Array.from(document.getElementsByTagName("h4"));
        const fifthHeadings = Array.from(document.getElementsByTagName("h5"));
        const sixsHeadings = Array.from(document.getElementsByTagName("h6"));
    
        document.get
    
        const allHeadings = [
            ...firstHeadings,
            ...secondHeadings,
            ...thirdHeadings,
            ...forthHeadings,
            ...fifthHeadings,
            ...sixsHeadings,
        ];
    
        let nearestId = '';
        let currentNearestPos = Number.MAX_SAFE_INTEGER;
        
        allHeadings.forEach(h => {
            const headingRect = h.getBoundingClientRect();
            const yPosition = headingRect.y;
    
            if (yPosition === calculationPoint) {
                nearestId = h.id;
                currentNearestPos = 0;
    
                return;
            }
    
            const diff = yPosition < calculationPoint
                ? calculationPoint - yPosition
                : yPosition - calculationPoint;
    
            if (currentNearestPos > diff) {
                currentNearestPos = yPosition;
                nearestId = h.id;
    
                return;
            }
        })
    
        var link = document.querySelectorAll(`a[href=#${nearestId}]`)[0];
        link.className = 'current';
    
        if (globalLink) {
            globalLink.className = '';
            globalLink = link;
        }
    };
    
    window.addEventListener("scroll", scrollPage);
})()