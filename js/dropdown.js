$(document).ready(function() {
    $('[data-toggle="dropdown-with-sub-menu"]').click(function(event) {
        if ($(window).width() > 1024) return;

        if (!$(this).parent().hasClass('open')) {
            $('.dropdown-with-sub-menu').removeClass('open');
        }

        $(this).parent().toggleClass('open');
    });

    $('[data-toggle="dropdown"]').click(function(event) {
        if ($(window).width() > 1024) return;

        $('.dropdown-with-sub-menu').removeClass('open');
        $('.sub-menu').removeClass('open');
    });

    $('[data-toggle="sub-dropdown"]').click(function(event) {
        if ($(window).width() > 1024) return;

        if (!$(this).parent().find('.sub-menu').hasClass('open')) {
            $('.sub-menu').removeClass('open');
        }

        $(this).parent().find('.sub-menu').toggleClass('open');
    });
});