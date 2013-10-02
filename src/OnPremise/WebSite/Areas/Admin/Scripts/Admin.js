$(function () {
    $(".config-editor .message").slideDown().delay(5000).slideUp();

    $("button.base64").click(function () {
        var self = $(this);
        var url = cryptoRandomUrl;
        var target = self.data("base64target");
        $.ajax({
            url: url, cache: false,
            success: function (result) {
                $("#" + target).val(result);
            }
        });
    });
});
