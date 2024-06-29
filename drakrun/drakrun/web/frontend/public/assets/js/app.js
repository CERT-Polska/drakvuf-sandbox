/**
 * Theme: Hyper - Responsive Bootstrap 4 Admin Dashboard
 * Author: Coderthemes
 * Module/App: Layout Js
 */


/**
 * LeftSidebar
 * @param {*} $ 
 */
!function ($) {
    'use strict';

    var LeftSidebar = function () {
        this.body = $('body'),
        this.window = $(window),
        this.menuContainer = $('#left-side-menu-container');
    };

    /**
     * Reset the theme
     */
    LeftSidebar.prototype._reset = function() {
        this.body.removeAttr('data-leftbar-theme');
    },

    /**
     * Activates the condensed side bar
     */
    LeftSidebar.prototype.activateCondensedSidebar = function () {
        this.body.attr('data-leftbar-compact-mode', 'condensed');
    },

    /**
     * Deactivates the condensed side bar
     */
    LeftSidebar.prototype.deactivateCondensedSidebar = function() {
        this.body.removeAttr('data-leftbar-compact-mode');
    },
  
    /**
     * Activates the scrollable sidenar
     */
    LeftSidebar.prototype.activateScrollableSidebar = function() {
        this.body.attr('data-leftbar-compact-mode', 'scrollable');
    },

    /**
     * Deactivates the scrollbar
     */
    LeftSidebar.prototype.deactivateScrollableSidebar = function() {
        this.body.removeAttr('data-leftbar-compact-mode');
    },

    /**
     * Activates the default theme
     */
    LeftSidebar.prototype.activateDefaultTheme = function () {
        this._reset();
    },
    
    /**
     * Activates the light theme
     */
    LeftSidebar.prototype.activateLightTheme = function() {
        this._reset();
        this.body.attr('data-leftbar-theme', 'light');
    },

    /**
     * Activates the dark theme
     */
    LeftSidebar.prototype.activateDarkTheme = function() {
        this._reset();
        this.body.attr('data-leftbar-theme', 'dark');
    },

    /**
     * Initilizes the menu
     */
    LeftSidebar.prototype.initMenu = function() {
        var self = this;

        // resets everything
        this._reset();

        // sidebar - main menu
        $('.side-nav').metisMenu();

        // click events
        // Left menu collapse
        $(document).on('click', '.button-menu-mobile', function(e) {
            e.preventDefault();
            self.body.toggleClass('sidebar-enable');

            // if (self.window.width() >= 768) {
            //   self.body.toggleClass('enlarged');
            // } else {
            //   self.body.removeClass('enlarged');
            // }
        });

        // activate the menu in left side bar based on url
        $('.side-nav a').each(function() {
        var pageUrl = window.location.href.split(/[?#]/)[0];
        if (this.href == pageUrl) {
            $(this).addClass('active');
            $(this)
            .parent()
            .addClass('mm-active'); // add active to li of the current link
            $(this)
            .parent()
            .parent()
            .addClass('mm-show');
            $(this)
            .parent()
            .parent()
            .prev()
            .addClass('active'); // add active class to an anchor
            $(this)
            .parent()
            .parent()
            .parent()
            .addClass('mm-active');
            $(this)
            .parent()
            .parent()
            .parent()
            .parent()
            .addClass('mm-show'); // add active to li of the current link
            $(this)
            .parent()
            .parent()
            .parent()
            .parent()
            .parent()
            .addClass('mm-active');
            $(this)
            .parent()
            .parent()
            .parent()
            .parent()
            .parent()
            .parent()
            .addClass('mm-show');
            $(this)
            .parent()
            .parent()
            .parent()
            .parent()
            .parent()
            .parent()
            .parent()
            .addClass('mm-active'); // add active to li of the current link
        }
        });
    },

    /**
     * Initilizes the menu
     */
    LeftSidebar.prototype.init = function() {
        this.initMenu();
    },
  
    $.LeftSidebar = new LeftSidebar, $.LeftSidebar.Constructor = LeftSidebar
}(window.jQuery),


/**
 * Topbar
 * @param {*} $ 
 */
function ($) {
    'use strict';

    var Topbar = function () {
        this.$body = $('body'),
        this.$window = $(window)
    };

    /**
     * Initilizes the menu
     */
    Topbar.prototype.initMenu = function() {
        $('.topnav-menu li a').each(function () {
            var pageUrl = window.location.href.split(/[?#]/)[0];
            if (this.href == pageUrl) {
                $(this).addClass('active');
                $(this).parent().parent().addClass('active'); // add active to li of the current link
                $(this).parent().parent().parent().parent().addClass('active');
                $(this).parent().parent().parent().parent().parent().parent().addClass('active');
            }
        });

        // Topbar - main menu
        $('.navbar-toggle').on('click', function () {
            $(this).toggleClass('open');
            $('#navigation').slideToggle(400);
        });

        $('.dropdown-menu a.dropdown-toggle').on('click', function () {
            if (
                !$(this)
                    .next()
                    .hasClass('show')
            ) {
                $(this)
                    .parents('.dropdown-menu')
                    .first()
                    .find('.show')
                    .removeClass('show');
            }
            var $subMenu = $(this).next('.dropdown-menu');
            $subMenu.toggleClass('show');

            return false;
        });
    },

    /**
     * Initilizes the menu
     */
    Topbar.prototype.init = function() {
        this.initMenu();
    },
    $.Topbar = new Topbar, $.Topbar.Constructor = Topbar
}(window.jQuery),


/**
 * RightBar
 * @param {*} $ 
 */
function ($) {
    'use strict';

    var RightBar = function () {
        this.body = $('body'),
        this.window = $(window)
    };

    /** 
     * Select the option based on saved config
    */
   RightBar.prototype._selectOptionsFromConfig = function() {
        var config = $.App.getLayoutConfig();
        if (config) {
            // sideBarTheme
            switch (config.sideBarTheme) {
                case 'default':
                    $('#default-check').prop('checked', true);
                    break;
                case 'light':
                    $('#light-check').prop('checked', true);
                    break;
                case 'dark':
                    $('#dark-check').prop('checked', true);
                    break;
            }

            if (config.isBoxed) {
                $('#boxed-check').prop('checked', true);
            } else {
                $('#fluid-check').prop('checked', true);
            }
            if (config.isCondensed) $('#condensed-check').prop('checked', true);
            if (config.isScrollable) $('#scrollable-check').prop('checked', true);
            if (!config.isScrollable && !config.isCondensed) $('#fixed-check').prop('checked', true);

            // overall color scheme
            if (!config.isDarkModeEnabled) {
                $('#light-mode-check').prop('checked', true);
                if (config.layout === 'vertical')
                    $('input[type=radio][name=theme]').prop('disabled', false);
            } 
            if (config.isDarkModeEnabled) {
                $('#dark-mode-check').prop('checked', true);
                if (config.layout === 'vertical')
                    $('input[type=radio][name=theme]').prop('disabled', false);
            }
        }
    },
  
    /**
     * Toggles the right sidebar
     */
    RightBar.prototype.toggleRightSideBar = function() {
        var self = this;
        self.body.toggleClass('right-bar-enabled');
        self._selectOptionsFromConfig();
    },

    /**
     * Initilizes the right side bar
     */
    RightBar.prototype.init = function() {
        var self = this;

        // right side-bar toggle
        $(document).on('click', '.right-bar-toggle', function () {
            self.toggleRightSideBar();
        });

        $(document).on('click', 'body', function (e) {
            if ($(e.target).closest('.right-bar-toggle, .right-bar').length > 0) {
                return;
            }

            if (
                $(e.target).closest('.left-side-menu, .side-nav').length > 0 ||
                $(e.target).hasClass('button-menu-mobile') ||
                $(e.target).closest('.button-menu-mobile').length > 0
            ) {
                return;
            }
            $('body').removeClass('right-bar-enabled');
            $('body').removeClass('sidebar-enable');
            return;
        });

        // width mode
        $('input[type=radio][name=width]').change(function () {
            switch ($(this).val()) {
                case 'fluid':
                    $.App.activateFluid();
                    break;
                case 'boxed':
                    $.App.activateBoxed();
                    break;
            }
        });

        // theme
        $('input[type=radio][name=theme]').change(function () {
            switch ($(this).val()) {
                case 'default':
                    $.App.activateDefaultSidebarTheme();
                    break;
                case 'light':
                    $.App.activateLightSidebarTheme();
                    break;
                case 'dark':
                    $.App.activateDarkSidebarTheme();
                    break;
            }
        });

        // compact
        $('input[type=radio][name=compact]').change(function () {
            switch ($(this).val()) {
                case 'fixed':
                    $.App.deactivateCondensedSidebar();
                    $.App.deactivateScrollableSidebar();
                    break;
                case 'scrollable':
                    $.App.activateScrollableSidebar();
                    break;
                case 'condensed':
                    $.App.activateCondensedSidebar();
                    break;
            }
        });

        // overall color scheme
        $('input[type=radio][name=color-scheme-mode]').change(function () {
            switch ($(this).val()) {
                case 'light':
                    $.App.deactivateDarkMode();
                    $.App.activateDefaultSidebarTheme();
                    $('#default-check').prop('checked', true);
                    $('input[type=radio][name=theme]').prop('disabled', false);
                    break;
                case 'dark':
                    $.App.activateDarkMode();
                    $('#dark-check').prop('checked', true);
                    // $('input[type=radio][name=theme]').prop('disabled', true);
                    break;
            }
        });        

        // reset
        $('#resetBtn').on('click', function (e) {
            e.preventDefault();
            // reset to default
            $.App.resetLayout(function() {
                self._selectOptionsFromConfig();
            });
        });
    },

    $.RightBar = new RightBar, $.RightBar.Constructor = RightBar
}(window.jQuery),


/**
 * Layout and theme manager
 * @param {*} $ 
 */

function ($) {
    'use strict';

    // Layout and theme manager
    var SIDEBAR_THEME_DEFAULT = 'default';
    var SIDEBAR_THEME_LIGHT = 'light';
    var SIDEBAR_THEME_DARK = 'dark';

    var DEFAULT_CONFIG = {
        sideBarTheme: SIDEBAR_THEME_DEFAULT,
        isBoxed: false,
        isCondensed: false,
        isScrollable: false,
        isDarkModeEnabled: false
    };

    var LayoutThemeApp = function () {
        this.body = $('body'),
        this.window = $(window),
        this._config = {};
        this.defaultSelectedStyle = null;
    };

    /**
    * Preserves the config
    */
    LayoutThemeApp.prototype._saveConfig = function(newConfig) {
        $.extend(this._config, newConfig);
        // sessionStorage.setItem('_HYPER_CONFIG_', JSON.stringify(this._config));
    },

    /**
     * Get the stored config
     */
    LayoutThemeApp.prototype._getStoredConfig = function() {
        var bodyConfig = this.body.data('layoutConfig');
        var config = DEFAULT_CONFIG;
        if (bodyConfig) {
            config['sideBarTheme'] = bodyConfig['leftSideBarTheme'];
            config['isBoxed'] = bodyConfig['layoutBoxed'];
            config['isCondensed'] = bodyConfig['leftSidebarCondensed'];
            config['isScrollable'] = bodyConfig['leftSidebarScrollable'];
            config['isDarkModeEnabled'] = bodyConfig['darkMode'];
        }
        return config;
    },

    /**
    * Apply the given config and sets the layout and theme
    */
    LayoutThemeApp.prototype._applyConfig = function() {
        var self = this;

        // getting the saved config if available
        this._config = this._getStoredConfig();

        // activate menus
        $.LeftSidebar.init();

        // sets the theme
        switch (self._config.sideBarTheme) {
            case SIDEBAR_THEME_DARK: {
                self.activateDarkSidebarTheme();
                break;
            }
            case SIDEBAR_THEME_LIGHT: {
                self.activateLightSidebarTheme();
                break;
            }
        }

        // enable or disable the dark mode
        if (self._config.isDarkModeEnabled)
            self.activateDarkMode();
        else
            self.deactivateDarkMode();

        // sets the boxed
        if (self._config.isBoxed) self.activateBoxed();

        // sets condensed view
        if (self._config.isCondensed) self.activateCondensedSidebar();

        // sets scrollable navbar
        if (self._config.isScrollable) self.activateScrollableSidebar();
    },

    /**
     * Initilizes the layout
     */
    LayoutThemeApp.prototype._adjustLayout = function() {
        // in case of small size, add class enlarge to have minimal menu
        if (this.window.width() >= 767 && this.window.width() <= 1028) {
            this.activateCondensedSidebar(true);
        } else {
            var config = this._getStoredConfig();
            if (!config.isCondensed && !config.isScrollable)
                this.deactivateCondensedSidebar();
        }
    },

    /**
     * Activate fluid mode
     */
    LayoutThemeApp.prototype.activateFluid = function() {
        this._saveConfig({ isBoxed: false });
        this.body.attr('data-layout-mode', 'fluid');
    },

    /**
     * Activate boxed mode
     */
    LayoutThemeApp.prototype.activateBoxed = function() {
        this._saveConfig({ isBoxed: true });
        this.body.attr('data-layout-mode', 'boxed');
    },

    /**
     * Activates the condensed side bar
     */
    LayoutThemeApp.prototype.activateCondensedSidebar = function(ignoreToStore) {
        if (!ignoreToStore) {
            this._saveConfig({
                isCondensed: true,
                isScrollable: false
            });
        }
        $.LeftSidebar.activateCondensedSidebar();
    },

    /**
     * Deactivates the condensed side bar
     */
    LayoutThemeApp.prototype.deactivateCondensedSidebar = function() {
        this._saveConfig({ isCondensed: false });
        $.LeftSidebar.deactivateCondensedSidebar();
    }

    /**
     * Activates the scrollable sidenar
     */
    LayoutThemeApp.prototype.activateScrollableSidebar = function() {
        this._saveConfig({ isScrollable: true, isCondensed: false });
        $.LeftSidebar.activateScrollableSidebar();
    },

    /**
     * Deactivates the scrollable sidenar
     */
    LayoutThemeApp.prototype.deactivateScrollableSidebar = function() {
        this._saveConfig({ isScrollable: false });
        $.LeftSidebar.deactivateScrollableSidebar();
    },

    /**
     * Activates the default theme
     */
    LayoutThemeApp.prototype.activateDefaultSidebarTheme = function() {
        $.LeftSidebar.activateDefaultTheme();
        this._saveConfig({ sideBarTheme: SIDEBAR_THEME_DEFAULT });
    },

    /**
     * Activates the light theme
     */
    LayoutThemeApp.prototype.activateLightSidebarTheme = function() {
        // this._resetLayout();
        $.LeftSidebar.activateLightTheme();
        this._saveConfig({ sideBarTheme: SIDEBAR_THEME_LIGHT });
    },

    /**
     * Activates the dark theme
     */
    LayoutThemeApp.prototype.activateDarkSidebarTheme = function() {
        // this._resetLayout();
        $.LeftSidebar.activateDarkTheme();
        this._saveConfig({ sideBarTheme: SIDEBAR_THEME_DARK });
    },

    /**
     * toggle the dark mode
     */
    LayoutThemeApp.prototype.activateDarkMode = function() {
        $("#light-style").attr("disabled", true);
        $("#dark-style").attr("disabled", false);
        $.LeftSidebar.activateDarkTheme();
        this._saveConfig({ isDarkModeEnabled: true, sideBarTheme: SIDEBAR_THEME_DARK });
    }

    /**
     * Deactivate the dark mode
     */
    LayoutThemeApp.prototype.deactivateDarkMode = function() {
        $("#light-style").attr("disabled", false);
        $("#dark-style").attr("disabled", true);
        this._saveConfig({ isDarkModeEnabled: false });
    }

    /**
     * Clear out the saved config
     */
    LayoutThemeApp.prototype.clearSavedConfig = function() {
        this._config = DEFAULT_CONFIG;
    },

    /**
     * Gets the config
     */
    LayoutThemeApp.prototype.getConfig = function() {
        return this._config;
    },

    /**
     * Reset to default
     */
    LayoutThemeApp.prototype.reset = function(callback) {
        this.clearSavedConfig();
        
        var self = this;
        if($("#main-style-container").length) {
            self.defaultSelectedStyle = $("#main-style-container").attr('href');
        }
        self.deactivateCondensedSidebar();
        self.deactivateDarkMode();
        self.activateDefaultSidebarTheme();
        self.activateFluid();
        // calling the call back to let the caller know that it's done
        callback();
    },

    /**
     * 
     */
    LayoutThemeApp.prototype.init = function() {
        var self = this;

        if($("#main-style-container").length) {
            self.defaultSelectedStyle = $("#main-style-container").attr('href');
        }
        
        // initilize the menu
        this._applyConfig();

        // adjust layout based on width
        this._adjustLayout();

        // on window resize, make menu flipped automatically
        this.window.on('resize', function (e) {
            e.preventDefault();
            self._adjustLayout();
        });

        // if horizontal layout - activate topbar
        var layout = $('body').data('layout');
        if (layout && layout === 'topnav') {
            $.Topbar.init();
        }
    },

    $.LayoutThemeApp = new LayoutThemeApp, $.LayoutThemeApp.Constructor = LayoutThemeApp
}(window.jQuery);
/**
 * Theme: Hyper - Responsive Bootstrap 4 Admin Dashboard
 * Author: Coderthemes
 * Module/App: Main Js
 */


!function($) {
    "use strict";

    /**
    Portlet Widget
    */
    var Portlet = function() {
        this.$body = $("body"),
        this.$portletIdentifier = ".card",
        this.$portletCloser = '.card a[data-toggle="remove"]',
        this.$portletRefresher = '.card a[data-toggle="reload"]'
    };

    //on init
    Portlet.prototype.init = function() {
        // Panel closest
        var $this = this;
        $(document).on("click",this.$portletCloser, function (ev) {
            ev.preventDefault();
            var $portlet = $(this).closest($this.$portletIdentifier);
                var $portlet_parent = $portlet.parent();
            $portlet.remove();
            if ($portlet_parent.children().length == 0) {
                $portlet_parent.remove();
            }
        });

        // Panel Reload
        $(document).on("click",this.$portletRefresher, function (ev) {
            ev.preventDefault();
            var $portlet = $(this).closest($this.$portletIdentifier);
            // This is just a simulation, nothing is going to be reloaded
            $portlet.append('<div class="card-disabled"><div class="card-portlets-loader"></div></div>');
            var $pd = $portlet.find('.card-disabled');
            setTimeout(function () {
                $pd.fadeOut('fast', function () {
                    $pd.remove();
                });
            }, 500 + 300 * (Math.random() * 5));
        });
    },
    //
    $.Portlet = new Portlet, $.Portlet.Constructor = Portlet
    
}(window.jQuery),

function($) {
    'use strict';

    var AdvanceFormApp = function() {
        this.$body = $('body'),
        this.$window = $(window)
    };


    /** 
     * Initlizes the select2
    */
    AdvanceFormApp.prototype.initSelect2 = function() {
        // Select2
        $('[data-toggle="select2"]').select2();
    },

    /** 
     * Initlized mask
    */
    AdvanceFormApp.prototype.initMask = function() {
        $('[data-toggle="input-mask"]').each(function (idx, obj) {
            var maskFormat = $(obj).data("maskFormat");
            var reverse = $(obj).data("reverse");
            if (reverse != null)
                $(obj).mask(maskFormat, {'reverse': reverse});
            else
                $(obj).mask(maskFormat);
        });
    },

    // Datetime and date range picker
    AdvanceFormApp.prototype.initDateRange = function() {
        var defaultOptions = {
            "cancelClass": "btn-light",
            "applyButtonClasses": "btn-success"
        };

        // date pickers
        $('[data-toggle="date-picker"]').each(function (idx, obj) {
            var objOptions = $.extend({}, defaultOptions, $(obj).data());
            $(obj).daterangepicker(objOptions);
        });

        //date pickers ranges only
        var start = moment().subtract(29, 'days');
        var end = moment();
        var defaultRangeOptions = {
            startDate: start,
            endDate: end,
            ranges: {
            'Today': [moment(), moment()],
            'Yesterday': [moment().subtract(1, 'days'), moment().subtract(1, 'days')],
            'Last 7 Days': [moment().subtract(6, 'days'), moment()],
            'Last 30 Days': [moment().subtract(29, 'days'), moment()],
            'This Month': [moment().startOf('month'), moment().endOf('month')],
            'Last Month': [moment().subtract(1, 'month').startOf('month'), moment().subtract(1, 'month').endOf('month')]
            }
        };

        $('[data-toggle="date-picker-range"]').each(function (idx, obj) {
            var objOptions = $.extend({}, defaultRangeOptions, $(obj).data());
            var target = objOptions["targetDisplay"];
            //rendering
            $(obj).daterangepicker(objOptions, function(start, end) {
                if (target)
                    $(target).html(start.format('MMMM D, YYYY') + ' - ' + end.format('MMMM D, YYYY'));
            });
        });
    },

    // time picker
    AdvanceFormApp.prototype.initTimePicker = function() {
        var defaultOptions = {
            "showSeconds": true,
            "icons": {
                "up": "mdi mdi-chevron-up",
                "down": "mdi mdi-chevron-down"
            }
        };

        // time picker
        $('[data-toggle="timepicker"]').each(function (idx, obj) {
            var objOptions = $.extend({}, defaultOptions, $(obj).data());
            $(obj).timepicker(objOptions);
        });
    },

    // touchspin
    AdvanceFormApp.prototype.initTouchspin = function() {
        var defaultOptions = {
        };

        // touchspin
        $('[data-toggle="touchspin"]').each(function (idx, obj) {
            var objOptions = $.extend({}, defaultOptions, $(obj).data());
            $(obj).TouchSpin(objOptions);
        });
    },

    // maxlength
    AdvanceFormApp.prototype.initMaxlength = function() {
        var defaultOptions = {
            warningClass: "badge badge-success",
            limitReachedClass: "badge badge-danger",
            separator: ' out of ',
            preText: 'You typed ',
            postText: ' chars available.',
            placement: 'bottom',
        };

        // maxlength
        $('[data-toggle="maxlength"]').each(function (idx, obj) {
            var objOptions = $.extend({}, defaultOptions, $(obj).data());
            $(obj).maxlength(objOptions);
        });
    },

    /** 
     * Initilize
    */
   AdvanceFormApp.prototype.init = function() {
        this.initSelect2();
        this.initMask();
        this.initDateRange();
        this.initTimePicker();
        this.initTouchspin();
        this.initMaxlength();
    },

    $.AdvanceFormApp = new AdvanceFormApp, $.AdvanceFormApp.Constructor = AdvanceFormApp


}(window.jQuery),

function($) {
    'use strict';

    var NotificationApp = function() {
    };


    /**
     * Send Notification
     * @param {*} heading heading text
     * @param {*} body body text
     * @param {*} position position e.g top-right, top-left, bottom-left, etc
     * @param {*} loaderBgColor loader background color
     * @param {*} icon icon which needs to be displayed
     * @param {*} hideAfter automatically hide after seconds
     * @param {*} stack 
     */
    NotificationApp.prototype.send = function(heading, body, position, loaderBgColor, icon, hideAfter, stack, showHideTransition) {
        // default      
        if (!hideAfter)
            hideAfter = 3000;
        if (!stack)
            stack = 1;

        var options = {
            heading: heading,
            text: body,
            position: position,
            loaderBg: loaderBgColor,
            icon: icon,
            hideAfter: hideAfter,
            stack: stack
        };

        if(showHideTransition)
            options.showHideTransition = showHideTransition;
        else
            options.showHideTransition = 'fade';

        $.toast().reset('all');
        $.toast(options);
    },

    $.NotificationApp = new NotificationApp, $.NotificationApp.Constructor = NotificationApp

}(window.jQuery),

function($) {
    "use strict";

    var Components = function() {};

    //initializing tooltip
    Components.prototype.initTooltipPlugin = function() {
        $.fn.tooltip && $('[data-toggle="tooltip"]').tooltip()
    },

    //initializing popover
    Components.prototype.initPopoverPlugin = function() {
        $.fn.popover && $('[data-toggle="popover"]').popover()
    },

    //initializing toast
    Components.prototype.initToastPlugin = function() {
        $.fn.toast && $('[data-toggle="toast"]').toast()
    },

    //initializing form validation
    Components.prototype.initFormValidation = function() {
        $(".needs-validation").on('submit', function (event) {
            $(this).addClass('was-validated');
            if ($(this)[0].checkValidity() === false) {
                event.preventDefault();
                event.stopPropagation();
                return false;
            }
            return true;
        });
    },
    Components.prototype.initSyntaxHighlight = function() {
        //syntax
        var entityMap = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': '&quot;',
            "'": '&#39;',
            "/": '&#x2F;'
        };
        function escapeHtml(string) {
            return String(string).replace(/[&<>"'\/]/g, function (s) {
                return entityMap[s];
            });
        }

        $(document).ready(function(e) {
            document.querySelectorAll("pre span.escape").forEach(function (element, n) {
                if (element.classList.contains("escape")) {
                  var text = element.innerText;
                } else {
                  var text = element.innerText;
                }
                text = text.replace(/^\n/, '').trimRight();// goodbye starting whitespace
                var to_kill = Infinity;
                var lines = text.split("\n");
                for (var i = 0; i < lines.length; i++) {
                  if (!lines[i].trim()) { continue; }
                  to_kill = Math.min(lines[i].search(/\S/), to_kill);
                }
                var out = [];
                for (var i = 0; i < lines.length; i++) {
                  out.push(lines[i].replace(new RegExp("^ {" + to_kill + "}", "g"), ""));
                }
                element.innerText = out.join("\n");
            });
        
            document.querySelectorAll('pre span.escape').forEach(function(block) {
                hljs.highlightBlock(block);
            });
        });
    },


    //initilizing
    Components.prototype.init = function() {
        this.initTooltipPlugin(),
        this.initPopoverPlugin(),
        this.initToastPlugin(),
        this.initFormValidation(),
        this.initSyntaxHighlight();
    },

    $.Components = new Components, $.Components.Constructor = Components

}(window.jQuery),


function ($) {
    'use strict';

    var App = function () {
        this.$body = $('body'),
        this.$window = $(window)
    };

    /**
     * Activates the default theme
     */
    App.prototype.activateDefaultSidebarTheme = function() {
        $.LayoutThemeApp.activateDefaultSidebarTheme();
    },

    /**
     * Activates the light theme
     */
    App.prototype.activateLightSidebarTheme = function() {
        $.LayoutThemeApp.activateLightSidebarTheme();
    },

    /**
     * Activates the dark theme
     */
    App.prototype.activateDarkSidebarTheme = function() {
        $.LayoutThemeApp.activateDarkSidebarTheme();
    },

    /**
     * Activates the condensed sidebar
     */
    App.prototype.activateCondensedSidebar = function() {
        $.LayoutThemeApp.activateCondensedSidebar();
    },

    /**
     * Deactivates the condensed sidebar
     */
    App.prototype.deactivateCondensedSidebar = function() {
        $.LayoutThemeApp.deactivateCondensedSidebar();
    },

    /**
     * Activates the scrollable sidebar
     */
    App.prototype.activateScrollableSidebar = function() {
        $.LayoutThemeApp.activateScrollableSidebar();
    },

    /**
     * Deactivates the scrollable
     */
    App.prototype.deactivateScrollableSidebar = function() {
        $.LayoutThemeApp.deactivateScrollableSidebar();
    },

    /**
     * Activates the boxed mode
     */
    App.prototype.activateBoxed = function() {
        $.LayoutThemeApp.activateBoxed();
    },

    /**
     * Activate the fluid mode
     */
    App.prototype.activateFluid = function() {
        $.LayoutThemeApp.activateFluid();
    },

    /**
     * Toggle the dark mode
     */
    App.prototype.activateDarkMode = function() {
        $.LayoutThemeApp.activateDarkMode();
    },

    /**
     * Deactivate the dark mode
     */
    App.prototype.deactivateDarkMode = function() {
        $.LayoutThemeApp.deactivateDarkMode();
    },

    /**
     * clear the saved layout related settings
     */
    App.prototype.clearSavedConfig = function() {
        $.LayoutThemeApp.clearSavedConfig();
    },

    /**
     * Gets the layout config
     */
    App.prototype.getLayoutConfig = function() {
        return $.LayoutThemeApp.getConfig();
    }

    /**
     * Reset the layout
     */
    App.prototype.resetLayout = function(callback) {
        $.LayoutThemeApp.reset(callback);
    },
    
    /**
     * initilizing
     */
    App.prototype.init = function () {
        $.LayoutThemeApp.init();

         // remove loading
        setTimeout(function() {
            document.body.classList.remove('loading');
        }, 400);

        $.RightBar.init();

        // showing the sidebar on load if user is visiting the page first time only
        var bodyConfig = this.$body.data('layoutConfig');
        if (window.sessionStorage && bodyConfig && bodyConfig.hasOwnProperty('showRightSidebarOnStart') && bodyConfig['showRightSidebarOnStart']) {
            var alreadyVisited = sessionStorage.getItem("_HYPER_VISITED_");
            if (!alreadyVisited) {
                $.RightBar.toggleRightSideBar();
                sessionStorage.setItem("_HYPER_VISITED_", true);
            }
        }
        
        //creating portles
        $.Portlet.init();
        $.AdvanceFormApp.init();
        $.Components.init();

        // loader - Preloader
        $(window).on('load', function () {
            $('#status').fadeOut();
            $('#preloader').delay(350).fadeOut('slow');
        });
    },

    $.App = new App, $.App.Constructor = App
}(window.jQuery),

//initializing main application module
function ($) {
    "use strict";
    $.App.init();
}(window.jQuery);