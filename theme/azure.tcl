# Azure Theme for ttk - Simplified Version
# Modern Windows-style theme with Azure color scheme

package require Tk 8.6

namespace eval ttk::theme::azure {
    variable version 2.0
    package provide ttk::theme::azure $version

    ttk::style theme create azure -parent clam -settings {
        # Azure Light Theme Colors
        ttk::style configure . \
            -background "#ffffff" \
            -foreground "#000000" \
            -bordercolor "#d1d1d1" \
            -selectbackground "#0078d4" \
            -selectforeground "#ffffff" \
            -fieldbackground "#ffffff" \
            -font {-family "Segoe UI" -size 9}

        # Button styling
        ttk::style configure TButton \
            -background "#e1e1e1" \
            -foreground "#000000" \
            -borderwidth 1 \
            -focuscolor "#0078d4" \
            -padding {10 5}

        ttk::style map TButton \
            -background [list \
                active "#e3f2fd" \
                pressed "#bbdefb" \
                disabled "#f5f5f5"]

        # Entry styling
        ttk::style configure TEntry \
            -fieldbackground "#ffffff" \
            -borderwidth 1 \
            -insertcolor "#000000"

        ttk::style map TEntry \
            -fieldbackground [list \
                readonly "#f0f0f0"] \
            -bordercolor [list \
                focus "#0078d4"]

        # Treeview styling
        ttk::style configure Treeview \
            -background "#ffffff" \
            -foreground "#000000" \
            -fieldbackground "#ffffff"

        ttk::style configure Treeview.Heading \
            -background "#f0f0f0" \
            -foreground "#000000"

        ttk::style map Treeview \
            -background [list selected "#e3f2fd"]

        # Notebook styling
        ttk::style configure TNotebook.Tab \
            -background "#e1e1e1" \
            -foreground "#000000" \
            -padding {10 5}

        ttk::style map TNotebook.Tab \
            -background [list \
                selected "#ffffff" \
                active "#e3f2fd"]

        # Frame styling
        ttk::style configure TFrame \
            -background "#ffffff"

        # LabelFrame styling
        ttk::style configure TLabelframe \
            -background "#ffffff"
        ttk::style configure TLabelframe.Label \
            -background "#ffffff" \
            -foreground "#000000"

        # Progressbar styling
        ttk::style configure TProgressbar \
            -background "#0078d4" \
            -troughcolor "#e0e0e0"

        # Combobox styling
        ttk::style configure TCombobox \
            -fieldbackground "#ffffff" \
            -borderwidth 1

        ttk::style map TCombobox \
            -fieldbackground [list \
                readonly "#f0f0f0"] \
            -bordercolor [list \
                focus "#0078d4"]
    }
}

# Dark theme variant
namespace eval ttk::theme::azure-dark {
    variable version 2.0
    package provide ttk::theme::azure-dark $version

    ttk::style theme create azure-dark -parent clam -settings {
        # Azure Dark Theme Colors
        ttk::style configure . \
            -background "#2b2b2b" \
            -foreground "#ffffff" \
            -bordercolor "#404040" \
            -selectbackground "#0078d4" \
            -selectforeground "#ffffff" \
            -fieldbackground "#3c3c3c" \
            -font {-family "Segoe UI" -size 9}

        # Button styling
        ttk::style configure TButton \
            -background "#404040" \
            -foreground "#ffffff" \
            -borderwidth 1 \
            -focuscolor "#0078d4" \
            -padding {10 5}

        ttk::style map TButton \
            -background [list \
                active "#0078d4" \
                pressed "#106ebe" \
                disabled "#2b2b2b"]

        # Entry styling
        ttk::style configure TEntry \
            -fieldbackground "#3c3c3c" \
            -borderwidth 1 \
            -insertcolor "#ffffff"

        ttk::style map TEntry \
            -fieldbackground [list \
                readonly "#2b2b2b"] \
            -bordercolor [list \
                focus "#0078d4"]

        # Treeview styling
        ttk::style configure Treeview \
            -background "#3c3c3c" \
            -foreground "#ffffff" \
            -fieldbackground "#3c3c3c"

        ttk::style configure Treeview.Heading \
            -background "#404040" \
            -foreground "#ffffff"

        ttk::style map Treeview \
            -background [list selected "#0078d4"]

        # Notebook styling
        ttk::style configure TNotebook.Tab \
            -background "#404040" \
            -foreground "#ffffff" \
            -padding {10 5}

        ttk::style map TNotebook.Tab \
            -background [list \
                selected "#2b2b2b" \
                active "#0078d4"]

        # Frame styling
        ttk::style configure TFrame \
            -background "#2b2b2b"

        # LabelFrame styling
        ttk::style configure TLabelframe \
            -background "#2b2b2b"
        ttk::style configure TLabelframe.Label \
            -background "#2b2b2b" \
            -foreground "#ffffff"

        # Progressbar styling
        ttk::style configure TProgressbar \
            -background "#0078d4" \
            -troughcolor "#404040"

        # Combobox styling
        ttk::style configure TCombobox \
            -fieldbackground "#3c3c3c" \
            -borderwidth 1

        ttk::style map TCombobox \
            -fieldbackground [list \
                readonly "#2b2b2b"] \
            -bordercolor [list \
                focus "#0078d4"]
    }
}