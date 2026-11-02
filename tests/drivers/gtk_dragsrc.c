/*
 * GTK 3 drag source for tests/cases/regress_gtk_mac.py, standing in for a file manager:
 * a 160x100 window titled "gz-dragsrc" at (0, 0) that drags the file named on the command
 * line as text/uri-list. Prints "end" on stdout (flushed) when a drag is over, whether the
 * target took the files, refused them or the drag was canceled.
 *
 *   cc gtk_dragsrc.c -o gtk_dragsrc $(pkg-config --cflags --libs gtk+-3.0)
 */
#include <gtk/gtk.h>
#include <stdio.h>

static char *s_uri;

static void on_get(GtkWidget *w, GdkDragContext *c, GtkSelectionData *sd, guint info, guint t, gpointer u)
{
    char *uris[2] = { s_uri, NULL };
    gtk_selection_data_set_uris(sd, uris);
}

static void on_end(GtkWidget *w, GdkDragContext *c, gpointer u)
{
    printf("end\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    gtk_init(&argc, &argv);
    if (argc < 2) return 2;
    GFile *f = g_file_new_for_path(argv[1]);
    s_uri = g_file_get_uri(f);
    g_object_unref(f);
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "gz-dragsrc");
    gtk_window_set_default_size(GTK_WINDOW(win), 160, 100);
    gtk_window_move(GTK_WINDOW(win), 0, 0);
    GtkWidget *eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), gtk_label_new("drag me"));
    gtk_container_add(GTK_CONTAINER(win), eb);
    static const GtkTargetEntry te[] = { { "text/uri-list", 0, 0 } };
    gtk_drag_source_set(eb, GDK_BUTTON1_MASK, te, 1, GDK_ACTION_COPY);
    g_signal_connect(eb, "drag-data-get", G_CALLBACK(on_get), NULL);
    g_signal_connect(eb, "drag-end", G_CALLBACK(on_end), NULL);
    g_signal_connect(win, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    gtk_widget_show_all(win);
    gtk_main();
    g_free(s_uri);
    return 0;
}
