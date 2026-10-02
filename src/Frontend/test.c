#include <gtk/gtk.h>
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>

// 전역 변수 선언
GtkWidget *text_view;
GtkTextBuffer *text_buffer;

// 파일 내용 표시 함수
static void display_file_content(const char *file_path) {
    FILE *file = fopen(file_path, "r");
    if (file) {
        fseek(file, 0, SEEK_END);
        long fsize = ftell(file);
        if (fsize < 0) {
            gtk_text_buffer_set_text(text_buffer, "Failed to determine file size.", -1);
            fclose(file);
            return;
        }

        fseek(file, 0, SEEK_SET);

        if (fsize == 0) {
            gtk_text_buffer_set_text(text_buffer, "File is empty.", -1);
            fclose(file);
            return;
        }

        char *content = malloc(fsize + 1);
        if (content == NULL) {
            gtk_text_buffer_set_text(text_buffer, "Failed to allocate memory.", -1);
            fclose(file);
            return;
        }

        size_t read_size = fread(content, 1, fsize, file);
        if (read_size != fsize) {
            gtk_text_buffer_set_text(text_buffer, "Failed to read entire file.", -1);
            free(content);
            fclose(file);
            return;
        }

        content[fsize] = '\0';  // Null-terminate the content
        fclose(file);

        gtk_text_buffer_set_text(text_buffer, content, -1);
        free(content);
    } else {
        gtk_text_buffer_set_text(text_buffer, "Failed to open file.", -1);
    }
}

// 디렉터리 변경 감지 콜백
static void on_directory_changed(GFileMonitor *monitor, GFile *file, GFile *other_file, GFileMonitorEvent event_type, gpointer user_data) {
    if (event_type == G_FILE_MONITOR_EVENT_CREATED) {
        char *file_path = g_file_get_path(file);
        if (file_path) {
            g_print("File created: %s\n", file_path);
            display_file_content(file_path);
            g_free(file_path);
        } else {
            g_print("Failed to get file path.\n");
        }
    }
}

// 파일 모니터링 초기화
static void init_file_monitor(const char *monitor_path) {
    GFile *directory = g_file_new_for_path(monitor_path);
    if (!directory) {
        g_print("Failed to monitor directory: %s\n", monitor_path);
        return;
    }

    GFileMonitor *monitor = g_file_monitor_directory(directory, G_FILE_MONITOR_NONE, NULL, NULL);
    if (!monitor) {
        g_print("Failed to create file monitor for directory: %s\n", monitor_path);
        g_object_unref(directory);
        return;
    }

    g_signal_connect(monitor, "changed", G_CALLBACK(on_directory_changed), NULL);
    g_object_unref(directory);
}

// GTK 애플리케이션 활성화
static void activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window;
    GtkWidget *scrolled_window;

    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "File Monitor");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);

    scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(window), scrolled_window);

    text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
    text_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    gtk_container_add(GTK_CONTAINER(scrolled_window), text_view);

    gtk_widget_show_all(window);

    // 모니터링할 디렉터리 설정
    init_file_monitor("/home/fol/A_Awake/monitor_test");
}

int main(int argc, char **argv) {
    GtkApplication *app;
    int status;

    app = gtk_application_new("com.example.FileMonitor", G_APPLICATION_FLAGS_NONE);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}

