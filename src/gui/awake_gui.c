/*
 * awake_gui — A-Awake 모니터링 화면 (GTK 3)
 *
 *   사용법: awake_gui <감시할 폴더> <분석 결과 폴더>
 *   (scripts/run_gui.sh가 config와 같은 기본 경로로 실행해 준다)
 *
 *   [감시] 탭   : 감시기(awake_monitor) 시작/중지, 감시기 출력 실시간 표시
 *   [판정 결과] 탭: 결과 폴더의 메일별 JSON을 읽어 정상/악성 목록 표시
 *
 * 예전 시안 4개(tab/2tab/3tab/test)를 하나로 합쳤다. 감시기는 이 실행 파일과 같은 폴더의
 * awake_monitor를 쓰고, 중지할 때 SIGTERM을 보내 정상 종료시킨다.
 */
#include <gtk/gtk.h>
#include <signal.h>
#include <string.h>

typedef struct {
    const char *watch_dir;
    const char *result_dir;
    GPid pid;
    GtkWidget *toggle;
    GtkWidget *status;
    GtkTextBuffer *log;
    GtkWidget *log_view;
    GtkListStore *results;
} App;

static void log_append(App *app, const char *text) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(app->log, &end);
    gtk_text_buffer_insert(app->log, &end, text, -1);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(app->log_view), gtk_text_buffer_get_insert(app->log), 0, FALSE, 0, 0);
    gtk_text_buffer_get_end_iter(app->log, &end);
    gtk_text_buffer_place_cursor(app->log, &end);
}

static void set_running(App *app, gboolean running) {
    gtk_button_set_label(GTK_BUTTON(app->toggle), running ? "감시 중지" : "감시 시작");
    gtk_label_set_text(GTK_LABEL(app->status), running ? "상태: 감시 중" : "상태: 정지");
}

static gboolean on_output(GIOChannel *ch, GIOCondition cond, gpointer data) {
    App *app = data;
    if (cond & G_IO_IN) {
        gchar *line = NULL;
        gsize len = 0;
        GIOStatus st = g_io_channel_read_line(ch, &line, &len, NULL, NULL);
        if (st == G_IO_STATUS_NORMAL && line != NULL) {
            log_append(app, line);
            g_free(line);
            return TRUE;
        }
        g_free(line);
        if (st == G_IO_STATUS_AGAIN) return TRUE;
    }
    g_io_channel_unref(ch);
    return FALSE; /* EOF·오류: 감시 해제 */
}

static void watch_fd(App *app, gint fd) {
    GIOChannel *ch = g_io_channel_unix_new(fd);
    g_io_channel_set_close_on_unref(ch, TRUE);
    g_io_channel_set_encoding(ch, NULL, NULL); /* 바이트 그대로 (UTF-8 출력) */
    g_io_add_watch(ch, G_IO_IN | G_IO_HUP | G_IO_ERR, on_output, app);
}

static void on_child_exit(GPid pid, gint status, gpointer data) {
    App *app = data;
    g_spawn_close_pid(pid);
    app->pid = 0;
    set_running(app, FALSE);
    log_append(app, g_spawn_check_wait_status(status, NULL) ? "[gui] 감시기가 종료되었습니다\n"
                                                            : "[gui] 감시기가 오류로 종료되었습니다\n");
}

static gchar *monitor_path(void) {
    gchar *exe = g_file_read_link("/proc/self/exe", NULL);
    gchar *dir = exe ? g_path_get_dirname(exe) : g_strdup(".");
    gchar *path = g_build_filename(dir, "awake_monitor", NULL);
    g_free(exe);
    g_free(dir);
    return path;
}

static void on_toggle(GtkWidget *button, gpointer data) {
    (void)button;
    App *app = data;
    if (app->pid != 0) {
        kill(app->pid, SIGTERM); /* 처리 중인 메일을 마친 뒤 종료된다 */
        log_append(app, "[gui] 중지 요청\n");
        return;
    }

    gchar *mon = monitor_path();
    gchar *argv[] = {mon, (gchar *)app->watch_dir, NULL};
    gint out_fd, err_fd;
    GError *err = NULL;
    if (!g_spawn_async_with_pipes(NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
                                  &app->pid, NULL, &out_fd, &err_fd, &err)) {
        gchar *msg = g_strdup_printf("[gui] 감시기 실행 실패: %s\n", err->message);
        log_append(app, msg);
        g_free(msg);
        g_error_free(err);
        app->pid = 0;
    } else {
        watch_fd(app, out_fd);
        watch_fd(app, err_fd);
        g_child_watch_add(app->pid, on_child_exit, app);
        set_running(app, TRUE);
    }
    g_free(mon);
}

/* 결과 JSON에서 "키": "값" 한 개를 꺼낸다 (pipeline.py가 쓰는 고정 형식만 다룬다) */
static gchar *json_string_field(const gchar *json, const gchar *key) {
    gchar *needle = g_strdup_printf("\"%s\": \"", key);
    const gchar *p = strstr(json, needle);
    gchar *out = NULL;
    if (p != NULL) {
        p += strlen(needle);
        const gchar *q = p;
        while (*q && !(*q == '"' && q[-1] != '\\')) q++;
        out = g_strndup(p, q - p);
    }
    g_free(needle);
    return out ? out : g_strdup("");
}

static void on_refresh(GtkWidget *button, gpointer data) {
    (void)button;
    App *app = data;
    gtk_list_store_clear(app->results);

    GDir *dir = g_dir_open(app->result_dir, 0, NULL);
    if (dir == NULL) return;
    const gchar *name;
    while ((name = g_dir_read_name(dir)) != NULL) {
        if (!g_str_has_suffix(name, ".json")) continue;
        gchar *path = g_build_filename(app->result_dir, name, NULL);
        gchar *json = NULL;
        if (g_file_get_contents(path, &json, NULL, NULL)) {
            gchar *decision = json_string_field(json, "final_decision");
            gchar *subject = json_string_field(json, "subject");
            GtkTreeIter it;
            gtk_list_store_append(app->results, &it);
            gtk_list_store_set(app->results, &it,
                               0, g_strcmp0(decision, "malicious") == 0 ? "악성" : "정상",
                               1, subject, 2, name, -1);
            g_free(decision);
            g_free(subject);
            g_free(json);
        }
        g_free(path);
    }
    g_dir_close(dir);
}

static GtkWidget *monitor_tab(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 8);

    gchar *where = g_strdup_printf("감시 폴더: %s", app->watch_dir);
    gtk_box_pack_start(GTK_BOX(box), gtk_label_new(where), FALSE, FALSE, 0);
    g_free(where);

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    app->toggle = gtk_button_new_with_label("감시 시작");
    app->status = gtk_label_new("상태: 정지");
    g_signal_connect(app->toggle, "clicked", G_CALLBACK(on_toggle), app);
    gtk_box_pack_start(GTK_BOX(row), app->toggle, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(row), app->status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 0);

    app->log_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app->log_view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(app->log_view), TRUE);
    app->log = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->log_view));
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), app->log_view);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);
    return box;
}

static GtkWidget *results_tab(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(box), 8);

    GtkWidget *refresh = gtk_button_new_with_label("새로고침");
    g_signal_connect(refresh, "clicked", G_CALLBACK(on_refresh), app);
    gtk_box_pack_start(GTK_BOX(box), refresh, FALSE, FALSE, 0);

    app->results = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    GtkWidget *tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(app->results));
    const char *titles[] = {"판정", "제목", "결과 파일"};
    for (int i = 0; i < 3; i++) {
        GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes(
            titles[i], gtk_cell_renderer_text_new(), "text", i, NULL);
        gtk_tree_view_column_set_resizable(col, TRUE);
        gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col);
    }
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), tree);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);
    return box;
}

static void on_destroy(GtkWidget *w, gpointer data) {
    (void)w;
    App *app = data;
    if (app->pid != 0) kill(app->pid, SIGTERM);
    gtk_main_quit();
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);
    if (argc != 3) {
        g_printerr("사용법: %s <감시할 폴더> <분석 결과 폴더>\n", argv[0]);
        return 1;
    }

    static App app;
    app.watch_dir = argv[1];
    app.result_dir = argv[2];

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "A-Awake — 악성 이메일 탐지");
    gtk_window_set_default_size(GTK_WINDOW(window), 900, 600);

    GtkWidget *notebook = gtk_notebook_new();
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), monitor_tab(&app), gtk_label_new("감시"));
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), results_tab(&app), gtk_label_new("판정 결과"));
    gtk_container_add(GTK_CONTAINER(window), notebook);

    g_signal_connect(window, "destroy", G_CALLBACK(on_destroy), &app);
    gtk_widget_show_all(window);
    on_refresh(NULL, &app);
    gtk_main();
    return 0;
}
