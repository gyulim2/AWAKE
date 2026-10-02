#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

// 백그라운드에서 실행되는 프로세스의 PID
GPid c_program_pid = 0;
gint c_program_process_group = 0;

// 버튼 클릭 시 호출되는 콜백 함수
static void on_button_clicked(GtkWidget *widget, gpointer data) {
    const char *current_label = gtk_button_get_label(GTK_BUTTON(widget));
    
    if (strcmp(current_label, "Run") == 0) {
        // C 프로그램을 백그라운드에서 실행
        const gchar *argv[] = {"../Backend/C_monitoring", NULL};  // 실행할 C 프로그램
        GError *error = NULL;

        g_print("Starting C program...\n");
        
        // 새로운 프로세스 그룹에서 프로세스를 생성
        if (!g_spawn_async_with_pipes(NULL, (gchar **)argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH, NULL, NULL, &c_program_pid, NULL, NULL, NULL, &error)) {
            g_printerr("Failed to start C program: %s\n", error->message);
            g_error_free(error);
            return;
        }
        
        // 프로세스 그룹 ID 설정
        c_program_process_group = (gint)c_program_pid;
        setpgid(c_program_pid, c_program_process_group);

        // 버튼 라벨을 Stop으로 변경
        gtk_button_set_label(GTK_BUTTON(widget), "Stop");
        g_print("Button changed to Stop!\n");
    } else {
        // C 프로그램을 종료
        if (c_program_pid != 0) {
            g_print("Terminating C program with process group ID: %d\n", c_program_process_group);
            kill(-c_program_process_group, SIGTERM); // 프로세스 그룹 전체에 SIGTERM 신호 보내기
            c_program_pid = 0; // PID 초기화
        }

        // 버튼 라벨을 Run으로 변경
        gtk_button_set_label(GTK_BUTTON(widget), "Run");
        g_print("Button changed to Run!\n");
    }
}

// GUI 설정을 수행하는 함수
void setup_gui(GtkWidget **window, GtkWidget **notebook, GtkWidget **run_button) {
    GtkWidget *vbox1, *vbox2, *vbox3;
    GtkWidget *tab_label1, *tab_label2, *tab_label3;
    GtkWidget *label1, *label2, *label3;
    GtkWidget *version_label, *system_info_label;

    // 윈도우 생성
    *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(*window), "Notebook Example");
    gtk_container_set_border_width(GTK_CONTAINER(*window), 10);

    // 창 크기 설정: 화면의 절반 크기로 설정
    GdkDisplay *display = gdk_display_get_default();
    GdkMonitor *monitor = gdk_display_get_primary_monitor(display);
    GdkRectangle monitor_geometry;
    gdk_monitor_get_geometry(monitor, &monitor_geometry);

    gint screen_width = monitor_geometry.width;
    gint screen_height = monitor_geometry.height;

    gtk_window_set_default_size(GTK_WINDOW(*window), screen_width / 2, screen_height / 2);

    // 창을 화면 중앙에 위치시키기
    gtk_window_set_position(GTK_WINDOW(*window), GTK_WIN_POS_CENTER);

    // 노트북(탭) 생성
    *notebook = gtk_notebook_new();

    // 첫 번째 탭의 내용 설정
    vbox1 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    
    // A-Awake 도트 아트 텍스트 라벨 생성
    label1 = gtk_label_new(
        "  AAA    -    A w  w   A  k  k  eeeee\n"
        " A   A  - -  A A w  w  A A k k   e    \n"
        "AAAAAA - - AAAAA w w wAAAA kkk   eeee \n"
        "A   A  - - A   A w w wA   A k k   e   \n"
        "A   A   -  A   A  w w A   A k  k  eeeee"
    );

    // 프로그램 버전 정보 라벨 생성
    version_label = gtk_label_new("Program Version: 0.1v");

    // 시스템 버전 정보 라벨 생성
    system_info_label = gtk_label_new("C Program Version: 1.0");

    // Run 버튼 생성
    *run_button = gtk_button_new_with_label("Run");
    g_signal_connect(*run_button, "clicked", G_CALLBACK(on_button_clicked), NULL);

    // 라벨과 버튼을 첫 번째 탭의 수직 박스에 추가
    gtk_box_pack_start(GTK_BOX(vbox1), label1, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox1), version_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox1), system_info_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox1), *run_button, FALSE, FALSE, 0);

    // 첫 번째 탭의 제목 라벨
    tab_label1 = gtk_label_new("Tab 1");
    gtk_notebook_append_page(GTK_NOTEBOOK(*notebook), vbox1, tab_label1);

    // 두 번째 탭의 내용 설정
    label2 = gtk_label_new("This is the content of Tab 2");
    vbox2 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_box_pack_start(GTK_BOX(vbox2), label2, TRUE, TRUE, 0);

    tab_label2 = gtk_label_new("Tab 2");
    gtk_notebook_append_page(GTK_NOTEBOOK(*notebook), vbox2, tab_label2);

    // 세 번째 탭의 내용 설정
    label3 = gtk_label_new("This is the content of Tab 3");
    vbox3 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_box_pack_start(GTK_BOX(vbox3), label3, TRUE, TRUE, 0);

    tab_label3 = gtk_label_new("Tab 3");
    gtk_notebook_append_page(GTK_NOTEBOOK(*notebook), vbox3, tab_label3);

    // 노트북을 윈도우에 추가
    gtk_container_add(GTK_CONTAINER(*window), *notebook);

    // CSS 스타일 제공
    GtkCssProvider *css_provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css_provider,
        "#dot_art_label { font-family: Monospace; font-size: 24px; }", -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css_provider),
        GTK_STYLE_PROVIDER_PRIORITY_USER);

    // 윈도우 닫기 버튼 클릭 시 프로그램 종료
    g_signal_connect(*window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // 모든 위젯 표시
    gtk_widget_show_all(*window);
}

int main(int argc, char *argv[]) {
    GtkWidget *window;
    GtkWidget *notebook;
    GtkWidget *run_button;

    // GTK 초기화
    gtk_init(&argc, &argv);

    // GUI 설정
    setup_gui(&window, &notebook, &run_button);

    // GTK 메인 루프 실행
    gtk_main();

    return 0;
}

