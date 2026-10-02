#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

GIOChannel *io_channel;
GtkLabel *output_label;

// 백그라운드 프로세스의 출력을 읽는 콜백 함수
gboolean on_output(GIOChannel *channel, GIOCondition condition, gpointer data) {
    gchar *line = NULL;
    gsize len;
    GError *error = NULL;

    // 한 줄을 읽음
    GIOStatus status = g_io_channel_read_line(channel, &line, &len, NULL, &error);

    if (status == G_IO_STATUS_NORMAL) {
        // 읽은 줄을 라벨에 추가
        const gchar *current_text = gtk_label_get_text(output_label);
        gchar *new_text = g_strconcat(current_text, line, NULL);
        gtk_label_set_text(output_label, new_text);
        g_free(new_text);
        g_free(line);
    } else if (status == G_IO_STATUS_EOF) {
        // 프로세스가 종료되었을 때 EOF 처리
        gtk_label_set_text(output_label, "Process finished");
        return FALSE;
    }

    return TRUE;
}

// 버튼 클릭 시 실행되는 함수 (프로그램 시작)
static void on_button_clicked(GtkWidget *widget, gpointer data) {
    GError *error = NULL;
    GPid pid;
    gint stdout_fd;
    gchar *argv[] = {"../Backend/C_monitoring", NULL}; // 실행할 파일 경로

    // 백그라운드 프로세스 시작
    gboolean success = g_spawn_async_with_pipes(
        NULL,            // 작업 디렉토리
        argv,            // 실행할 명령어
        NULL,            // 환경 변수
        G_SPAWN_DO_NOT_REAP_CHILD, // 프로세스를 수동으로 수집
        NULL,            // 실행 전 콜백 함수
        NULL,            // 콜백 함수의 데이터
        &pid,            // 프로세스 ID를 저장할 위치
        &stdout_fd,      // stdout 파이프 파일 디스크립터
	NULL,
        NULL,            // stderr 파이프 파일 디스크립터
        &error           // 에러 정보
    );

    if (!success) {
        gtk_label_set_text(output_label, "Failed to launch process");
        g_error_free(error);
        return;
    }

    // stdout 파일 디스크립터를 GIOChannel로 변환
    io_channel = g_io_channel_unix_new(stdout_fd);

    // GIOChannel에서 데이터가 올 때마다 콜백 함수 실행
    g_io_add_watch(io_channel, G_IO_IN, (GIOFunc) on_output, NULL);
}

int main(int argc, char *argv[]) {
    GtkWidget *window;
    GtkWidget *notebook;
    GtkWidget *vbox1, *vbox2, *vbox3;
    GtkWidget *tab_label1, *tab_label2, *tab_label3;
    GtkWidget *label1, *label2, *label3;
    GtkWidget *run_button;

    // GTK 초기화
    gtk_init(&argc, &argv);

    // 윈도우 생성
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Notebook Example");
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);

    // 화면 중앙에 창을 위치시키기
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);

    // 노트북(탭) 생성
    notebook = gtk_notebook_new();

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

    // 명령어 실행 결과를 보여줄 라벨 생성
    output_label = GTK_LABEL(gtk_label_new("Command output will be displayed here"));

    // Run 버튼 생성
    run_button = gtk_button_new_with_label("Run C_monitoring");
    g_signal_connect(run_button, "clicked", G_CALLBACK(on_button_clicked), NULL);

    // 라벨과 버튼을 첫 번째 탭의 수직 박스에 추가
    gtk_box_pack_start(GTK_BOX(vbox1), label1, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox1), GTK_WIDGET(output_label), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox1), run_button, FALSE, FALSE, 0);

    // 첫 번째 탭의 제목 라벨
    tab_label1 = gtk_label_new("Tab 1");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), vbox1, tab_label1);

    // 두 번째 탭의 내용 설정
    label2 = gtk_label_new("This is the content of Tab 2");
    vbox2 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_box_pack_start(GTK_BOX(vbox2), label2, TRUE, TRUE, 0);

    tab_label2 = gtk_label_new("Tab 2");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), vbox2, tab_label2);

    // 세 번째 탭의 내용 설정
    label3 = gtk_label_new("This is the content of Tab 3");
    vbox3 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_box_pack_start(GTK_BOX(vbox3), label3, TRUE, TRUE, 0);

    tab_label3 = gtk_label_new("Tab 3");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), vbox3, tab_label3);

    // 노트북을 윈도우에 추가
    gtk_container_add(GTK_CONTAINER(window), notebook);

    // 윈도우 닫기 버튼 클릭 시 프로그램 종료
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // 모든 위젯 표시
    gtk_widget_show_all(window);

    // GTK 메인 루프 실행
    gtk_main();

    return 0;
}

