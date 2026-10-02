#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// .sh 파일 실행 결과를 읽어오는 함수 (비동기 실행)
void start_script_async(const char* script_path) {
    char command[256];
    snprintf(command, sizeof(command), "%s &", script_path);  // 스크립트를 백그라운드에서 실행
    system(command);  // 비동기 실행
}

// 버튼 클릭 시 호출되는 콜백 함수
static void on_button_clicked(GtkWidget *button, gpointer data) {
    static int is_started = 0;  // 상태를 저장하는 변수 (0 = Stop, 1 = Start)

    GtkWidget *label = (GtkWidget*)data;

    if (is_started == 0) {
        // Start 상태에서 버튼 클릭 시
        gtk_button_set_label(GTK_BUTTON(button), "Stop");
        gtk_widget_set_size_request(button, 100, 50);  // 버튼 크기 변경

        // monitoring.sh 스크립트를 비동기 실행
        start_script_async("./monitoring.sh");

        // 결과를 라벨에 설정
        gtk_label_set_text(GTK_LABEL(label), "Script started...");

        is_started = 1;  // 상태를 Start로 변경
    } else {
        // Stop 상태에서 버튼 클릭 시 프로그램 종료
        gtk_main_quit();  // GTK 메인 루프 종료
    }
}

int main(int argc, char *argv[]) {
    GtkWidget *window;
    GtkWidget *button;
    GtkWidget *label;
    GtkWidget *vbox;

    // GTK 초기화
    gtk_init(&argc, &argv);

    // 윈도우 생성
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Script Output App");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);

    // 수직 박스 컨테이너 생성
    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    // 버튼 생성 (초기 상태: Start)
    button = gtk_button_new_with_label("Start");

    // 라벨 생성
    label = gtk_label_new("Waiting for button click...");

    // 버튼 클릭 시 콜백 함수 연결
    g_signal_connect(button, "clicked", G_CALLBACK(on_button_clicked), label);

    // 컨테이너에 버튼 및 라벨 추가
    gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, TRUE, TRUE, 0);

    // 윈도우에 수직 박스 추가
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // 윈도우 닫기 버튼 클릭 시 프로그램 종료
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // 모든 위젯 표시
    gtk_widget_show_all(window);

    // GTK 메인 루프 실행
    gtk_main();

    return 0;
}

