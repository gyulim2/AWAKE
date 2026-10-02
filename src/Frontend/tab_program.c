#include <gtk/gtk.h>

int main(int argc, char *argv[]) {
    GtkWidget *window;
    GtkWidget *notebook;
    GtkWidget *label1, *label2, *label3;
    GtkWidget *tab_label1, *tab_label2, *tab_label3;
    GtkWidget *vbox;

    // GTK 초기화 //초기화 
    gtk_init(&argc, &argv);

    // 윈도우 생성
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Notebook Example");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);

    // 창을 최대화(전체화면 크기)로 설정 (제목 표시줄은 유지)
    gtk_window_maximize(GTK_WINDOW(window));

    // 노트북(탭) 생성
    notebook = gtk_notebook_new();

    // 탭 1에 들어갈 라벨 위젯 생성
    label1 = gtk_label_new("This is the content of Tab 1");
    // 탭 1의 제목 라벨
    tab_label1 = gtk_label_new("Tab 1");
    // 노트북에 첫 번째 탭 추가
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label1, tab_label1);

    // 탭 2에 들어갈 라벨 위젯 생성
    label2 = gtk_label_new("This is the content of Tab 2");
    // 탭 2의 제목 라벨
    tab_label2 = gtk_label_new("Tab 2");
    // 노트북에 두 번째 탭 추가
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label2, tab_label2);

    // 탭 3에 들어갈 라벨 위젯 생성
    label3 = gtk_label_new("This is the content of Tab 3");
    // 탭 3의 제목 라벨
    tab_label3 = gtk_label_new("Tab 3");
    // 노트북에 세 번째 탭 추가
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label3, tab_label3);

    // 수직 박스 컨테이너 생성
    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_box_pack_start(GTK_BOX(vbox), notebook, TRUE, TRUE, 0);

    // 윈도우에 노트북(탭) 추가
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // 윈도우 닫기 버튼 클릭 시 프로그램 종료
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // 모든 위젯 표시
    gtk_widget_show_all(window);

    // GTK 메인 루프 실행
    gtk_main();

    return 0;
}

